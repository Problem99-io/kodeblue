package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
	"github.com/Problem99-io/kodeblue/internal/blue/respond"
	"github.com/Problem99-io/kodeblue/internal/blue/upgrade"
)

// invokeHelper reaches the root helper (tests replace it).
var invokeHelper = respond.Invoke

// Upgrade implements hublink.Agent: a hub operator asked to upgrade kodeblue
// to the release m.Body. It is recorded here and started by the main loop
// once no learning or agent session runs, so an upgrade never cuts a
// learning run or an investigation short.
func (d *Daemon) Upgrade(m hubproto.OperatorMessage) hubproto.MessageReply {
	to := strings.TrimSpace(m.Body)
	if err := upgrade.Check(to, hubproto.Version); err != nil {
		return hubproto.MessageReply{Status: "refused", Text: "Not upgrading: " + err.Error() + "."}
	}
	if s := d.upgradeState(); s != nil && s.State == upgrade.Installing {
		return hubproto.MessageReply{Status: "refused", Text: "An upgrade to " + s.To + " is being installed."}
	}
	s := upgrade.Status{To: to, From: hubproto.Version, State: upgrade.Waiting, By: "hub:" + m.Author, At: time.Now().UTC()}
	if busy := d.busy(); busy != "" {
		s.Detail = "starts once " + busy + " finishes"
	}
	if err := upgrade.Write(d.cfg.Server.StateDir, s, -1); err != nil {
		return hubproto.MessageReply{Status: "failed", Text: "Could not record the upgrade: " + err.Error()}
	}
	d.st.Journal(s.By, "upgrade.requested", hubproto.Version+" -> "+to)
	select {
	case d.restartNow <- struct{}{}: // let the main loop look now
	default:
	}
	if s.Detail != "" {
		return hubproto.MessageReply{Status: "done", Text: fmt.Sprintf("Upgrade to %s recorded: it %s.", to, s.Detail)}
	}
	return hubproto.MessageReply{Status: "done", Text: fmt.Sprintf("Upgrading from %s to %s now.", hubproto.Version, to)}
}

// busy names what an upgrade waits for, or "" when nothing runs.
func (d *Daemon) busy() string {
	switch n := len(d.LiveSessions()) + d.followUpsRunning(); {
	case d.learning.Load():
		return "learning"
	case n == 1:
		return "the running agent session"
	case n > 1:
		return fmt.Sprintf("the %d running agent sessions", n)
	case d.software.Load():
		return "the software check"
	}
	return ""
}

// upgradeState reads the status file and settles what it says against what
// runs: an upgrade to the version running now is done, and an install that
// neither finished nor reported within upgrade.InstallTimeout failed.
func (d *Daemon) upgradeState() *upgrade.Status {
	d.upgradeMu.Lock()
	defer d.upgradeMu.Unlock()
	s := upgrade.Read(d.cfg.Server.StateDir)
	if s == nil {
		return nil
	}
	changed := false
	switch {
	case s.State != upgrade.Done && s.To == hubproto.Version:
		s.State, s.Detail, s.At, changed = upgrade.Done, "", time.Now().UTC(), true
		d.st.Journal(s.By, "upgrade.done", s.From+" -> "+s.To)
	case s.State == upgrade.Installing && time.Since(s.At) > upgrade.InstallTimeout:
		s.State, s.Detail, s.At, changed = upgrade.Failed, fmt.Sprintf("the install did not finish within %s; on the server: journalctl -u %s", upgrade.InstallTimeout, upgrade.Unit), time.Now().UTC(), true
	case s.State == upgrade.Waiting && upgrade.Check(s.To, hubproto.Version) != nil:
		// Upgraded past it some other way meanwhile.
		s.State, s.Detail, s.At, changed = upgrade.Failed, "not started: "+upgrade.Check(s.To, hubproto.Version).Error(), time.Now().UTC(), true
	}
	if changed {
		_ = upgrade.Write(d.cfg.Server.StateDir, *s, -1)
	}
	return s
}

// UpgradeStatus implements hublink.Agent.
func (d *Daemon) UpgradeStatus() *hubproto.UpgradeStatus {
	s := d.upgradeState()
	if s == nil {
		return nil
	}
	return &hubproto.UpgradeStatus{To: s.To, From: s.From, State: s.State, Detail: s.Detail, By: s.By, At: s.At}
}

// maybeUpgrade starts a waiting upgrade once nothing runs: the root helper
// starts the install in its own unit, which restarts kodeblue when done.
func (d *Daemon) maybeUpgrade(ctx context.Context) {
	s := d.upgradeState()
	if s == nil || s.State != upgrade.Waiting {
		return
	}
	if busy := d.busy(); busy != "" {
		if want := "starts once " + busy + " finishes"; s.Detail != want {
			s.Detail = want
			_ = upgrade.Write(d.cfg.Server.StateDir, *s, -1)
		}
		return
	}
	s.State, s.Detail, s.At = upgrade.Installing, "handed to the root helper", time.Now().UTC()
	_ = upgrade.Write(d.cfg.Server.StateDir, *s, -1)
	d.nudgeHub()
	payload, _ := json.Marshal(map[string]string{"op": "upgrade", "version": s.To, "by": s.By})
	hctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	out, err := invokeHelper(hctx, d.cfg.Path(), payload)
	var rec respond.Record
	if err == nil {
		if json.Unmarshal(out, &rec) != nil {
			rec.Result = strings.TrimSpace(string(out))
		}
	}
	if err != nil || rec.Status != "started" {
		why := rec.Result
		if err != nil {
			why = err.Error()
		}
		// The root side may have written its own failure already.
		if cur := upgrade.Read(d.cfg.Server.StateDir); cur != nil && cur.State == upgrade.Failed {
			why = cur.Detail
		}
		s.State, s.Detail, s.At = upgrade.Failed, why, time.Now().UTC()
		_ = upgrade.Write(d.cfg.Server.StateDir, *s, -1)
		d.log.Error("upgrade not started", "to", s.To, "reason", why)
		d.st.Journal(s.By, "upgrade.failed", s.To+": "+why)
		d.nudgeHub()
		return
	}
	d.log.Info("upgrade started; the install restarts kodeblue", "to", s.To, "by", s.By)
	d.st.Journal(s.By, "upgrade.started", hubproto.Version+" -> "+s.To)
}
