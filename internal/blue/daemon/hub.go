package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/detect"
	"github.com/Problem99-io/kodeblue/internal/blue/hublink"
	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
	"github.com/Problem99-io/kodeblue/internal/blue/notify"
	"github.com/Problem99-io/kodeblue/internal/blue/runtime"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

// startHub connects to the kodeblue hub when one is configured. A broken hub
// configuration never stops monitoring.
func (d *Daemon) startHub(ctx context.Context) {
	if !d.cfg.Hub.Enabled() {
		return
	}
	link, err := hublink.New(d.cfg, d.st, d.log, d)
	if err != nil {
		d.log.Error("hub link disabled", "error", err)
		return
	}
	d.hub = link
	d.wg.Add(1)
	go func() { defer d.wg.Done(); link.Run(ctx) }()
}

func (d *Daemon) nudgeHub() {
	if d.hub != nil {
		d.hub.Nudge()
	}
}

// Phase implements hublink.Agent.
func (d *Daemon) Phase() string {
	if d.st.Get("learned_at") == "" {
		return "learning"
	}
	if d.mode() == detect.ModeMaintenance {
		return "maintenance"
	}
	return "watching"
}

func (d *Daemon) ModelsEnabled() bool { return d.engine() != nil }

func (d *Daemon) Transcript(ctx context.Context, sessionID string, running bool) ([]hubproto.Turn, error) {
	kc := d.engine()
	if kc == nil {
		return nil, fmt.Errorf("model runtime not running")
	}
	return kc.Transcript(ctx, sessionID, running)
}

func (d *Daemon) LiveSessions() map[string]int64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make(map[string]int64, len(d.live))
	for k, v := range d.live {
		out[k] = v
	}
	return out
}

// track marks a session as running (its transcript streams to the hub).
func (d *Daemon) track(sessionID string, incident int64) func() {
	d.mu.Lock()
	if d.liveEpoch == nil {
		d.liveEpoch = map[string]uint64{}
	}
	d.nextTracking++
	epoch := d.nextTracking
	d.liveEpoch[sessionID] = epoch
	d.live[sessionID] = incident
	d.mu.Unlock()
	d.nudgeHub()
	return func() {
		d.mu.Lock()
		if d.liveEpoch[sessionID] == epoch {
			delete(d.live, sessionID)
			delete(d.liveEpoch, sessionID)
		}
		d.mu.Unlock()
		d.nudgeHub()
	}
}

// Learning implements hublink.Agent.
func (d *Daemon) Learning() bool { return d.learning.Load() }

// Learn implements hublink.Agent: a hub operator's learning command. It
// returns once the run has started. Every run is announced in Slack, since a
// relearn absorbs whatever the server runs at that moment as normal.
func (d *Daemon) Learn(ctx context.Context, m hubproto.OperatorMessage) hubproto.MessageReply {
	if m.Command == hubproto.CommandLearn {
		if d.engine() == nil {
			return hubproto.MessageReply{Status: "failed", Text: "The learner needs kodeblue's model layer, which is not running on this server (no inference key, or the agent engine failed to start). Relearn still collects the baseline without it."}
		}
		if d.overBudget(1.5) {
			return hubproto.MessageReply{Status: "refused", Text: fmt.Sprintf("Today's model budget is spent ($%.2f of $%.2f). Raise [budget] daily_usd on the server or try tomorrow.", d.spentToday(), d.cfg.Budget.DailyUSD)}
		}
	}
	if !d.learning.CompareAndSwap(false, true) {
		return hubproto.MessageReply{Status: "refused", Text: "Learning is already running on this server."}
	}
	total := 0
	for _, n := range d.st.BaselineCounts() {
		total += n
	}
	announce := func(title, body string) {
		d.slack.Async(notify.Message{Server: d.cfg.Server.Name, Kind: "learning", Severity: "medium", Title: title, Body: body}, nil)
	}
	if m.Command == hubproto.CommandRelearn {
		sweeps := max(d.cfg.Schedule.LearningSweeps, 1)
		window := time.Duration(d.cfg.Schedule.LearningMinutes) * time.Minute
		d.st.Journal("hub:"+m.Author, "relearn", "")
		announce(fmt.Sprintf("Hub operator %s started relearning this server", m.Author),
			fmt.Sprintf("kodeblue collects the baseline again (%d sweeps over %s) and absorbs what it sees as normal, then runs the learner.", sweeps, window))
		select {
		case d.relearnNow <- struct{}{}:
		default:
		}
		learner := "then the learner"
		if d.engine() == nil {
			learner = "no learner (the model layer is not running)"
		}
		return hubproto.MessageReply{Status: "done", Text: fmt.Sprintf("Relearning: %d baseline sweeps over %s, %s. Changes seen meanwhile are absorbed as normal; the server is watching again when it finishes.", sweeps, window, learner)}
	}

	counts, _ := json.Marshal(d.st.BaselineCounts())
	brief := fmt.Sprintf("Learning run for server %q, requested by hub operator %s. The baseline is already collected (item counts: %s) and detection is running. "+
		"Follow your procedure. Review what earlier learning runs left (profile, definitions, monitors, skills) and update it rather than duplicating it; fill in what is missing.",
		d.cfg.Server.Name, m.Author, counts)
	in, sess, err := d.startLearner(ctx, brief)
	if err != nil {
		d.learning.Store(false)
		return hubproto.MessageReply{Status: "failed", Text: "Could not start the learner session: " + err.Error()}
	}
	d.st.Journal("hub:"+m.Author, "learn", fmt.Sprintf("learner session %s (case #%d)", sess.ID, in.ID))
	announce(fmt.Sprintf("Hub operator %s started the learner on this server", m.Author),
		fmt.Sprintf("The learner reviews the current baseline (%d items) and may change the profile, definitions, monitors and skills.", total))
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		defer d.learning.Store(false)
		if !learnerRan(d.finishLearner(ctx, in, sess)) || ctx.Err() != nil {
			return // a waiting learner stays waiting
		}
		d.assess(ctx)
		d.checkServiceCoverage("learning")
		if ctx.Err() == nil {
			_ = d.st.Set(store.LearnerPendingKey, "")
		}
	}()
	return hubproto.MessageReply{Status: "done", SessionID: sess.ID,
		Text: fmt.Sprintf("Learner started on the current baseline (%d items): case #%d.", total, in.ID)}
}

// reportRemoteChanges notifies the team of any change to kodeblue's
// detection made during an operator conversation, so a hub asking agents to
// quietly blind a server leaves a visible trail. With the hub owning Slack
// the trail goes through the hub too; [notify] direct = true also posts it
// straight from the server, where a compromised hub cannot suppress it.
func (d *Daemon) reportRemoteChanges(m hubproto.OperatorMessage, since time.Time) {
	var changes []string
	for _, j := range d.st.JournalSince(since, 200) {
		switch {
		case j.Action == "allow_rule.add", j.Action == "allow_rule.disable", j.Action == "monitor.disable", j.Action == "monitor.put",
			j.Action == "profile.set", j.Action == "integrity.add", strings.HasPrefix(j.Action, "respond."), strings.HasPrefix(j.Action, "sensor."):
			changes = append(changes, j.Action+": "+j.Detail)
		}
	}
	if len(changes) == 0 {
		return
	}
	if len(changes) > 12 {
		changes = append(changes[:12], fmt.Sprintf("… %d more", len(changes)-12))
	}
	d.slack.Async(notify.Message{Server: d.cfg.Server.Name, Kind: "operator", Severity: "medium",
		Title: fmt.Sprintf("kodeblue changed while answering hub operator %s", m.Author),
		Body:  "Message: " + runtime.TrimForPrompt(m.Body, 300) + "\n" + strings.Join(changes, "\n")}, nil)
}

// HandleOperatorMessage runs an operator's hub message as an agent session.
// A message about an incident continues that incident's own session, so the
// responder keeps its full context; anything else goes to the operator
// liaison, one session per hub conversation.
func (d *Daemon) HandleOperatorMessage(ctx context.Context, m hubproto.OperatorMessage) hubproto.MessageReply {
	return d.BeginOperatorMessage(ctx, m)()
}

// StopSession aborts a running agent session on the operator's request. The
// session's own Wait loop then books it and marks its incident resolved.
func (d *Daemon) StopSession(ctx context.Context, m hubproto.OperatorMessage) hubproto.MessageReply {
	kc := d.engine()
	if kc == nil {
		return hubproto.MessageReply{Status: "failed", Text: "the model engine is not running on this server"}
	}
	sid := m.SessionID
	if sid == "" && m.IncidentID > 0 {
		if in := d.st.GetIncident(m.IncidentID); in != nil {
			sid = in.SessionID
		}
	}
	if sid == "" {
		return hubproto.MessageReply{Status: "refused", Text: "no session named (pass session_id or an incident_id with a running session)"}
	}
	if _, ok := d.LiveSessions()[sid]; !ok {
		return hubproto.MessageReply{Status: "refused", Text: "session " + sid + " is not running here"}
	}
	d.operatorMu.Lock()
	if turn := d.operatorSessions[sid]; turn != nil && turn.cancel != nil {
		turn.cancel()
	}
	d.operatorMu.Unlock()
	d.st.Journal("hub:"+m.Author, "session.stop", sid)
	if err := kc.Abort(ctx, sid); err != nil {
		return hubproto.MessageReply{Status: "failed", Text: "abort failed: " + err.Error()}
	}
	d.log.Warn("operator stopped a running session", "session", sid, "by", m.Author)
	return hubproto.MessageReply{Status: "done", Text: "stopping session " + sid + "; it will finish its current step and stop", SessionID: sid}
}
