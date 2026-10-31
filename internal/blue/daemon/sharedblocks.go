package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/hublink"
	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
	"github.com/Problem99-io/kodeblue/internal/blue/mcpserver"
	"github.com/Problem99-io/kodeblue/internal/blue/notify"
	"github.com/Problem99-io/kodeblue/internal/blue/respond"
)

// Blocks shared by the fleet: when another server blocks an address, the hub
// relays it and this server blocks it too, under its own policy, as if one
// of its own agents had asked. Where block_ip runs automatically (contain)
// the root helper blocks it, which takes it only with the root-owned
// hub.accept_shared_blocks; elsewhere it waits for an operator's approval
// like any request. Protected and infrastructure addresses are refused as
// always, and shared blocks never take more than half the hour's actions,
// so this server's own incidents keep room to act.

const (
	// sharedHandledKey records what this server did with each shared block
	// (id -> outcome), so none is asked for twice.
	sharedHandledKey = "shared_blocks_handled"
	// maxSharedPending is how many shared blocks wait for an operator at
	// once; the rest are asked for as those are settled.
	maxSharedPending = 20
)

// SharedBlocksChanged implements hublink.Agent.
func (d *Daemon) SharedBlocksChanged() {
	select {
	case d.sharedCh <- struct{}{}:
	default:
	}
}

// startSharedBlocks applies the shared blocks on a goroutine of its own:
// each automatic one is a root helper run, which must not hold up a sweep.
func (d *Daemon) startSharedBlocks(ctx context.Context) {
	if !d.cfg.Hub.Enabled() || !d.cfg.Hub.AcceptSharedBlocks || !d.sharing.CompareAndSwap(false, true) {
		return
	}
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		defer d.sharing.Store(false)
		d.applySharedBlocks(ctx, time.Now())
	}()
}

// applySharedBlocks works through the hub's last list: requests for blocks
// no longer shared are withdrawn, and each new block is carried out or put
// to an operator. What waits (the hour's actions used up, too many waiting
// for approval, block_ip turned off) is tried again on a later call.
func (d *Daemon) applySharedBlocks(ctx context.Context, now time.Time) {
	list := hublink.LoadSharedBlocks(d.st).Blocks
	listed := map[string]bool{}
	for _, b := range list {
		listed[b.ID] = true
	}
	var seen map[string]string
	_ = json.Unmarshal([]byte(d.st.Get(sharedHandledKey)), &seen)
	handled := map[string]string{}
	for id, v := range seen {
		if listed[id] {
			handled[id] = v
		}
	}
	defer func() {
		b, _ := json.Marshal(handled)
		_ = d.st.Set(sharedHandledKey, string(b))
	}()

	waiting := 0
	for _, r := range mcpserver.LoadRequests(d.cfg) {
		if r.RequestedBy != respond.FleetRequester {
			continue
		}
		if listed[r.ID] {
			waiting++
			continue
		}
		// The server that blocked it unblocked it (or it is older than the
		// hub shares): an operator need not decide it any more.
		if err := mcpserver.DenyRequest(d.cfg, r.ID, "fleet: no longer shared"); err == nil {
			d.st.Journal(respond.FleetRequester, "respond.withdrawn", fmt.Sprintf("%s block_ip %s: no longer blocked elsewhere in the fleet (unblocked there, or older than %d days)", r.ID, r.Params["ip"], hubproto.SharedBlockDays))
		}
	}
	rule := d.cfg.ActionRule("block_ip")
	if rule == hubproto.ActionOff {
		return
	}
	journal := respond.Load(d.cfg.Response.StateDir)
	pending := mcpserver.LoadRequests(d.cfg)
	limit := d.cfg.Response.MaxActionsPerHour
	var done, asked []string
	// Oldest first: the hub lists the newest first.
	for i := len(list) - 1; i >= 0 && ctx.Err() == nil; i-- {
		b := list[i]
		if handled[b.ID] != "" {
			continue
		}
		ip, err := netip.ParseAddr(b.IP)
		if ip = ip.Unmap(); err != nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
			handled[b.ID] = "skipped: not a public address"
			continue
		}
		req := respond.Request{ID: b.ID, Action: "block_ip", Params: map[string]string{"ip": ip.String()}, RequestedBy: respond.FleetRequester, RequestedAt: now,
			Justification: fmt.Sprintf("Blocked on %s, another server of this fleet, at %s. Its reason (untrusted): %s",
				strconv.Quote(clipLine(b.Server, 80)), b.At.UTC().Format(time.RFC3339), strconv.Quote(clipLine(b.Why, 300)))}
		line := fmt.Sprintf("%s (blocked on %s: %s)", req.Params["ip"], clipLine(b.Server, 80), clipLine(b.Why, 160))
		if err := respond.Check(d.cfg.Response, req); err != nil {
			handled[b.ID] = "refused: " + err.Error()
			d.st.Journal(respond.FleetRequester, "respond.refused", fmt.Sprintf("%s block_ip %s: %s", b.ID, req.Params["ip"], err))
			continue
		}
		if blockedHere(journal, req.Params["ip"]) {
			handled[b.ID] = "already blocked"
			continue
		}
		if rule == hubproto.ActionAuto {
			// Half the hour's actions at most: the rest when the hour allows.
			if n := respond.ActionsLastHour(d.cfg.Response.StateDir); limit > 0 && n >= max(limit/2, 1) {
				break
			}
			rec, err := d.ruleRun(ctx, req)
			if err != nil {
				d.log.Warn("could not apply a block shared by the fleet; retrying later", "ip", req.Params["ip"], "error", err)
				break
			}
			if rec.Status == "refused" && strings.HasPrefix(rec.Result, "rate limit") {
				break
			}
			handled[b.ID] = rec.Status
			d.st.Journal(respond.FleetRequester, "respond."+rec.Status, fmt.Sprintf("%s block_ip %s (shared by %s): %s", b.ID, req.Params["ip"], strconv.Quote(clipLine(b.Server, 80)), rec.Result))
			journal = append(journal, *rec)
			if rec.Status == "done" {
				done = append(done, line+"; undo: kodeblue respond undo "+b.ID)
			}
			continue
		}
		if id := requestedAs(pending, req); id != "" {
			handled[b.ID] = "already requested as " + id
			continue
		}
		if waiting >= maxSharedPending {
			break
		}
		if err := mcpserver.AppendRequest(d.cfg, req); err != nil {
			d.log.Warn("could not record a block shared by the fleet", "ip", req.Params["ip"], "error", err)
			break
		}
		handled[b.ID] = "requested"
		waiting++
		pending = append(pending, req)
		d.st.Journal(respond.FleetRequester, "respond.request", fmt.Sprintf("%s block_ip %s (shared by %s)", b.ID, req.Params["ip"], strconv.Quote(clipLine(b.Server, 80))))
		asked = append(asked, line+"; approve: kodeblue respond approve "+b.ID)
	}
	// One notice per batch: a flood blocked on one server must not become
	// one Slack message per address on every other.
	if len(done) > 0 {
		d.log.Info("blocked addresses shared by the fleet", "count", len(done))
		d.slack.Async(notify.Message{Server: d.cfg.Server.Name, Kind: "action", Severity: "medium",
			Title: fmt.Sprintf("Blocked %d %s other servers of the fleet blocked", len(done), plural(len(done), "address", "addresses")),
			Body:  clipText(strings.Join(done, "\n"), 3000)}, nil)
	}
	if len(asked) > 0 {
		d.slack.Async(notify.Message{Server: d.cfg.Server.Name, Kind: "action", Severity: "high",
			Title: fmt.Sprintf("%d %s other servers of the fleet blocked %s approval here", len(asked), plural(len(asked), "address", "addresses"), plural(len(asked), "awaits", "await")),
			Body:  clipText("Approve or deny them in the hub (Activity) or on the server.\n"+strings.Join(asked, "\n"), 3000)}, nil)
	}
}

// blockedHere reports whether a block of ip is in effect here, as far as
// the action journal says (its last record per action).
func blockedHere(journal []respond.Record, ip string) bool {
	last := map[string]respond.Record{}
	for _, r := range journal {
		last[r.ID] = r
	}
	for _, r := range last {
		if r.Action == "block_ip" && r.Status == "done" && r.Params["ip"] == ip {
			return true
		}
	}
	return false
}

// requestedAs is the id of a pending request for the same action and
// target, or "".
func requestedAs(pending []respond.Request, req respond.Request) string {
	for _, r := range pending {
		if r.Action == req.Action && respond.SameTarget(r.Params, req.Params) {
			return r.ID
		}
	}
	return ""
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// clipLine is one line of untrusted text, at most n bytes.
func clipLine(s string, n int) string {
	return clipText(strings.Join(strings.Fields(s), " "), n)
}
