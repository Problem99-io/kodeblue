package daemon

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/detect"
	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
	"github.com/Problem99-io/kodeblue/internal/blue/mcpserver"
	"github.com/Problem99-io/kodeblue/internal/blue/runtime"
)

// decisionsFollowedKey records, per incident, how many operator decisions
// were already handed back to its agent.
func decisionsFollowedKey(id int64) string { return fmt.Sprintf("decisions_followed:%d", id) }

// DecisionMade implements hublink.Agent: an operator approved or denied a
// containment request. The run loop then hands settled decisions back to
// their incidents' agents.
func (d *Daemon) DecisionMade() {
	select {
	case d.decided <- struct{}{}:
	default:
	}
}

// followUpDecisions continues the session of each recent incident whose
// containment requests are all decided, with what the operators decided and
// what the root helper did. The agent never runs actions itself, so without
// this it would not learn that its requests were carried out, and the case
// would wait for a human forever.
func (d *Daemon) followUpDecisions(ctx context.Context) {
	if d.engine() == nil || d.overBudget(1.5) {
		return
	}
	busy := map[int64]bool{}
	for _, id := range d.LiveSessions() {
		busy[id] = true
	}
	recent := d.st.Incidents(`WHERE kind='incident' AND session_id<>'' AND status<>'investigating' AND created_at>? ORDER BY id`, time.Now().Add(-72*time.Hour).Unix())
	for i := range recent {
		in := &recent[i]
		if busy[in.ID] {
			continue
		}
		pending, settled := mcpserver.Decisions(d.cfg, in.ID)
		told, _ := strconv.Atoi(d.st.Get(decisionsFollowedKey(in.ID)))
		if pending > 0 || len(settled) <= told {
			continue
		}
		d.resumeAfterDecisions(ctx, in.ID, in.SessionID, in.Severity, settled)
	}
}

func (d *Daemon) resumeAfterDecisions(ctx context.Context, incID int64, sessionID, severity string, settled []string) {
	kc, ectx, release := d.engineFor(ctx)
	if kc == nil {
		release()
		return
	}
	body := fmt.Sprintf("OPERATOR DECISIONS on the containment you requested for incident #%d. The root helper has already carried out every approved action; you do not run them yourself:\n", incID)
	for _, s := range settled {
		body += "\n- " + s
	}
	body += "\n\nCheck that the approved actions took effect and whether the activity stopped, then call mcp__kodeblue__incident_resolve again with your final verdict, severity, summary and report. If something still needs a human, say exactly what, and request any further containment it needs."
	// A follow-up continues the session: book only this turn's usage.
	usd0, in0, out0, cached0 := kc.SessionCost(context.Background(), sessionID)
	sess, err := kc.FollowUp(ectx, &runtime.Session{ID: sessionID}, body)
	if err != nil {
		release()
		d.log.Warn("could not hand operator decisions to the incident agent; retrying later", "incident", incID, "error", err)
		return
	}
	_ = d.st.Set(decisionsFollowedKey(incID), strconv.Itoa(len(settled)))
	d.st.TouchIncident(incID)
	d.log.Info("operator decisions handed to the incident agent", "incident", incID, "session", sess.ID, "decisions", len(settled))
	// Track before returning, so a pending settings restart waits for it.
	untrack := d.track(sess.ID, incID)
	role := hubproto.RoleResponder
	if severity == detect.SevCritical {
		role = hubproto.RoleCritical
	}
	_, model := d.engineModel(role)
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		defer release()
		out := kc.Wait(ectx, sess, 20*time.Minute)
		untrack()
		usd, tin, tout, cached := d.sessionCost(sess.ID)
		if tin < in0 || tout < out0 {
			usd, tin, tout, cached = usd0, in0, out0, cached0
		}
		spent := d.st.Spend("incident", model, tin-in0, tout-out0, cached-cached0, usd-usd0)
		if cur := d.st.GetIncident(incID); cur != nil {
			cur.CostUSD += spent
			_ = d.st.UpdateIncident(cur)
		}
		d.log.Info("incident agent finished after operator decisions", "incident", incID, "status", out.Status, "text", strings.TrimSpace(clipText(out.Text, 200)))
		if d.restartWanted.Load() {
			d.ApplySettings() // the settings restart waited for this session
		}
	}()
}

func clipText(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
