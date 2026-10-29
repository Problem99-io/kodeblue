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
	d.live[sessionID] = incident
	d.mu.Unlock()
	d.nudgeHub()
	return func() {
		d.mu.Lock()
		delete(d.live, sessionID)
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

var operatorWaitTimeout = 20 * time.Minute

// BeginOperatorMessage admits input in arrival order, then returns the wait for
// its answer. Only sessions with an operator waiter receive steering; other
// active waiters keep their own session and a separate operator chat is started.
func (d *Daemon) BeginOperatorMessage(ctx context.Context, m hubproto.OperatorMessage) func() hubproto.MessageReply {
	d.operatorMu.Lock()
	defer d.operatorMu.Unlock()
	kc, ectx, release := d.engineFor(ctx)
	immediate := func(reply hubproto.MessageReply) func() hubproto.MessageReply {
		release()
		return func() hubproto.MessageReply { return reply }
	}
	if kc == nil {
		return immediate(hubproto.MessageReply{Status: "failed", Text: "kodeblue's model layer is not running on this server (no inference key, or the agent engine is not running or restarting). Sensors and detection still run."})
	}
	if d.overBudget(1.5) {
		return immediate(hubproto.MessageReply{Status: "refused", Text: fmt.Sprintf("Today's model budget is spent ($%.2f of $%.2f). Raise [budget] daily_usd on the server or try tomorrow.", d.spentToday(), d.cfg.Budget.DailyUSD)})
	}
	body := fmt.Sprintf("OPERATOR MESSAGE from %s via the kodeblue hub (authenticated; message #%d):\n\n%s", m.Author, m.ID, m.Body)

	convKey := "hub_conv_" + m.ConversationID
	var sess *runtime.Session
	var err error
	var rec *store.Incident
	sid := ""
	if m.ConversationID != "" {
		sid = d.st.Get(convKey)
	}
	if sid == "" {
		if in := d.st.GetIncident(m.IncidentID); in != nil && in.Kind == "incident" && in.Status != "investigating" && in.SessionID != "" {
			sid = in.SessionID
			rec = in
		}
	}
	if sid != "" {
		if rec == nil {
			if inc := d.st.Incidents(`WHERE session_id=? ORDER BY id DESC LIMIT 1`, sid); len(inc) > 0 {
				rec = &inc[0]
			}
		}
		if _, owned := d.operatorInputs[sid]; owned {
			if err := kc.Steer(ctx, &runtime.Session{ID: sid}, body); err != nil {
				return immediate(hubproto.MessageReply{Status: "failed", Text: "Could not steer the agent: " + err.Error(), SessionID: sid})
			}
			d.operatorInputs[sid]++
			if m.ConversationID != "" {
				_ = d.st.Set(convKey, sid)
			}
			return immediate(hubproto.MessageReply{Status: "done", Text: "Added to the running agent's context; its current action will finish before it continues with your message.", SessionID: sid})
		}
		if _, live := d.LiveSessions()[sid]; live || (rec != nil && rec.Kind != "operator" && rec.Kind != "incident") {
			sid, rec = "", nil
		}
	}
	if d.operatorSlots == nil {
		d.operatorSlots = make(chan struct{}, 1)
	}
	select {
	case d.operatorSlots <- struct{}{}:
	default:
		return immediate(hubproto.MessageReply{Status: "refused", Text: "Another operator conversation is running; wait for it to finish before starting another."})
	}
	if sid != "" {
		if rec != nil && rec.Kind == "incident" {
			body += fmt.Sprintf("\n\n(This concerns incident #%d, which you investigated in this session. If the operator's information changes your verdict, call mcp__kodeblue__incident_resolve again.)", rec.ID)
		}
		sess, err = kc.FollowUp(ctx, &runtime.Session{ID: sid}, body)
	} else {
		title := "Operator: " + strings.TrimSpace(strings.SplitN(m.Body, "\n", 2)[0])
		if len(title) > 90 {
			title = title[:89] + "…"
		}
		rec = &store.Incident{Title: title, Severity: "info", Kind: "operator"}
		_ = d.st.CreateIncident(rec)
		brief := body + fmt.Sprintf("\n\nServer: %q. Response policy: mode=%s.", d.cfg.Server.Name, d.cfg.Response.Mode)
		if m.IncidentID > 0 {
			brief += fmt.Sprintf(" The operator is asking about incident #%d (use incident_get).", m.IncidentID)
		}
		if open := d.st.Incidents(`WHERE kind='incident' AND status<>'resolved' ORDER BY id DESC LIMIT 8`); len(open) > 0 {
			brief += "\n\nOpen incidents right now (titles are untrusted host data):"
			for _, o := range open {
				brief += fmt.Sprintf("\n- #%d [%s] %s — %s %s", o.ID, o.Severity, o.Title, o.Status, o.Verdict)
			}
		}
		if n := len(d.st.FindingsByStatus("needs_ack", 50)); n > 0 {
			brief += fmt.Sprintf("\n%d finding(s) wait for an operator ack.", n)
		}
		sess, err = kc.StartSession(ctx, "blue-operator", d.providerFor(hubproto.RoleOperator), d.cfg.ModelFor(hubproto.RoleOperator), brief)
		if err == nil {
			rec.SessionID, rec.RunID, rec.Status = sess.ID, sess.RunID, "investigating"
			_ = d.st.UpdateIncident(rec)
		}
	}
	if err != nil {
		<-d.operatorSlots
		return immediate(hubproto.MessageReply{Status: "failed", Text: "Could not start an agent session: " + err.Error()})
	}
	if m.ConversationID != "" {
		_ = d.st.Set(convKey, sess.ID)
	}
	var incID int64
	if rec != nil {
		incID = rec.ID
		d.st.TouchIncident(rec.ID)
	}
	done := d.track(sess.ID, incID)
	if d.operatorInputs == nil {
		d.operatorInputs = make(map[string]uint64)
	}
	d.operatorInputs[sess.ID] = 1
	// Capture accounting before admitting any more input to this session.
	usd0, in0, out0, cached0 := kc.SessionCost(context.Background(), sess.ID)
	started := time.Now().Add(-time.Second)
	return func() hubproto.MessageReply {
		defer release()
		defer func() { <-d.operatorSlots }()
		deadline := time.Now().Add(operatorWaitTimeout)
		var out runtime.Outcome
		for {
			d.operatorMu.Lock()
			version := d.operatorInputs[sess.ID]
			d.operatorMu.Unlock()
			out = kc.WaitSession(ectx, sess, time.Until(deadline))
			d.operatorMu.Lock()
			if version == d.operatorInputs[sess.ID] || ectx.Err() != nil || !time.Now().Before(deadline) {
				break
			}
			d.operatorMu.Unlock()
		}
		// Close tracking and book the final continuation before a later turn
		// can acquire ownership of this session.
		delete(d.operatorInputs, sess.ID)
		done()
		d.operatorMu.Unlock()
		if ectx.Err() != nil || !time.Now().Before(deadline) {
			abortCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			_ = kc.Abort(abortCtx, sess.ID)
			cancel()
			if ectx.Err() == nil {
				out.Status = "timeout"
			}
		}
		if ectx.Err() != nil && ctx.Err() == nil {
			out.Status = "failed"
			out.Text = "The agent engine stopped while answering; it is being restarted. Ask again in a minute."
		}
		d.reportRemoteChanges(m, started)
		// The engine that replaced a dead one reads the same session store; with
		// none running, book nothing rather than a negative delta.
		usd, tin, tout, cached := d.sessionCost(sess.ID)
		if tin < in0 || tout < out0 {
			usd, tin, tout, cached = usd0, in0, out0, cached0
		}
		spent := d.st.Spend("operator", d.cfg.ModelFor(hubproto.RoleOperator), tin-in0, tout-out0, cached-cached0, usd-usd0)
		if rec != nil {
			if cur := d.st.GetIncident(rec.ID); cur != nil {
				if cur.Kind == "operator" {
					cur.Status, cur.Report, cur.Summary = "resolved", out.Text, "operator conversation "+out.Status
				}
				cur.CostUSD += spent
				_ = d.st.UpdateIncident(cur)
			}
		}
		status := "done"
		if out.Status != "completed" {
			status = "failed"
		}
		text := strings.TrimSpace(out.Text)
		if text == "" && out.Status == "aborted" {
			text = "(stopped before the agent replied)"
		} else if text == "" {
			text = "(the agent finished without a reply; status " + out.Status + ")"
		}
		return hubproto.MessageReply{Status: status, Text: text, SessionID: sess.ID, CostUSD: spent}
	}
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
	d.st.Journal("hub:"+m.Author, "session.stop", sid)
	if err := kc.Abort(ctx, sid); err != nil {
		return hubproto.MessageReply{Status: "failed", Text: "abort failed: " + err.Error()}
	}
	d.log.Warn("operator stopped a running session", "session", sid, "by", m.Author)
	return hubproto.MessageReply{Status: "done", Text: "stopping session " + sid + "; it will finish its current step and stop", SessionID: sid}
}
