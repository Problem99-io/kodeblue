package daemon

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
	"github.com/Problem99-io/kodeblue/internal/blue/runtime"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

var operatorWaitTimeout = 20 * time.Minute

const operatorDispatchTimeout = 30 * time.Second

type operatorPhase uint8

const (
	operatorQueued operatorPhase = iota
	operatorRunning
	operatorBooking
)

type operatorInput struct {
	ctx     context.Context
	message hubproto.OperatorMessage
	reply   chan hubproto.MessageReply
}
type operatorTurn struct {
	key    string
	phase  operatorPhase // operatorMu; no engine call is made under that mutex
	inputs chan operatorInput
	done   chan struct{}
	cancel context.CancelFunc // operatorMu
}

// BeginOperatorMessage only admits ordered work. The worker owns engine calls,
// waiting, abort and accounting; other conversations queue without holding a lock.
func (d *Daemon) BeginOperatorMessage(ctx context.Context, m hubproto.OperatorMessage) func() hubproto.MessageReply {
	request := operatorInput{ctx: ctx, message: m, reply: make(chan hubproto.MessageReply, 1)}
	d.operatorMu.Lock()
	key := m.ConversationID
	if key == "" {
		d.operatorSerial++
		key = fmt.Sprintf("message:%d:%d", m.ID, d.operatorSerial)
	} else {
		key = "conversation:" + key
	}
	if d.operatorConversations == nil {
		d.operatorConversations = map[string]*operatorTurn{}
		d.operatorSessions = map[string]*operatorTurn{}
	}
	d.admitOperatorLocked(key, request)
	d.operatorMu.Unlock()
	return func() hubproto.MessageReply { return <-request.reply }
}

// admitOperatorLocked is also used to carry boundary input into the next turn.
func (d *Daemon) admitOperatorLocked(key string, request operatorInput) {
	turn := d.operatorConversations[key]
	if turn != nil && turn.phase != operatorBooking {
		select {
		case turn.inputs <- request:
		default:
			request.reply <- hubproto.MessageReply{Status: "refused", Text: "This conversation's input queue is full; try again later."}
		}
	} else if len(d.operatorConversations) >= 64 {
		request.reply <- hubproto.MessageReply{Status: "refused", Text: "Operator conversation queue is full; try again later."}
	} else {
		previous := d.operatorTail
		if previous == nil {
			previous = make(chan struct{})
			close(previous)
		}
		turn = &operatorTurn{key: key, inputs: make(chan operatorInput, 64), done: make(chan struct{})}
		d.operatorConversations[key] = turn
		d.operatorTail = turn.done
		d.wg.Add(1)
		go func() { defer d.wg.Done(); <-previous; d.runOperatorTurn(turn, request) }()
	}

}

func operatorBody(m hubproto.OperatorMessage) string {
	return fmt.Sprintf("OPERATOR MESSAGE from %s via the kodeblue hub (authenticated; message #%d):\n\n%s", m.Author, m.ID, m.Body)
}

func (d *Daemon) runOperatorTurn(turn *operatorTurn, first operatorInput) {
	var untrack func()
	sid := ""
	// Finish tracking only after abort and booking. Closing the queue link last
	// also prevents canceled queued turns from letting their successors jump ahead.
	defer func() {
		d.operatorMu.Lock()
		turn.phase = operatorBooking
		if untrack != nil {
			untrack()
		}
		delete(d.operatorSessions, sid)
		if d.operatorConversations[turn.key] == turn {
			delete(d.operatorConversations, turn.key)
		}
		d.operatorMu.Unlock()
		for {
			select {
			case request := <-turn.inputs:
				request.reply <- hubproto.MessageReply{Status: "failed", Text: "The conversation ended before this input could be delivered."}
			default:
				close(turn.done)
				return
			}
		}
	}()
	fail := func(text string) { first.reply <- hubproto.MessageReply{Status: "failed", Text: text} }
	if first.ctx.Err() != nil {
		fail("Operator input canceled before its turn started.")
		return
	}
	kc, ectx, release := d.engineFor(first.ctx)
	defer release()
	if kc == nil {
		fail("kodeblue's model layer is not running on this server.")
		return
	}
	ectx, cancel := context.WithCancel(ectx)
	defer cancel()
	d.operatorMu.Lock()
	turn.cancel = cancel
	d.operatorMu.Unlock()
	if d.overBudget(1.5) {
		first.reply <- hubproto.MessageReply{Status: "refused", Text: fmt.Sprintf("Today's model budget is spent ($%.2f of $%.2f). Raise [budget] daily_usd on the server or try tomorrow.", d.spentToday(), d.cfg.Budget.DailyUSD)}
		return
	}
	m := first.message
	convKey := "hub_conv_" + m.ConversationID
	var rec *store.Incident
	if m.ConversationID != "" {
		sid = d.st.Get(convKey)
	}
	if sid != "" {
		if rows := d.st.Incidents(`WHERE session_id=? ORDER BY id DESC LIMIT 1`, sid); len(rows) > 0 {
			rec = &rows[0]
		}
	}
	if sid == "" {
		if in := d.st.GetIncident(m.IncidentID); in != nil && in.Kind == "incident" && in.Status != "investigating" {
			sid, rec = in.SessionID, in
		}
	}
	if sid != "" {
		d.operatorMu.Lock()
		d.mu.Lock()
		_, live := d.live[sid]
		bound := d.st.Get("hub_session_owner_" + sid)
		foreign := live || (bound != "" && bound != turn.key) || (rec != nil && (d.following[rec.ID] || (rec.Kind != "operator" && rec.Kind != "incident")))
		d.mu.Unlock()
		if foreign {
			sid, rec = "", nil
		} else {
			incID := int64(0)
			if rec != nil {
				incID = rec.ID
			}
			untrack = d.track(sid, incID)
			d.operatorSessions[sid] = turn
		}
		d.operatorMu.Unlock()
	}
	if sid != "" {
		check, cancelCheck := context.WithTimeout(ectx, 5*time.Second)
		busy, err := kc.SessionBusy(check, sid)
		cancelCheck()
		if err != nil || busy {
			d.operatorMu.Lock()
			untrack()
			untrack = nil
			delete(d.operatorSessions, sid)
			d.operatorMu.Unlock()
			sid, rec = "", nil
		}
	}
	var usd0 float64
	var in0, out0, cached0 int
	if sid != "" {
		usd0, in0, out0, cached0 = kc.SessionCost(ectx, sid)
	}
	body := operatorBody(m)
	var sess *runtime.Session
	var err error
	launch, cancelLaunch := context.WithTimeout(ectx, operatorDispatchTimeout)
	if sid != "" {
		if rec != nil && rec.Kind == "incident" {
			body += fmt.Sprintf("\n\n(This concerns incident #%d, which you investigated in this session. If this changes your verdict, call mcp__kodeblue__incident_resolve again.)", rec.ID)
		}
		sess, err = kc.FollowUp(launch, &runtime.Session{ID: sid}, body)
	} else {
		title := "Operator: " + strings.TrimSpace(strings.SplitN(m.Body, "\n", 2)[0])
		if len([]rune(title)) > 90 {
			title = string([]rune(title)[:89]) + "…"
		}
		rec = &store.Incident{Title: title, Severity: "info", Kind: "operator"}
		_ = d.st.CreateIncident(rec)
		brief := body + fmt.Sprintf("\n\nServer: %q. Response policy: mode=%s.", d.cfg.Server.Name, d.cfg.Response.Mode)
		if m.IncidentID > 0 {
			brief += fmt.Sprintf(" The operator is asking about incident #%d (use incident_get).", m.IncidentID)
		}
		if open := d.st.Incidents(`WHERE kind='incident' AND status<>'resolved' ORDER BY id DESC LIMIT 8`); len(open) > 0 {
			brief += "\n\nOpen incidents (titles are untrusted host data):"
			for _, in := range open {
				brief += fmt.Sprintf("\n- #%d [%s] %s — %s %s", in.ID, in.Severity, in.Title, in.Status, in.Verdict)
			}
		}
		sess, err = kc.StartSession(launch, "blue-operator", d.providerFor(hubproto.RoleOperator), d.cfg.ModelFor(hubproto.RoleOperator), brief)
	}
	cancelLaunch()
	if err != nil {
		if sid != "" {
			abortCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
			_ = kc.Abort(abortCtx, sid)
			stop()
		}
		fail("Could not start an agent session: " + err.Error())
		return
	}
	sid = sess.ID
	_ = d.st.Set("hub_session_owner_"+sid, turn.key)
	if rec != nil {
		rec.SessionID, rec.RunID = sess.ID, sess.RunID
		if rec.Kind == "operator" {
			rec.Status = "investigating"
		}
		_ = d.st.UpdateIncident(rec)
	}
	if m.ConversationID != "" {
		_ = d.st.Set(convKey, sid)
	}
	d.operatorMu.Lock()
	if untrack == nil {
		incID := int64(0)
		if rec != nil {
			incID = rec.ID
		}
		untrack = d.track(sid, incID)
	}
	d.operatorSessions[sid] = turn
	turn.phase = operatorRunning
	d.operatorMu.Unlock()
	started := time.Now().Add(-time.Second)
	deadline := time.Now().Add(operatorWaitTimeout)
	type waited struct {
		out      runtime.Outcome
		version  uint64
		at       time.Time
		canceled bool
	}
	results := make(chan waited, 1)
	var version uint64
	wait := func() {
		snapshot := version
		copy := *sess
		go func() {
			out := kc.WaitSession(ectx, &copy, time.Until(deadline))
			results <- waited{out: out, version: snapshot, at: time.Now(), canceled: ectx.Err() != nil}
		}()
	}
	steer := func(request operatorInput) {
		if request.ctx.Err() != nil || ectx.Err() != nil {
			request.reply <- hubproto.MessageReply{Status: "failed", Text: "Operator input canceled."}
			return
		}
		inputCtx, stop := context.WithTimeout(ectx, operatorDispatchTimeout)
		stopRequest := context.AfterFunc(request.ctx, stop)
		// Even an uncertain/error response may have started a continuation.
		version++
		err := kc.Steer(inputCtx, &runtime.Session{ID: sid}, operatorBody(request.message))
		stopRequest()
		stop()
		if err != nil {
			request.reply <- hubproto.MessageReply{Status: "failed", Text: "Could not steer the agent: " + err.Error(), SessionID: sid}
			return
		}
		request.reply <- hubproto.MessageReply{Status: "done", Text: "Added to this conversation's running agent context; its current action will finish first.", SessionID: sid}
	}
	wait()
	var result waited
	for {
		select {
		case request := <-turn.inputs:
			steer(request)
		case result = <-results:
			if result.version != version && !result.canceled && result.out.Status != "timeout" && result.at.Before(deadline) {
				wait()
				continue
			}
			// Admission and this last mailbox check share one short critical section.
			// Inputs admitted during booking create the next queued turn instead.
			d.operatorMu.Lock()
			if !result.canceled && result.out.Status != "timeout" && result.version == version && time.Now().Before(deadline) {
				select {
				case request := <-turn.inputs:
					d.operatorMu.Unlock()
					steer(request)
					wait()
					continue
				default:
				}
			}
			turn.phase = operatorBooking
			// A completed answer stays completed even if the admission lock was slow.
			// Inputs arriving too late for this run are queued with their own answer.
			if result.out.Status == "completed" && result.version == version && !result.canceled {
				for {
					select {
					case request := <-turn.inputs:
						d.admitOperatorLocked(turn.key, request)
					default:
						goto drained
					}
				}
			}
		drained:
			d.operatorMu.Unlock()
			goto finished
		}
	}
finished:
	out := result.out
	abort := result.canceled || out.Status == "timeout" || result.version != version
	if abort {
		abortCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
		_ = kc.Abort(abortCtx, sid)
		stop()
		if out.Status == "completed" {
			out.Status = "timeout"
		}
	}
	if result.canceled && first.ctx.Err() == nil {
		out.Status = "failed"
		out.Text = "The agent engine stopped while answering; ask again after it restarts."
	}
	// Ownership and the queue slot remain held through the cost snapshot and write.
	d.reportRemoteChanges(m, started)
	usd, tin, tout, cached := d.sessionCost(sid)
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
	if text == "" {
		text = "(the agent finished without a reply; status " + out.Status + ")"
	}
	first.reply <- hubproto.MessageReply{Status: status, Text: text, SessionID: sid, CostUSD: spent}
}
