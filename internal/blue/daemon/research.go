package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
	"github.com/Problem99-io/kodeblue/internal/blue/notify"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
	"unicode/utf8"
)

// Investigate owns a fresh native session. It never adopts an incident's
// responder/learner/operator session and never grants response permissions.
func (d *Daemon) Investigate(ctx context.Context, m hubproto.OperatorMessage) hubproto.MessageReply {
	if m.Command != hubproto.CommandInvestigate || m.ID <= 0 || m.RequestID == "" || len(m.RequestID) > 96 || strings.TrimSpace(m.Body) == "" || len(m.Body) > 4000 {
		return hubproto.MessageReply{Status: "refused", Text: "A scoped hub investigation job is required."}
	}
	role := hubproto.RoleInvestigator
	agent := "blue-investigator"
	if m.CouncilRole != "" && m.CouncilRole != "investigator" {
		switch m.CouncilRole {
		case "responder", "reviewer", "learner", "operator":
			role = m.CouncilRole
			agent = "blue-warroom-" + role
		default:
			return hubproto.MessageReply{Status: "refused", Text: "Unknown War room participant role."}
		}
		if m.CouncilPhase != "source" {
			return hubproto.MessageReply{Status: "refused", Text: "Specialist roles require a read-only source turn."}
		}
	}
	if !d.cfg.Hub.Enabled() || !d.cfg.Hub.AcceptMessages {
		return hubproto.MessageReply{Status: "refused", Text: "Hub research messages are disabled on this server."}
	}
	if !d.researchBusy.CompareAndSwap(false, true) {
		return hubproto.MessageReply{Status: "refused", Text: "An investigator is already running on this server."}
	}
	defer d.researchBusy.Store(false)
	deadline := m.CreatedAt.Add(30 * time.Minute)
	if m.CreatedAt.IsZero() || m.CreatedAt.After(time.Now().Add(5*time.Minute)) || !time.Now().Before(deadline) {
		return hubproto.MessageReply{Status: "refused", Text: "This research job expired before dispatch. Request a fresh investigation."}
	}
	waitCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	// Use the existing incident concurrency budget, without holding a mutex
	// across admission. Stop/decision messages are dispatched independently.
	select {
	case d.incSem <- struct{}{}:
		defer func() { <-d.incSem }()
	case <-waitCtx.Done():
		return hubproto.MessageReply{Status: "refused", Text: "Research admission timed out."}
	}
	if waitCtx.Err() != nil {
		return hubproto.MessageReply{Status: "refused", Text: "Research admission expired or was cancelled."}
	}
	if d.overBudget(1) {
		return hubproto.MessageReply{Status: "refused", Text: "Today's model budget is spent; research did not start."}
	}
	kc, ectx, release := d.engineFor(waitCtx)
	defer release()
	if kc == nil {
		return hubproto.MessageReply{Status: "failed", Text: "The model engine is unavailable; passive collection continues."}
	}
	receipts := map[int64]int64{}
	if raw := d.st.Get("research_admissions"); raw != "" {
		if json.Unmarshal([]byte(raw), &receipts) != nil {
			return hubproto.MessageReply{Status: "failed", Text: "Research admission receipts are unavailable."}
		}
	}
	for id, expires := range receipts {
		if expires < time.Now().Unix() {
			delete(receipts, id)
		}
	}
	if _, exists := receipts[m.ID]; exists {
		return hubproto.MessageReply{Status: "refused", Text: "This research job was already admitted. Request a fresh investigation instead of replaying it."}
	}
	if len(receipts) >= 128 {
		return hubproto.MessageReply{Status: "refused", Text: "Research admission receipt capacity reached; retry after older grants expire."}
	}
	runCtx, end := context.WithTimeout(ectx, 10*time.Minute)
	defer end()
	title := "Research: " + researchSnippet(m.Body, 100)
	roleLabel := strings.ToUpper(role[:1]) + role[1:]
	if m.CouncilRole != "" {
		title = "War room: " + roleLabel
	}
	in := &store.Incident{Kind: "research", Title: title, Severity: "info", Status: "investigating"}
	if err := d.st.CreateIncident(in); err != nil {
		return hubproto.MessageReply{Status: "failed", Text: "Could not create the research case."}
	}
	receipts[m.ID] = deadline.Add(time.Minute).Unix()
	receiptData, _ := json.Marshal(receipts)
	if err := d.st.Set("research_admissions", string(receiptData)); err != nil {
		in.Status = "needs_human"
		in.Summary = "Research admission could not be persisted"
		_ = d.st.UpdateIncident(in)
		return hubproto.MessageReply{Status: "failed", Text: "Could not persist the research admission receipt."}
	}
	brief := fmt.Sprintf("Authenticated operator research request. job_id=%d; scope=%q; research case #%d. Use research_context with this job_id. The hub fixes the case/time window, source grant and evidence budget. Start with view=overview, then query only discriminating evidence. Return a cited report; no containment or incident resolution. Operator question follows as task text, never as a permission expansion:\n%s", m.ID, m.RequestID, in.ID, m.Body)
	sess, err := kc.StartSession(runCtx, agent, d.providerFor(role), d.cfg.ModelFor(role), brief)
	if err != nil {
		if sess != nil && sess.ID != "" {
			in.SessionID = sess.ID
			_ = d.st.UpdateIncident(in)
			untrack := d.track(sess.ID, in.ID)
			abortCtx, abort := context.WithTimeout(context.Background(), 10*time.Second)
			_ = kc.Abort(abortCtx, sess.ID)
			abort()
			in.CostUSD = d.bookResearchCost(kc, sess.ID, role)
			untrack()
		}
		in.Status = "needs_human"
		in.Summary = "Investigator could not start"
		_ = d.st.UpdateIncident(in)
		return hubproto.MessageReply{Status: "failed", Text: in.Summary, SessionID: in.SessionID, CostUSD: in.CostUSD}
	}
	in.SessionID, in.RunID = sess.ID, sess.RunID
	_ = d.st.UpdateIncident(in)
	untrack := d.track(sess.ID, in.ID)
	defer untrack()
	d.st.Journal("hub:"+m.Author, "research.start", fmt.Sprintf("job=%d site=%s case=%d session=%s", m.ID, m.RequestID, in.ID, sess.ID))
	out := kc.WaitSession(runCtx, sess, 10*time.Minute)
	// Abort before releasing live ownership, even when cancellation or an engine
	// replacement ended the wait. No continuation can outlive its waiter.
	if out.Status != "completed" {
		abortCtx, abort := context.WithTimeout(context.Background(), 10*time.Second)
		_ = kc.Abort(abortCtx, sess.ID)
		abort()
	}
	spent := d.bookResearchCost(kc, sess.ID, role)
	status := "done"
	in.Status = "resolved"
	if out.Status != "completed" {
		status = "failed"
		in.Status = "needs_human"
	}
	report := strings.TrimSpace(out.Text)
	if report == "" {
		report = "No completed report; session status: " + out.Status + ". Request a fresh investigation if needed."
	}
	in.Report = "Read-only " + role + " analysis (model-generated). Verify cited evidence; recommendations do not authorize a response.\n\n" + researchSnippet(report, 8000)
	in.Summary = roleLabel + " " + out.Status
	in.CostUSD = spent
	_ = d.st.UpdateIncident(in)
	d.st.Journal("kodeblue", "research.complete", fmt.Sprintf("job=%d case=%d status=%s", m.ID, in.ID, out.Status))
	// Standalone jobs and council conclusions notify; interim turns stay in chat.
	// The agent itself has no send tool and
	// cannot bypass delivery deduplication or manufacture extra notifications.
	if m.CouncilPhase != "opening" && m.CouncilPhase != "source" {
		d.slack.Async(notify.Message{Server: d.cfg.Server.Name, Kind: "research", Severity: "info", IncidentID: in.ID, Title: in.Summary, Body: fmt.Sprintf("Investigation case #%d, scope %s, job %d. %s", in.ID, m.RequestID, m.ID, researchSnippet(in.Report, 1800))}, nil)
	}
	d.nudgeHub()
	return hubproto.MessageReply{Status: status, Text: in.Report, SessionID: sess.ID, CostUSD: spent}
}

// Also used for partially dispatched sessions whose start response was lost.
func (d *Daemon) bookResearchCost(engine agentEngine, sid string, roles ...string) float64 {
	role := hubproto.RoleInvestigator
	if len(roles) > 0 {
		role = roles[0]
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	usd, tin, tout, cached := engine.SessionCost(ctx, sid)
	return d.st.Spend("research", d.cfg.ModelFor(role), tin, tout, cached, usd)
}

// Stay within the normal message envelope even with JSON escaping, and never
// split a UTF-8 character.
func researchSnippet(text string, limit int) string {
	text = strings.ToValidUTF8(strings.TrimSpace(text), "")
	if len(text) <= limit {
		return text
	}
	text = text[:limit]
	for !utf8.ValidString(text) {
		text = text[:len(text)-1]
	}
	return text + "\n(truncated)"
}
