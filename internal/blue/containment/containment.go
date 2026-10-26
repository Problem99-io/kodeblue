// Package containment manages containment rules on the unprivileged side:
// agents propose them, people approve them (on the server or the hub), and
// the daemon fires the approved ones on the findings they answer. Approving,
// pausing and deleting go through the root helper, which keeps the only copy
// that counts and checks every action a rule asks for (respond.ExecuteRule).
package containment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/config"
	"github.com/Problem99-io/kodeblue/internal/blue/respond"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

// View is a rule as people see it: the proposal, the helper's state when it
// was approved (that state wins), and what it has done.
type View struct {
	respond.Rule
	// Hash identifies the proposed content; an approval must name it.
	Hash string `json:"hash"`
	// Fired counts the actions it took; LastFired is the latest.
	Fired     int       `json:"fired"`
	FiredHour int       `json:"fired_last_hour"`
	LastFired time.Time `json:"last_fired,omitzero"`
	// Proposed is the proposal waiting (or rejected) beside an approved copy
	// that differs from it: approving it replaces the approved copy.
	Pending bool `json:"pending_change,omitempty"`
}

// Propose records an agent's proposal. It acts on nothing until a person
// approves it.
func Propose(st *store.Store, r respond.Rule, by string) (View, error) {
	r.Status, r.ProposedBy, r.ProposedAt = respond.RuleProposed, by, time.Now().UTC()
	r.ApprovedBy, r.ApprovedAt, r.ExpiresAt, r.ChangedBy, r.ChangedAt, r.Note = "", time.Time{}, time.Time{}, "", time.Time{}, ""
	if err := respond.ValidateRule(r); err != nil {
		return View{}, err
	}
	// A person's no stands: the same proposal again is refused, and a
	// deleted id is not reused.
	for _, p := range st.RuleProposals() {
		var old respond.Rule
		if p.ID != r.ID || json.Unmarshal(p.Body, &old) != nil {
			continue
		}
		switch {
		case p.Status == respond.RuleDeleted:
			return View{}, fmt.Errorf("rule %s was deleted; propose a different rule under a new id", r.ID)
		case p.Status == respond.RuleRejected && old.Hash() == r.Hash():
			return View{}, fmt.Errorf("this exact rule was rejected (%s); change what the objection was about, or leave it", p.Note)
		}
	}
	b, _ := json.Marshal(r)
	if err := st.PutRuleProposal(r.ID, b, by); err != nil {
		return View{}, err
	}
	return View{Rule: r, Hash: r.Hash()}, nil
}

// List merges proposals with the helper's approved rules, most actionable
// first: waiting for approval, active, paused, then the rest.
func List(cfg config.Config, st *store.Store) []View {
	now := time.Now()
	approved := map[string]respond.Rule{}
	for _, r := range respond.LoadRules(cfg.Response.StateDir) {
		approved[r.ID] = r
	}
	byID := map[string]*View{}
	for _, p := range st.RuleProposals() {
		var r respond.Rule
		if json.Unmarshal(p.Body, &r) != nil {
			continue
		}
		r.Status, r.ProposedBy, r.Note = p.Status, p.ProposedBy, p.Note
		if p.Status == respond.RuleRejected {
			r.ChangedAt = p.UpdatedAt
		}
		v := &View{Rule: r, Hash: r.Hash()}
		if a, ok := approved[r.ID]; ok {
			pending := p.Status == respond.RuleProposed && a.Hash() != r.Hash()
			a.ProposedBy, a.ProposedAt = r.ProposedBy, r.ProposedAt
			v = &View{Rule: a, Hash: a.Hash(), Pending: pending}
			if pending {
				v.Hash = r.Hash() // what an approval must name
			}
		}
		byID[r.ID] = v
	}
	for id, a := range approved {
		if _, ok := byID[id]; !ok {
			byID[id] = &View{Rule: a, Hash: a.Hash()}
		}
	}
	for _, rec := range respond.Load(cfg.Response.StateDir) {
		id := respond.RuleOf(rec.RequestedBy)
		v := byID[id]
		if v == nil || rec.Status != "done" || rec.DoneAt.IsZero() {
			continue
		}
		v.Fired++
		if now.Sub(rec.DoneAt) < time.Hour {
			v.FiredHour++
		}
		if rec.DoneAt.After(v.LastFired) {
			v.LastFired = rec.DoneAt
		}
	}
	out := make([]View, 0, len(byID))
	for _, v := range byID {
		v.Status = v.Effective(now)
		out = append(out, *v)
	}
	order := map[string]int{respond.RuleProposed: 0, respond.RuleActive: 1, respond.RulePaused: 2, respond.RuleExpired: 3, respond.RuleRejected: 4, respond.RuleDeleted: 5}
	slices.SortFunc(out, func(a, b View) int {
		if a.Pending != b.Pending {
			if a.Pending {
				return -1
			}
			return 1
		}
		if d := order[a.Status] - order[b.Status]; d != 0 {
			return d
		}
		return strings.Compare(a.ID, b.ID)
	})
	return out
}

// Get is one rule's view, or nil.
func Get(cfg config.Config, st *store.Store, id string) *View {
	for _, v := range List(cfg, st) {
		if v.ID == id {
			return &v
		}
	}
	return nil
}

// toApprove is the content an approval of id makes active: the proposal
// when one waits, otherwise the approved copy (renewing or resuming it).
func toApprove(cfg config.Config, st *store.Store, id string) (respond.Rule, error) {
	for _, p := range st.RuleProposals() {
		if p.ID == id && p.Status == respond.RuleProposed {
			var r respond.Rule
			if err := json.Unmarshal(p.Body, &r); err != nil {
				return r, err
			}
			return r, nil
		}
	}
	for _, r := range respond.LoadRules(cfg.Response.StateDir) {
		if r.ID == id {
			if r.Status == respond.RuleDeleted {
				return r, fmt.Errorf("rule %s was deleted", id)
			}
			return r, nil
		}
	}
	return respond.Rule{}, fmt.Errorf("no containment rule %s", id)
}

// helperRule runs a rule op on the root helper.
func helperRule(ctx context.Context, cfg config.Config, env map[string]any) (respond.Rule, error) {
	payload, _ := json.Marshal(env)
	out, err := respond.Invoke(ctx, cfg.Path(), payload)
	if err != nil {
		return respond.Rule{}, err
	}
	var res struct {
		Status string       `json:"status"`
		Result string       `json:"result"`
		Rule   respond.Rule `json:"rule"`
	}
	if json.Unmarshal(out, &res) != nil {
		return respond.Rule{}, fmt.Errorf("helper: %s", strings.TrimSpace(string(out)))
	}
	if res.Status != "done" {
		return respond.Rule{}, errors.New(res.Result)
	}
	return res.Rule, nil
}

// Approve asks the root helper to make the rule active. hash is the content
// the approver saw (View.Hash); hubBy is "hub:<operator>" when relayed from
// the hub, empty when root approves on the server.
func Approve(ctx context.Context, cfg config.Config, st *store.Store, id, hash, hubBy string) (respond.Rule, error) {
	r, err := toApprove(cfg, st, id)
	if err != nil {
		return r, err
	}
	env := map[string]any{"op": "rule_approve", "rule": r, "rule_hash": hash}
	if hubBy != "" {
		env["hub_by"] = hubBy
	}
	a, err := helperRule(ctx, cfg, env)
	if err != nil {
		return a, err
	}
	_ = st.SetRuleProposalStatus(id, "approved", a.ApprovedBy, "")
	return a, nil
}

// Pause stops an approved rule from acting; only an approval resumes it.
func Pause(ctx context.Context, cfg config.Config, st *store.Store, id, hubBy, note string) (respond.Rule, error) {
	r, err := helperRule(ctx, cfg, map[string]any{"op": "rule_pause", "rule_id": id, "hub_by": hubBy, "note": note})
	if err == nil {
		st.Journal(r.ChangedBy, "rule.paused", id+": "+note)
	}
	return r, err
}

// Delete removes an approved rule for good (an approval or root needed).
// A proposal never approved has nothing on the helper and is only marked.
func Delete(ctx context.Context, cfg config.Config, st *store.Store, id, hubBy, note string) (respond.Rule, error) {
	if !slices.ContainsFunc(respond.LoadRules(cfg.Response.StateDir), func(r respond.Rule) bool { return r.ID == id }) {
		by := hubBy
		if by == "" {
			by = "root"
		}
		return respond.Rule{ID: id, Status: respond.RuleDeleted, ChangedBy: by}, st.SetRuleProposalStatus(id, respond.RuleDeleted, by, note)
	}
	r, err := helperRule(ctx, cfg, map[string]any{"op": "rule_delete", "rule_id": id, "hub_by": hubBy, "note": note})
	if err == nil {
		_ = st.SetRuleProposalStatus(id, respond.RuleDeleted, r.ChangedBy, note)
	}
	return r, err
}

// Reject turns a proposal down. Nothing is active, so the helper is not
// involved.
func Reject(st *store.Store, id, by, note string) error {
	return st.SetRuleProposalStatus(id, respond.RuleRejected, by, note)
}

// Active are the approved rules acting now (the helper's copy).
func Active(cfg config.Config, now time.Time) []respond.Rule {
	var out []respond.Rule
	for _, r := range respond.LoadRules(cfg.Response.StateDir) {
		if r.Effective(now) == respond.RuleActive {
			out = append(out, r)
		}
	}
	return out
}

// Invoker runs a containment request on the root helper (tests replace it).
type Invoker func(ctx context.Context, req respond.Request) (*respond.Record, error)

// HelperInvoker is the root helper.
func HelperInvoker(cfg config.Config) Invoker {
	return func(ctx context.Context, req respond.Request) (*respond.Record, error) {
		payload, _ := json.Marshal(map[string]any{"op": "execute", "request": req})
		out, err := respond.Invoke(ctx, cfg.Path(), payload)
		if err != nil {
			return nil, err
		}
		var rec respond.Record
		if err := json.Unmarshal(out, &rec); err != nil {
			return nil, fmt.Errorf("helper output: %s", strings.TrimSpace(string(out)))
		}
		return &rec, nil
	}
}

// Fired is what one rule did about one finding.
type Fired struct {
	Rule    string
	Target  string
	Done    bool
	Message string
}

// Fire runs every active rule that answers f, for each target the finding
// names. The helper decides; this only asks.
func Fire(ctx context.Context, rules []respond.Rule, f *store.Finding, run Invoker) []Fired {
	var out []Fired
	for _, r := range rules {
		if r.When.Rule != f.Rule {
			continue
		}
		for _, target := range r.When.Targets(f.Evidence) {
			params, err := r.RuleParams(target)
			if err != nil {
				out = append(out, Fired{Rule: r.ID, Target: target, Message: "not taken: " + err.Error()})
				continue
			}
			req := respond.Request{ID: respond.NewID(), IncidentID: f.IncidentID, Action: r.Action, Params: params,
				Justification: fmt.Sprintf("containment rule %s (%s), approved by %s, answering finding #%d: %s", r.ID, r.Title, r.ApprovedBy, f.ID, f.Title),
				RequestedBy:   respond.RuleRequester(r.ID), RequestedAt: time.Now()}
			rec, err := run(ctx, req)
			switch {
			case err != nil:
				out = append(out, Fired{Rule: r.ID, Target: target, Message: "helper unavailable: " + err.Error()})
			default:
				out = append(out, Fired{Rule: r.ID, Target: target, Done: rec.Status == "done", Message: rec.Status + ": " + rec.Result})
			}
		}
	}
	return out
}
