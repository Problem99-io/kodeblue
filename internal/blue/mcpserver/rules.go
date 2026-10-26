package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/containment"
	"github.com/Problem99-io/kodeblue/internal/blue/notify"
	"github.com/Problem99-io/kodeblue/internal/blue/respond"
)

// containmentRulePropose records an agent's proposal for a containment rule.
// It does nothing until a person approves it; the team is asked on Slack.
func (s *Server) containmentRulePropose(ctx context.Context, args json.RawMessage) (string, error) {
	var a struct {
		ID         string            `json:"id"`
		Title      string            `json:"title"`
		Why        string            `json:"why"`
		Rule       string            `json:"trigger_rule"`
		Field      string            `json:"target_field"`
		Extract    string            `json:"extract"`
		Action     string            `json:"action"`
		Scope      map[string]string `json:"scope"`
		MaxPerHour int               `json:"max_per_hour"`
		Days       int               `json:"days"`
		Incidents  []int64           `json:"incidents"`
		Findings   []int64           `json:"findings"`
	}
	if err := decode(args, &a); err != nil {
		return "", err
	}
	// Recurring means seen before: name the cases that show it.
	var seen []string
	for _, id := range a.Incidents {
		if in := s.st.GetIncident(id); in != nil {
			seen = append(seen, fmt.Sprintf("incident #%d %s", id, truncate(in.Title, 100)))
		}
	}
	for _, id := range a.Findings {
		if f := s.st.GetFinding(id); f != nil {
			if f.Rule != a.Rule {
				return "", fmt.Errorf("finding #%d is %s, not %s: name findings of the rule this answers", id, f.Rule, a.Rule)
			}
			seen = append(seen, fmt.Sprintf("finding #%d %s (%d times)", id, truncate(f.Title, 100), max(f.Occurrences, 1)))
		}
	}
	if len(seen) < 2 {
		return "", errors.New("a containment rule answers a recurring attack: name at least two existing incidents or findings (incidents, findings) that show it")
	}
	if a.MaxPerHour == 0 {
		a.MaxPerHour = 10
	}
	if a.Days == 0 {
		a.Days = 30
	}
	r := respond.Rule{ID: a.ID, Title: truncate(a.Title, 200), Why: truncate(a.Why, 3000) + "\n\nSeen in: " + strings.Join(seen, "; "),
		When: respond.Trigger{Rule: a.Rule, Field: a.Field, Extract: a.Extract}, Action: a.Action, Scope: a.Scope, MaxPerHour: a.MaxPerHour, Days: a.Days}
	if !s.allowsAction(a.Action) {
		return "", fmt.Errorf("%s is not in this server's allowed_actions, so no rule can take it", a.Action)
	}
	v, err := containment.Propose(s.st, r, "agent")
	if err != nil {
		return "", err
	}
	s.slack.Async(notify.Message{Server: s.cfg.Server.Name, Kind: "action", Severity: "high",
		Title: "Approval needed: containment rule " + v.ID,
		Body: fmt.Sprintf("%s\nWhen a %s finding names a target in %q: %s it (at most %d an hour, for %d days once approved).\n\n%s\n\nApprove on the hub (Monitors & rules) or on the server: sudo kodeblue rules approve %s",
			v.Title, v.When.Rule, v.When.Field, v.Action, v.MaxPerHour, v.Days, truncate(v.Why, 1500), v.ID),
		Fields: map[string]string{"Rule": v.ID}}, nil)
	return fmt.Sprintf("Proposed containment rule %s. It does nothing until a person approves it (hub, or sudo kodeblue rules approve %s on the server); the team was asked on Slack.", v.ID, v.ID), nil
}

func (s *Server) allowsAction(a string) bool {
	for _, x := range s.cfg.Response.AllowedActions {
		if x == a {
			return true
		}
	}
	return false
}

func (s *Server) containmentRuleList(ctx context.Context, args json.RawMessage) (string, error) {
	views := containment.List(s.cfg, s.st)
	if len(views) == 0 {
		return "No containment rules yet.", nil
	}
	var b strings.Builder
	for _, v := range views {
		fmt.Fprintf(&b, "- %s [%s] %s: when %s names %s", v.ID, v.Status, v.Title, v.When.Rule, v.When.Field)
		if v.When.Extract != "" {
			fmt.Fprintf(&b, " (extract %s)", v.When.Extract)
		}
		fmt.Fprintf(&b, ", %s, max %d/h", v.Action, v.MaxPerHour)
		if v.ApprovedBy != "" {
			fmt.Fprintf(&b, "; approved by %s, expires %s", v.ApprovedBy, v.ExpiresAt.Format(time.DateOnly))
		}
		fmt.Fprintf(&b, "; fired %d times (%d in the last hour)", v.Fired, v.FiredHour)
		if v.Note != "" {
			fmt.Fprintf(&b, "; note: %s", v.Note)
		}
		b.WriteString("\n")
	}
	return b.String(), nil
}

func (s *Server) containmentRulePause(ctx context.Context, args json.RawMessage) (string, error) {
	var a struct {
		ID     string `json:"id"`
		Reason string `json:"reason"`
	}
	if err := decode(args, &a); err != nil {
		return "", err
	}
	if strings.TrimSpace(a.Reason) == "" {
		return "", errors.New("say why the rule must stop (it acted on something it should not have, the attack stopped)")
	}
	r, err := containment.Pause(ctx, s.cfg, s.st, a.ID, "", truncate(a.Reason, 500))
	if err != nil {
		return "", err
	}
	s.slack.Async(notify.Message{Server: s.cfg.Server.Name, Kind: "action", Severity: "high",
		Title: "Containment rule " + r.ID + " paused by an agent", Body: a.Reason + "\n\nOnly an approval resumes it."}, nil)
	return "Paused " + r.ID + ". Only a person's approval makes it act again.", nil
}
