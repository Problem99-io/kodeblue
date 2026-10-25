package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

// findingReport lets an agent that found an intrusion outside an incident
// (the learner reading a log, the reviewer, an operator session) open one.
// Without it the only outlet was Slack, and nothing contained the attacker.
// The finding skips triage: an agent with host tools already did more than
// triage would; the responder still judges it with evidence.
func (s *Server) findingReport(ctx context.Context, args json.RawMessage) (string, error) {
	var a struct {
		Severity string `json:"severity"`
		Title    string `json:"title"`
		Subject  string `json:"subject"`
		Evidence string `json:"evidence"`
	}
	if err := decode(args, &a); err != nil {
		return "", err
	}
	switch a.Severity {
	case "high", "critical":
	default:
		return "", errors.New("severity must be high or critical; put lesser observations in definitions or your report")
	}
	a.Title, a.Subject, a.Evidence = strings.TrimSpace(a.Title), strings.TrimSpace(a.Subject), strings.TrimSpace(a.Evidence)
	if a.Title == "" || a.Subject == "" || len(a.Evidence) < 40 {
		return "", errors.New("title, subject (the attacker's address, the process or the path) and the evidence you saw are required")
	}
	fp := "agent:" + strings.ToLower(a.Subject)
	if f := s.st.OpenFinding(fp); f != nil {
		s.st.BumpFinding(f.ID)
		return fmt.Sprintf("already reported as finding %d (incident %d); added to it", f.ID, f.IncidentID), nil
	}
	f := &store.Finding{
		Fingerprint: fp, Collector: "agent", Rule: "agent.report", Severity: a.Severity,
		Title:  "Agent report: " + truncate(a.Title, 160),
		Detail: truncate(a.Evidence, 4000),
		Evidence: map[string]string{
			"kind":     "agent_report",
			"subject":  truncate(a.Subject, 200),
			"evidence": truncate(a.Evidence, 4000),
		},
		Status: "escalated",
	}
	if err := s.st.AddFinding(f); err != nil {
		return "", err
	}
	s.st.Journal("agent", "finding.report", fmt.Sprintf("#%d %s: %s", f.ID, a.Subject, a.Title))
	return fmt.Sprintf("reported as finding %d; kodeblue opens an incident for it and a responder investigates and contains it", f.ID), nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
