package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/hostexec"
	"github.com/Problem99-io/kodeblue/internal/blue/monitor"
	"github.com/Problem99-io/kodeblue/internal/skill"
)

func parseSpec(raw json.RawMessage) (*monitor.Spec, error) {
	var w struct {
		Spec json.RawMessage `json:"spec"`
	}
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, err
	}
	if t := strings.TrimSpace(string(w.Spec)); t == "" || t == "{}" || t == "null" {
		// Small models sometimes drop the nested object; say exactly what is missing.
		return nil, errors.New(`spec is empty: put every field inside "spec", e.g. {"spec": {"id": "sshd-port-22", "kind": "port", "port": 22, "description": "sshd listens on 22", "rationale": "only admin path", "severity": "medium", "interval_seconds": 60}}`)
	}
	var spec monitor.Spec
	if err := json.Unmarshal(w.Spec, &spec); err != nil {
		return nil, fmt.Errorf("spec: %w", err)
	}
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	return &spec, nil
}

func (s *Server) monitorCreate(ctx context.Context, args json.RawMessage) (string, error) {
	spec, err := parseSpec(args)
	if err != nil {
		return "", err
	}
	if len(s.st.Monitors(false)) >= 60 {
		return "", errors.New("monitor limit (60) reached; disable obsolete monitors first")
	}
	b, _ := json.Marshal(spec)
	if err := s.st.PutMonitor(spec.ID, b, "agent"); err != nil {
		return "", err
	}
	if spec.NewValues {
		// A replaced spec learns its known values afresh (from known_values
		// or the log), not from what the old spec remembered.
		_ = s.st.Set("monitor_seen:"+spec.ID, "")
	}
	return fmt.Sprintf("monitor %s saved (every %ds, %d consecutive failures before a finding)", spec.ID, spec.IntervalSeconds, spec.ConsecutiveFailures), nil
}

func (s *Server) monitorTest(ctx context.Context, args json.RawMessage) (string, error) {
	spec, err := parseSpec(args)
	if err != nil {
		return "", err
	}
	ok, output, err := monitor.Probe(ctx, s.cfg.Server.StateDir, s.env, *spec)
	if err != nil {
		return "", err
	}
	out := fmt.Sprintf("valid. passes_now=%v output: %s", ok, output)
	if spec.Kind == "log" {
		// A log monitor only reads what is written from now on; show what
		// its pattern finds in today's log.
		out += "\n" + monitor.NewRunner(nil, s.env).LogBacktest(*spec)
	}
	return out + untrusted, nil
}

func (s *Server) monitorList(ctx context.Context, args json.RawMessage) (string, error) {
	return jsonOut(s.st.Monitors(true)) + untrusted, nil
}

func (s *Server) monitorDisable(ctx context.Context, args json.RawMessage) (string, error) {
	var a struct {
		ID     string `json:"id"`
		Reason string `json:"reason"`
	}
	if err := decode(args, &a); err != nil {
		return "", err
	}
	return "disabled", s.st.DisableMonitor(a.ID, "agent", a.Reason)
}

func (s *Server) profileSet(ctx context.Context, args json.RawMessage) (string, error) {
	var a struct {
		Summary string `json:"summary"`
	}
	if err := decode(args, &a); err != nil {
		return "", err
	}
	a.Summary = strings.TrimSpace(a.Summary)
	if len(a.Summary) < 100 {
		return "", errors.New("profile too short to be useful")
	}
	if len(a.Summary) > 2000 {
		a.Summary = a.Summary[:2000]
	}
	s.st.Journal("agent", "profile.set", fmt.Sprintf("%d chars", len(a.Summary)))
	return "profile saved", s.st.Set("profile_summary", a.Summary)
}

func (s *Server) skillWrite(ctx context.Context, args json.RawMessage) (string, error) {
	var a struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Body        string `json:"body"`
	}
	if err := decode(args, &a); err != nil {
		return "", err
	}
	if err := skill.ValidateName(a.Name); err != nil {
		return "", err
	}
	desc := strings.ReplaceAll(strings.TrimSpace(a.Description), "\n", " ")
	if desc == "" || len(strings.TrimSpace(a.Body)) < 50 {
		return "", errors.New("description and a real procedure body are required")
	}
	dir := filepath.Join(s.cfg.WorkspaceDir(), ".kodeblue", "skills", a.Name)
	if b, err := os.ReadFile(filepath.Join(dir, "SKILL.md")); err == nil && strings.Contains(string(b), "kodeblue-bundled: true") {
		return "", errors.New("bundled skills are read-only; write a new server-specific skill instead")
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	content := fmt.Sprintf("---\nname: %s\ndescription: %s\nmetadata:\n  author: kodeblue-agent\n  updated: %s\n---\n\n%s\n", a.Name, desc, time.Now().UTC().Format("2006-01-02"), strings.TrimSpace(a.Body))
	if _, err := skill.ParseMarkdown(content); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(content), 0o640); err != nil {
		return "", err
	}
	s.st.Journal("agent", "skill.write", a.Name)
	return "skill " + a.Name + " saved; available to future sessions via the skill tool", nil
}

func (s *Server) integrityAdd(ctx context.Context, args json.RawMessage) (string, error) {
	var a struct {
		Paths []string `json:"paths"`
	}
	if err := decode(args, &a); err != nil {
		return "", err
	}
	var cur []string
	_ = json.Unmarshal([]byte(s.st.Get("extra_integrity_paths")), &cur)
	seen := map[string]bool{}
	for _, p := range cur {
		seen[p] = true
	}
	for _, p := range a.Paths {
		if !filepath.IsAbs(p) || hostexec.IsSecretPath(p) {
			return "", fmt.Errorf("%s: must be absolute and not a secret path", p)
		}
		if !seen[p] {
			cur = append(cur, p)
			seen[p] = true
		}
	}
	if len(cur) > 200 {
		return "", errors.New("integrity watch list limited to 200 paths")
	}
	sort.Strings(cur)
	b, _ := json.Marshal(cur)
	s.st.Journal("agent", "integrity.add", strings.Join(a.Paths, ", "))
	return fmt.Sprintf("watching %d extra paths", len(cur)), s.st.Set("extra_integrity_paths", string(b))
}

func (s *Server) selfEvaluationWrite(ctx context.Context, args json.RawMessage) (string, error) {
	var a struct {
		ID    int64   `json:"id"`
		Score float64 `json:"score"`
		Text  string  `json:"text"`
	}
	if err := decode(args, &a); err != nil {
		return "", err
	}
	in := s.st.GetIncident(a.ID)
	if in == nil || in.Kind != "review" {
		return "", fmt.Errorf("review %d not found", a.ID)
	}
	if a.Score < 1 || a.Score > 10 || len(strings.TrimSpace(a.Text)) < 40 {
		return "", errors.New("score must be 1-10 and text must contain the actual evaluation")
	}
	in.SelfEval, in.Confidence = strings.TrimSpace(a.Text), a.Score/10
	if err := s.st.UpdateIncident(in); err != nil {
		return "", err
	}
	s.st.Journal("agent", "self_evaluation", fmt.Sprintf("review #%d score %.0f/10", a.ID, a.Score))
	return "self-evaluation recorded", nil
}

func (s *Server) stats(ctx context.Context, args json.RawMessage) (string, error) {
	var a struct {
		JournalHours int `json:"journal_hours"`
	}
	_ = decode(args, &a)
	if a.JournalHours <= 0 {
		a.JournalHours = 24
	}
	day := time.Now().UTC().Truncate(24 * time.Hour)
	usd, per, tokens := s.st.SpentSince(day)
	mons := s.st.Monitors(true)
	type mon struct {
		ID         string `json:"id"`
		Runs, Fail int
		LastOK     bool `json:"last_ok"`
		Disabled   bool `json:"disabled"`
	}
	var ms []mon
	for _, m := range mons {
		ms = append(ms, mon{ID: m.ID, Runs: m.Runs, Fail: m.Fails, LastOK: m.LastOK, Disabled: m.Disabled})
	}
	return jsonOut(map[string]any{
		"spend_today_usd": usd, "spend_by_purpose": per, "tokens_today": tokens, "daily_budget_usd": s.cfg.Budget.DailyUSD,
		"findings_7d_by_rule_status": s.st.FindingStats(time.Now().Add(-7 * 24 * time.Hour)),
		"baseline":                   s.st.BaselineCounts(), "monitors": ms,
		"journal": s.st.JournalSince(time.Now().Add(-time.Duration(a.JournalHours)*time.Hour), 80),
	}), nil
}
