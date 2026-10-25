package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/detect"
	"github.com/Problem99-io/kodeblue/internal/blue/notify"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

func (s *Server) findingsList(ctx context.Context, args json.RawMessage) (string, error) {
	var a struct {
		Status     string `json:"status"`
		SinceHours int    `json:"since_hours"`
		Limit      int    `json:"limit"`
	}
	if err := decode(args, &a); err != nil {
		return "", err
	}
	if a.Limit <= 0 {
		a.Limit = 50
	}
	if a.SinceHours <= 0 {
		a.SinceHours = 24
	}
	var list []store.Finding
	if a.Status != "" {
		for _, f := range s.st.FindingsByStatus(a.Status, a.Limit) {
			if time.Since(f.CreatedAt) < time.Duration(a.SinceHours)*time.Hour {
				list = append(list, f)
			}
		}
	} else {
		list = s.st.FindingsSince(time.Now().Add(-time.Duration(a.SinceHours)*time.Hour), a.Limit)
	}
	return jsonOut(list) + untrusted, nil
}

func (s *Server) incidentGet(ctx context.Context, args json.RawMessage) (string, error) {
	var a struct {
		ID int64 `json:"id"`
	}
	if err := decode(args, &a); err != nil {
		return "", err
	}
	in := s.st.GetIncident(a.ID)
	if in == nil {
		return "", fmt.Errorf("incident %d not found", a.ID)
	}
	return jsonOut(map[string]any{"incident": in, "findings": s.st.FindingsForIncident(a.ID)}) + untrusted, nil
}

func (s *Server) incidentResolve(ctx context.Context, args json.RawMessage) (string, error) {
	var a struct {
		ID       int64   `json:"id"`
		Verdict  string  `json:"verdict"`
		Severity string  `json:"severity"`
		Summary  string  `json:"summary"`
		Report   string  `json:"report"`
		Absorb   *bool   `json:"absorb"`
		Conf     float64 `json:"confidence"`
		SelfEval string  `json:"self_evaluation"`
	}
	if err := decode(args, &a); err != nil {
		return "", err
	}
	in := s.st.GetIncident(a.ID)
	if in == nil {
		return "", fmt.Errorf("incident %d not found", a.ID)
	}
	switch a.Verdict {
	case "true_positive", "false_positive", "benign_change", "inconclusive":
	default:
		return "", errors.New("verdict must be true_positive|false_positive|benign_change|inconclusive")
	}
	if detect.Rank(a.Severity) == 0 && a.Severity != "info" {
		return "", errors.New("severity must be low|medium|high|critical")
	}
	if len(strings.TrimSpace(a.Summary)) < 20 || len(strings.TrimSpace(a.Report)) < 50 {
		return "", errors.New("summary and report must contain the actual evidence")
	}
	in.Verdict, in.Summary, in.Report, in.Severity = a.Verdict, a.Summary, a.Report, a.Severity
	if a.Conf > 1 {
		a.Conf /= 100 // models sometimes answer in percent
	}
	in.Confidence, in.SelfEval = min(max(a.Conf, 0), 1), strings.TrimSpace(a.SelfEval)
	in.Status = "resolved"
	if a.Verdict == "inconclusive" || a.Verdict == "true_positive" {
		in.Status = "needs_human"
	}
	if err := s.st.UpdateIncident(in); err != nil {
		return "", err
	}
	absorb := a.Verdict == "false_positive" || a.Verdict == "benign_change"
	if a.Absorb != nil {
		absorb = absorb && *a.Absorb
	}
	var accepted, refused []string
	findings := s.st.FindingsForIncident(a.ID)
	protectedBenign := false
	for _, f := range findings {
		if f.Evidence["protected"] == "true" && (a.Verdict == "false_positive" || a.Verdict == "benign_change") {
			protectedBenign = true
		}
	}
	if protectedBenign {
		// A model may not close a protected detection (planted key, uid 0,
		// sudoers, SUID, ld.so.preload…) as harmless on its own word.
		in.Status = "needs_human"
		_ = s.st.UpdateIncident(in)
	}
	for _, f := range findings {
		status := "closed"
		if f.Evidence["protected"] == "true" && (a.Verdict == "false_positive" || a.Verdict == "benign_change") {
			status = "needs_ack"
		}
		if absorb && f.ItemID != "" {
			if f.Evidence["protected"] == "true" {
				refused = append(refused, f.Title)
				status = "needs_ack"
			} else {
				parts := strings.SplitN(f.ItemID, "|", 2)
				_ = s.st.UpsertBaseline([]store.BaselineItem{{ID: f.ItemID, Collector: parts[0], Key: parts[1], Value: f.Value, Note: fmt.Sprintf("incident #%d %s", a.ID, a.Verdict)}}, "incident")
				accepted = append(accepted, f.Title)
			}
		}
		_ = s.st.SetFindingStatus(f.ID, status, a.Verdict, a.Summary, 0)
	}
	// Persist the report where humans (and later reviews) can read it.
	_ = os.WriteFile(filepath.Join(s.cfg.WorkspaceDir(), "reports", fmt.Sprintf("incident-%d.md", a.ID)),
		[]byte(fmt.Sprintf("# Incident %d — %s\n\nverdict: %s · severity: %s · resolved %s\n\n## Summary\n%s\n\n%s\n", a.ID, in.Title, a.Verdict, a.Severity, time.Now().UTC().Format(time.RFC3339), a.Summary, a.Report)), 0o640)
	s.st.Journal("agent", "incident.resolve", fmt.Sprintf("#%d %s: %s", a.ID, a.Verdict, a.Summary))
	msg := fmt.Sprintf("Incident %d resolved as %s (status %s).", a.ID, a.Verdict, in.Status)
	if len(accepted) > 0 {
		msg += fmt.Sprintf(" Accepted into baseline: %d item(s).", len(accepted))
	}
	if len(refused) > 0 || protectedBenign {
		msg += " This incident involves a protected detection, so it stays open for an operator (`kodeblue ack <finding>`); kodeblue has notified the team."
		s.slack.Async(notify.Message{Server: s.cfg.Server.Name, Kind: "needs_ack", Severity: "high", IncidentID: a.ID,
			Title: fmt.Sprintf("#%d judged %s by the agent — operator confirmation required", a.ID, a.Verdict),
			Body:  a.Summary + "\nProtected detections are never accepted on a model's word. If this is legitimate run: kodeblue ack <finding-id>",
		}, nil)
	}
	return msg, nil
}

var protectedRules = regexp.MustCompile(`^(ssh_key\.|account\.(uid0|empty_password|new_login|privileged_group|shell_enabled)|sudoers\.|persistence\.(ld_preload|auth_hook)|suid\.new|integrity\.(package_mismatch|changed)|package\.checksums_changed|tmp_exec\.elf|process\.(deleted_exe|memfd_exe|suspicious_location)|outbound\.(shell|suspicious_port))`)

var protectedCollectors = map[string]bool{"ssh_key": true, "suid": true}

func (s *Server) allowAdd(ctx context.Context, args json.RawMessage) (string, error) {
	var a struct {
		Collector    string `json:"collector"`
		KeyPattern   string `json:"key_pattern"`
		ValuePattern string `json:"value_pattern"`
		Rule         string `json:"rule"`
		Reason       string `json:"reason"`
		TTLDays      int    `json:"ttl_days"`
	}
	if err := decode(args, &a); err != nil {
		return "", err
	}
	p := strings.TrimSpace(a.KeyPattern)
	narrow := detect.CheckAllowPattern(s.env, p)
	switch {
	case a.Collector == "" || a.Collector == "*":
		return "", errors.New("collector is required and cannot be *")
	case protectedCollectors[a.Collector] || (a.Rule != "" && protectedRules.MatchString(a.Rule)):
		return "", errors.New("protected detections cannot be allow-listed by an agent; an operator must run `kodeblue allow`")
	case narrow != nil:
		return "", fmt.Errorf("pattern too broad: %v (keep a specific literal anchor of at least 8 characters, name the file rather than a whole directory, and do not start with *)", narrow)
	case len(strings.TrimSpace(a.Reason)) < 20:
		return "", errors.New("reason must cite the evidence")
	}
	if a.Collector == "account" && (strings.HasPrefix(p, "user/") || strings.HasPrefix(p, "group/") || strings.HasPrefix(p, "sudoers")) {
		return "", errors.New("account changes cannot be allow-listed by an agent")
	}
	if a.Collector == "persistence" && strings.Contains(p, "ld.so.preload") {
		return "", errors.New("ld.so.preload cannot be allow-listed by an agent")
	}
	if a.TTLDays <= 0 {
		a.TTLDays = 90
	}
	if a.TTLDays > 365 {
		a.TTLDays = 365
	}
	r := &store.AllowRule{Collector: a.Collector, KeyPattern: p, ValuePattern: a.ValuePattern, Rule: a.Rule, Reason: a.Reason, CreatedBy: "agent", ExpiresAt: time.Now().Add(time.Duration(a.TTLDays) * 24 * time.Hour)}
	if err := s.st.AddAllowRule(r); err != nil {
		return "", err
	}
	return fmt.Sprintf("allow rule #%d added (expires %s)", r.ID, r.ExpiresAt.Format("2006-01-02")), nil
}

func (s *Server) allowList(ctx context.Context, args json.RawMessage) (string, error) {
	return jsonOut(s.st.AllowRules()), nil
}

func (s *Server) allowDisable(ctx context.Context, args json.RawMessage) (string, error) {
	var a struct {
		ID     int64  `json:"id"`
		Reason string `json:"reason"`
	}
	if err := decode(args, &a); err != nil {
		return "", err
	}
	return "disabled", s.st.DisableAllowRule(a.ID, "agent: "+a.Reason)
}
