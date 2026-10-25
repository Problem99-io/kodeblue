package mcpserver

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Problem99-io/kodeblue/internal/blue/config"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

// An agent's report becomes an escalated finding, which the daemon turns
// into an incident; a second report about the same subject joins it.
func TestFindingReport(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Server.StateDir = dir
	st, err := store.Open(filepath.Join(dir, "kb.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s := New(cfg, st)
	call := func(args map[string]any) (string, error) {
		b, _ := json.Marshal(args)
		return s.findingReport(context.Background(), b)
	}
	if _, err := call(map[string]any{"severity": "medium", "title": "x", "subject": "10.0.0.7", "evidence": strings.Repeat("e", 50)}); err == nil {
		t.Fatal("medium must be refused")
	}
	if _, err := call(map[string]any{"severity": "high", "title": "x", "subject": "10.0.0.7", "evidence": "short"}); err == nil {
		t.Fatal("evidence is required")
	}
	ev := "10.0.0.7 read /rest/admin/application-configuration and logged in after probing /api/Users"
	out, err := call(map[string]any{"severity": "high", "title": "Client 10.0.0.7 attacking the app", "subject": "10.0.0.7", "evidence": ev})
	if err != nil || !strings.Contains(out, "reported as finding") {
		t.Fatalf("report: %v %s", err, out)
	}
	esc := st.FindingsByStatus("escalated", 10)
	if len(esc) != 1 || esc[0].Rule != "agent.report" || esc[0].Evidence["subject"] != "10.0.0.7" || esc[0].IncidentID != 0 {
		t.Fatalf("want one escalated agent.report finding waiting for an incident: %+v", esc)
	}
	if out, _ := call(map[string]any{"severity": "high", "title": "again", "subject": "10.0.0.7", "evidence": ev}); !strings.Contains(out, "already reported") {
		t.Fatalf("second report should join the first: %s", out)
	}
}
