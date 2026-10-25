package mcpserver

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Problem99-io/kodeblue/internal/blue/config"
	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
	"github.com/Problem99-io/kodeblue/internal/blue/respond"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

// In contain mode a hub rule can still require approval or turn an action
// off; neither path reaches the root helper.
func TestRespondFollowsHubActionRules(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Server.StateDir = dir
	cfg.Response.StateDir = filepath.Join(dir, "response")
	cfg.Response.Mode = "contain"
	st, err := store.Open(filepath.Join(dir, "kb.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	in := &store.Incident{Title: "x", Severity: "high", Kind: "incident"}
	if err := st.CreateIncident(in); err != nil {
		t.Fatal(err)
	}
	args := func(action string, params map[string]string) json.RawMessage {
		b, _ := json.Marshal(map[string]any{"incident_id": in.ID, "action": action, "params": params,
			"justification": "outbound connection to a known mining pool from /tmp/x"})
		return b
	}

	cfg.ActionRules = map[string]string{"block_ip": hubproto.ActionApprove, "lock_user": hubproto.ActionOff}
	s := New(cfg, st)
	out, err := s.respond(context.Background(), args("block_ip", map[string]string{"ip": "203.0.113.9"}))
	if err != nil || !strings.Contains(out, "awaiting operator approval") {
		t.Fatalf("approve rule in contain mode: %q %v", out, err)
	}
	if reqs := LoadRequests(cfg); len(reqs) != 1 || reqs[0].Action != "block_ip" {
		t.Fatalf("pending: %+v", reqs)
	}
	if _, err := s.respond(context.Background(), args("lock_user", map[string]string{"user": "mallory"})); err == nil || !strings.Contains(err.Error(), "turned lock_user off") {
		t.Fatalf("off rule: %v", err)
	}
}

// An agent may not quarantine a protected/baseline admin's authorized_keys,
// even though the path contains "/." (the "suspicious" shortcut): that would
// lock the admins out.
func TestRespondRefusesAdminKeyQuarantine(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Server.StateDir = dir
	cfg.Response.StateDir = dir + "-respond"
	cfg.Response.Mode = "contain"
	st, err := store.Open(filepath.Join(dir, "kb.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	in := &store.Incident{Title: "x", Severity: "high", Kind: "incident"}
	if err := st.CreateIncident(in); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]any{"incident_id": in.ID, "action": "quarantine_file",
		"params":        map[string]string{"path": "/root/.ssh/authorized_keys"},
		"justification": "the attacker appended a key to root's authorized_keys after the brute force"})
	s := New(cfg, st)
	if _, err := s.respond(context.Background(), b); err == nil || !strings.Contains(err.Error(), "authorized_keys") {
		t.Fatalf("quarantining root's authorized_keys must be refused, got %v", err)
	}
}

// Only a completed action that can be undone tells the team how to undo it.
func TestActionNoticeUndoLine(t *testing.T) {
	req := func(action string) respond.Request {
		return respond.Request{ID: "act_1", IncidentID: 3, Action: action}
	}
	kept := map[string]string{"note": "process killed; binary preserved at /q/1-pid9", "evidence": "/q/1-pid9"}
	for _, c := range []struct {
		name, action, status string
		undo                 map[string]string
		undoLine, binary     string
	}{
		{"block done", "block_ip", "done", map[string]string{"cmd": "iptables", "ip": "198.51.100.7"}, "kodeblue respond undo act_1", ""},
		{"block pending", "block_ip", "awaiting approval", nil, "", ""},
		{"block refused", "block_ip", "refused", nil, "", ""},
		{"already done by another", "block_ip", "done", nil, "", ""},
		{"kill kept binary", "kill_process", "done", kept, "not possible: a killed process cannot be revived", "preserved for forensics in /q/1-pid9"},
		{"kill lost binary", "kill_process", "done", map[string]string{"note": "process killed; its binary could not be preserved"}, "not possible: a killed process cannot be revived", "could not be preserved"},
	} {
		f := actionFields(req(c.action), c.status, "{}", c.undo)
		if f["Undo"] != c.undoLine || f["Binary"] != c.binary {
			t.Errorf("%s: Undo %q Binary %q, want %q %q", c.name, f["Undo"], f["Binary"], c.undoLine, c.binary)
		}
	}
}
