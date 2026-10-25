package mcpserver

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Problem99-io/kodeblue/internal/blue/config"
	"github.com/Problem99-io/kodeblue/internal/blue/services"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

func TestServiceInventoryAndCoverageCase(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "host")
	// One unit, running, on kodeblue's own filesystem.
	p := filepath.Join(root, "proc", "10")
	_ = os.MkdirAll(filepath.Join(p, "fd"), 0o755)
	_ = os.Symlink("/usr/bin/redis-server", filepath.Join(p, "exe"))
	_ = os.Symlink(root, filepath.Join(p, "root"))
	_ = os.WriteFile(filepath.Join(p, "cmdline"), []byte("redis-server"), 0o644)
	_ = os.WriteFile(filepath.Join(p, "cgroup"), []byte("0::/system.slice/redis-server.service\n"), 0o644)
	_ = os.WriteFile(filepath.Join(p, "status"), []byte("State:\tS\nPPid:\t1\nUid:\t0\n"), 0o644)
	_ = os.MkdirAll(filepath.Join(root, "run/systemd/system"), 0o755)

	cfg := config.Default()
	cfg.Server.StateDir = dir
	cfg.Server.Root = root
	st, err := store.Open(filepath.Join(dir, "kb.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s := New(cfg, st)
	call := func(fn func(context.Context, json.RawMessage) (string, error), args map[string]any) (string, error) {
		b, _ := json.Marshal(args)
		return fn(context.Background(), b)
	}

	out, err := call(s.serviceInventory, map[string]any{"gaps_only": true})
	if err != nil || !strings.Contains(out, `"name": "redis-server"`) || !strings.Contains(out, `"health"`) {
		t.Fatalf("inventory: %v\n%s", err, out)
	}

	if _, err := call(s.coverageCase, map[string]any{"service": "redis-server", "summary": "x"}); err == nil {
		t.Fatal("a case without a summary must be refused")
	}
	if _, err := call(s.coverageCase, map[string]any{"service": "redis-server", "severity": "critical", "summary": "kodeblue cannot reach redis's port"}); err == nil {
		t.Fatal("critical is for intrusions")
	}
	out, err = call(s.coverageCase, map[string]any{"service": "redis-server", "summary": "kodeblue cannot reach redis's port from its namespace", "tried": "port monitor on 6379 failed"})
	if err != nil || !strings.Contains(out, "opened coverage case") {
		t.Fatalf("open: %v %s", err, out)
	}
	open := st.Incidents(`WHERE kind=? AND status='needs_human'`, services.Kind)
	if len(open) != 1 || !strings.Contains(open[0].Report, "port monitor on 6379 failed") || !strings.Contains(open[0].Report, "**health: missing**") {
		t.Fatalf("case: %+v", open)
	}
	out, _ = call(s.coverageCase, map[string]any{"service": "redis-server", "summary": "still cannot reach redis's port", "tried": "x"})
	if !strings.Contains(out, "already open") || len(st.Incidents(`WHERE kind=?`, services.Kind)) != 1 {
		t.Fatalf("second call must update the case: %s", out)
	}

	// The inventory shows the case; a monitor resolves it at the next sync.
	if out, _ := call(s.serviceInventory, nil); !strings.Contains(out, `"case": `) {
		t.Fatalf("inventory must show the open case:\n%s", out)
	}
	_ = st.PutMonitor("redis-up", []byte(`{"id":"redis-up","kind":"process","process_exe":"/usr/bin/redis-server"}`), "agent")
	if _, resolved := services.Sync(st, services.Take(s.env, st, cfg.RequestsDir())); len(resolved) != 1 {
		t.Fatalf("resolved: %+v", resolved)
	}
}

func TestVulnerabilityTools(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Server.StateDir = dir
	cfg.Server.Root = "/"
	st, err := store.Open(filepath.Join(dir, "kb.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s := New(cfg, st)
	call := func(fn func(context.Context, json.RawMessage) (string, error), args map[string]any) (string, error) {
		b, _ := json.Marshal(args)
		return fn(context.Background(), b)
	}
	key := filepath.Join(dir, "ctf.key")
	_ = os.WriteFile(key, []byte("mode-only"), 0o644)
	report := map[string]any{
		"id": "app-key-readable", "service": "host", "title": "The app's signing key is readable by everyone", "severity": "high", "category": "secret",
		"evidence": "ls -l " + key + ": -rw-r--r--", "remediation": "chmod 600 " + key + " and restart the app",
		"check": map[string]any{"kind": "command", "argv": []string{"ls", "-l", key}, "expect_match": "^-rw-------"},
	}
	out, err := call(s.vulnerabilityReport, report)
	if err != nil || !strings.Contains(out, "recorded vulnerability app-key-readable") || strings.Contains(out, "no service by that name") {
		t.Fatalf("report: %v %s", err, out)
	}
	report["service"] = "nginx"
	if out, _ := call(s.vulnerabilityReport, report); !strings.Contains(out, "updated") || !strings.Contains(out, "no service by that name") {
		t.Fatalf("an unknown service must be pointed out: %s", out)
	}
	if out, _ := call(s.vulnerabilityList, map[string]any{"status": "open"}); !strings.Contains(out, "1 vulnerabilities") {
		t.Fatalf("list: %s", out)
	}
	if _, err := call(s.vulnerabilityResolve, map[string]any{"id": "app-key-readable"}); err == nil {
		t.Fatal("still readable: resolve must be refused")
	}
	_ = os.Chmod(key, 0o600)
	if out, err := call(s.vulnerabilityResolve, map[string]any{"id": "app-key-readable"}); err != nil || !strings.Contains(out, "resolved") {
		t.Fatalf("resolve: %v %s", err, out)
	}
}
