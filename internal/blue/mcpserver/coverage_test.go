package mcpserver

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Problem99-io/kodeblue/internal/blue/config"
	"github.com/Problem99-io/kodeblue/internal/blue/sensors"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

func TestSensorDisableOnlyWhenBlindAndReplaced(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "host")
	other := filepath.Join(dir, "container")
	_ = os.MkdirAll(other, 0o755)
	// One workload process, on a filesystem kodeblue does not read.
	p := filepath.Join(root, "proc", "10")
	_ = os.MkdirAll(filepath.Join(p, "fd"), 0o755)
	_ = os.Symlink("/usr/bin/node", filepath.Join(p, "exe"))
	_ = os.Symlink(other, filepath.Join(p, "root"))
	_ = os.WriteFile(filepath.Join(p, "cmdline"), []byte("node"), 0o644)
	_ = os.WriteFile(filepath.Join(p, "status"), []byte("State:\tS\nPPid:\t0\nUid:\t0\n"), 0o644)

	cfg := config.Default()
	cfg.Server.StateDir = dir
	cfg.Server.Root = root
	st, err := store.Open(filepath.Join(dir, "kb.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s := New(cfg, st)
	call := func(args map[string]any) (string, error) {
		b, _ := json.Marshal(args)
		return s.sensorDisable(context.Background(), b)
	}

	if _, err := call(map[string]any{"collector": "tmp_exec", "reason": "reads kodeblue's own /tmp"}); err == nil || !strings.Contains(err.Error(), "replaced_by is required") {
		t.Fatalf("no replacement: %v", err)
	}
	if _, err := call(map[string]any{"collector": "tmp_exec", "reason": "x", "replaced_by": []string{"app-tmp"}}); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("missing monitor: %v", err)
	}
	_ = st.PutMonitor("app-tmp", []byte(`{"id":"app-tmp","kind":"file"}`), "agent")
	if _, err := call(map[string]any{"collector": "tmp_exec", "reason": "x", "replaced_by": []string{"app-tmp"}}); err != nil {
		t.Fatal(err)
	}
	if _, ok := sensors.ParseDisabled(st.Get(sensors.DisabledKey))["tmp_exec"]; !ok {
		t.Fatal("tmp_exec not recorded as off")
	}
	// Some models flatten an array argument into a string.
	if _, err := call(map[string]any{"collector": "suid", "reason": "x", "replaced_by": "app-tmp, "}); err != nil {
		t.Fatalf("comma-separated replaced_by: %v", err)
	}
	if d := sensors.ParseDisabled(st.Get(sensors.DisabledKey))["suid"]; len(d.ReplacedBy) != 1 || d.ReplacedBy[0] != "app-tmp" {
		t.Fatalf("suid replaced_by = %v", d.ReplacedBy)
	}
	// cpu_hog still sees the processes, so it stays on.
	if _, err := call(map[string]any{"collector": "cpu_hog", "reason": "x", "replaced_by": []string{"app-tmp"}}); err == nil || !strings.Contains(err.Error(), "not blind") {
		t.Fatalf("a sensor that sees the server must stay on: %v", err)
	}
	if out, err := s.sensorEnable(context.Background(), json.RawMessage(`{"collector":"tmp_exec"}`)); err != nil || !strings.Contains(out, "on from the next sweep") {
		t.Fatalf("enable: %q %v", out, err)
	}
}
