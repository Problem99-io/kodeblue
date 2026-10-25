package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	internal "github.com/Problem99-io/kodeblue/internal"
)

func TestPathPolicyReadWithinRoot(t *testing.T) {
	root := t.TempDir()
	cfg := DefaultConfig()
	cfg.Paths.ProjectRoot = root
	pp, err := NewPathPolicy(cfg)
	if err != nil {
		t.Fatalf("NewPathPolicy: %v", err)
	}

	// Create a file inside root
	testFile := filepath.Join(root, "hello.txt")
	if err := os.WriteFile(testFile, []byte("hi"), 0o644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	if err := pp.CheckRead(testFile); err != nil {
		t.Errorf("read within root should pass: %v", err)
	}
}

func TestPathPolicyReadOutsideRoot(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	cfg := DefaultConfig()
	cfg.Paths.ProjectRoot = root
	pp, err := NewPathPolicy(cfg)
	if err != nil {
		t.Fatalf("NewPathPolicy: %v", err)
	}

	outsideFile := filepath.Join(outside, "secret.txt")
	if err := pp.CheckRead(outsideFile); err == nil {
		t.Error("read outside root should be denied")
	}
}

func TestPathPolicyWriteAllowed(t *testing.T) {
	root := t.TempDir()
	cfg := DefaultConfig()
	cfg.Paths.ProjectRoot = root
	cfg.Paths.AllowWritePaths = []string{"."}
	cfg.Paths.DenyPaths = nil
	pp, err := NewPathPolicy(cfg)
	if err != nil {
		t.Fatalf("NewPathPolicy: %v", err)
	}

	writePath := filepath.Join(root, "output.txt")
	if err := pp.CheckWrite(writePath); err != nil {
		t.Errorf("write to allowed path should pass: %v", err)
	}
}

func TestPathPolicyWriteDenied(t *testing.T) {
	root := t.TempDir()
	// Create .git dir
	gitDir := filepath.Join(root, ".git")
	if err := os.MkdirAll(gitDir, 0o755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}

	cfg := DefaultConfig()
	cfg.Paths.ProjectRoot = root
	cfg.Paths.AllowWritePaths = []string{"."}
	cfg.Paths.DenyPaths = []string{".git"}
	pp, err := NewPathPolicy(cfg)
	if err != nil {
		t.Fatalf("NewPathPolicy: %v", err)
	}

	deniedPath := filepath.Join(root, ".git", "config")
	if err := pp.CheckWrite(deniedPath); err == nil {
		t.Error("write to .git should be denied")
	}
}

func TestToolGuardIntegration(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig()
	cfg.Paths.ProjectRoot = root
	cfg.Paths.AllowWritePaths = []string{"."}
	cfg.Paths.DenyPaths = []string{".git"}

	am, err := NewToolGuard(cfg)
	if err != nil {
		t.Fatalf("NewToolGuard: %v", err)
	}

	// Enabled tool without restrictions should be allowed
	check, err := am.CheckToolExecution("read_file", jsonArgs(t, map[string]string{
		"path": filepath.Join(root, "test.txt"),
	}))
	if err != nil {
		t.Fatalf("CheckToolExecution read_file: %v", err)
	}
	if !check.Allowed {
		t.Errorf("read_file in root should be allowed, got denied: %s", check.DenyReason)
	}

	// Tools outside the path guard are allowed without inspecting arguments.
	for _, name := range []internal.ToolName{"run_shell", "some_unguarded_tool"} {
		check, err = am.CheckToolExecution(name, json.RawMessage(`{}`))
		if err != nil {
			t.Fatalf("CheckToolExecution %s: %v", name, err)
		}
		if !check.Allowed {
			t.Errorf("%s is not path-guarded and should be allowed, got denied: %s", name, check.DenyReason)
		}
	}

	// Write to .git should be denied
	check, err = am.CheckToolExecution("write_file", jsonArgs(t, map[string]string{
		"path": filepath.Join(root, ".git", "config"),
	}))
	if err != nil {
		t.Fatalf("CheckToolExecution write .git: %v", err)
	}
	if check.Allowed {
		t.Error("write to .git should be denied")
	}
}

func TestToolGuardUsesRunRootForRelativeAndDefaultReadPaths(t *testing.T) {
	projectRoot := t.TempDir()
	runRoot := filepath.Join(projectRoot, "task", "fixture")
	if err := os.MkdirAll(runRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := testConfig()
	cfg.Paths.ProjectRoot = projectRoot
	am, err := NewToolGuard(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name internal.ToolName
		args json.RawMessage
	}{
		{"read_file", jsonArgs(t, map[string]any{"path": "README.md"})},
		{"list_dir", jsonArgs(t, map[string]any{"path": "config"})},
	} {
		check, err := am.CheckToolExecutionAtRoot(tc.name, tc.args, runRoot)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if !check.Allowed {
			t.Errorf("%s should resolve inside run root: %s", tc.name, check.DenyReason)
		}
	}
	check, err := am.CheckToolExecutionAtRoot("read_file", jsonArgs(t, map[string]any{"path": filepath.Join(projectRoot, "outside.txt")}), runRoot)
	if err != nil {
		t.Fatal(err)
	}
	if check.Allowed {
		t.Fatal("absolute path outside the run root should be denied")
	}
}

func TestToolGuardValidatesBatchPaths(t *testing.T) {
	projectRoot := t.TempDir()
	runRoot := filepath.Join(projectRoot, "fixture")
	if err := os.MkdirAll(runRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := testConfig()
	cfg.Paths.ProjectRoot = projectRoot
	cfg.Paths.AllowWritePaths = []string{"."}
	am, err := NewToolGuard(cfg)
	if err != nil {
		t.Fatal(err)
	}
	allowed := []struct {
		name internal.ToolName
		args map[string]any
	}{
		{"read_file", map[string]any{"reads": []map[string]any{{"path": "a.txt"}, {"path": "b.txt"}}}},
		{"write_file", map[string]any{"writes": []map[string]any{{"path": "a.txt", "content": "a"}, {"path": "b.txt", "content": "b"}}}},
		{"write_file", map[string]any{"path": "nested/c.txt", "content": "c"}},
	}
	for _, tc := range allowed {
		check, err := am.CheckToolExecutionAtRoot(tc.name, jsonArgs(t, tc.args), runRoot)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if !check.Allowed {
			t.Errorf("%s batch should be allowed: %s", tc.name, check.DenyReason)
		}
	}
	check, err := am.CheckToolExecutionAtRoot("read_file", jsonArgs(t, map[string]any{"reads": []map[string]any{{"path": "ok.txt"}, {"path": "../escape.txt"}}}), runRoot)
	if err != nil {
		t.Fatal(err)
	}
	if check.Allowed {
		t.Fatal("batch containing an escaping path should be denied")
	}
	check, err = am.CheckToolExecutionAtRoot("write_file", jsonArgs(t, map[string]any{"writes": []map[string]any{{"path": "ok.txt", "content": "a"}, {"path": "../escape.txt", "content": "b"}}}), runRoot)
	if err != nil {
		t.Fatal(err)
	}
	if check.Allowed {
		t.Fatal("write batch containing an escaping path should be denied")
	}
}

// testConfig returns the default policy config.
func testConfig() *Config {
	return DefaultConfig()
}

func jsonArgs(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json marshal: %v", err)
	}
	return json.RawMessage(b)
}
