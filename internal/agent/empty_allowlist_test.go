package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	internal "github.com/Problem99-io/kodeblue/internal"
	"github.com/Problem99-io/kodeblue/internal/provider"
	"github.com/Problem99-io/kodeblue/internal/tools"
)

// An agent whose allowlist matched no registered tool (say it named a tool
// that was later removed) gets an empty, non-nil tool list. That must allow
// nothing, not fall back to every registered tool.
func TestEmptyToolListAllowsNoTool(t *testing.T) {
	if runAllowedToolSet(nil) != nil {
		t.Fatal("nil tool list must mean no restriction")
	}
	if allowed := runAllowedToolSet([]internal.ToolDefinition{}); allowed == nil || len(allowed) != 0 {
		t.Fatalf("empty tool list = %#v, want an empty restriction", allowed)
	}

	root := t.TempDir()
	reg := tools.NewRegistry()
	reg.Register(tools.NewWriteFile(tools.ToolConfig{ProjectRoot: root}))
	ec := &eventCollector{}
	mp := newMockProvider([][]provider.StreamEvent{
		toolCallResponse("tc_write", "write_file", `{"path":"pwned.txt","content":"x"}`),
		simpleTextResponse("done"),
	})
	loop := NewLoop(reg, newAllowAllToolGuard(), nil, ec.sink)
	cfg := buildRunConfig(mp, []internal.ToolDefinition{})
	cfg.BaseDirectory = root
	if _, err := loop.Run(context.Background(), cfg, "go", nil); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "pwned.txt")); !os.IsNotExist(err) {
		t.Fatalf("write_file ran for an agent allowed no tools (stat err=%v)", err)
	}
	if len(mp.requests) == 0 || len(mp.requests[0].Tools) != 0 {
		t.Fatalf("model was offered tools: %#v", mp.requests)
	}
}
