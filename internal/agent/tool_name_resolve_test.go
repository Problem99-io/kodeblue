package agent

import (
	"testing"

	internal "github.com/Problem99-io/kodeblue/internal"
)

func TestQualifyBareToolNames(t *testing.T) {
	defs := []internal.ToolDefinition{
		{Name: "mcp__kodeblue__host_exec"},
		{Name: "mcp__kodeblue__stats"},
		{Name: "mcp__kodeblue__status"},
		{Name: "mcp__other__status"},
		{Name: "read_file"},
		{Name: "mcp__kodeblue__read_file"},
		{Name: "patch_definition"},
	}
	calls := []internal.ToolCall{
		{ID: "1", Name: "host_exec"},
		{ID: "2", Name: "stats"},
		{ID: "3", Name: "mcp__kodeblue__host_exec"},
		{ID: "4", Name: "status"},    // two servers have it: ambiguous
		{ID: "5", Name: "read_file"}, // a tool in its own right
		{ID: "6", Name: "nonexistent"},
		{ID: "7", Name: "mcp__kodeblue__read_file"}, // a real MCP tool: unchanged
		{ID: "8", Name: "mcp__kodeblue__patch_definition"},
		{ID: "9", Name: "mcp__kodeblue__nope"},
	}
	want := []internal.ToolName{
		"mcp__kodeblue__host_exec",
		"mcp__kodeblue__stats",
		"mcp__kodeblue__host_exec",
		"status",
		"read_file",
		"nonexistent",
		"mcp__kodeblue__read_file",
		"patch_definition",
		"mcp__kodeblue__nope",
	}
	got := qualifyBareToolNames(calls, defs)
	for i, w := range want {
		if got[i].Name != w {
			t.Errorf("call %s: name %q, want %q", got[i].ID, got[i].Name, w)
		}
	}
}
