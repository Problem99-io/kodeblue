package main

import (
	"testing"

	internal "github.com/Problem99-io/kodeblue/internal"
)

func TestToolsForAgentAppliesAgentAllowlist(t *testing.T) {
	all := []internal.ToolDefinition{{Name: "read_file"}, {Name: "write_file"}}
	selected, unknown := toolsForAgent(all, &internal.AgentDefinition{Tools: []string{"read_file"}})
	if len(selected) != 1 || selected[0].Name != "read_file" || len(unknown) != 0 {
		t.Fatalf("allowlisted tools = %#v, unknown = %v", selected, unknown)
	}
	if unrestricted, _ := toolsForAgent(all, nil); len(unrestricted) != 2 {
		t.Fatalf("tools without allowlist = %#v", unrestricted)
	}
}

// An agent stored before a tool was removed, whose allowlist names only that
// tool, must end up with no tools: a non-nil empty list, which the loop reads
// as "allow nothing". nil would mean every registered tool.
func TestToolsForAgentWithOnlyUnknownToolsAllowsNothing(t *testing.T) {
	all := []internal.ToolDefinition{{Name: "read_file"}, {Name: "write_file"}}
	selected, unknown := toolsForAgent(all, &internal.AgentDefinition{Name: "old", Tools: []string{"grep"}})
	if selected == nil || len(selected) != 0 {
		t.Fatalf("selected = %#v, want an empty non-nil list", selected)
	}
	if len(unknown) != 1 || unknown[0] != "grep" {
		t.Fatalf("unknown = %v, want [grep]", unknown)
	}
}
