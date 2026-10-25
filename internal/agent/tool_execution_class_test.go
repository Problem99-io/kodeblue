package agent

import (
	"testing"

	internal "github.com/Problem99-io/kodeblue/internal"
)

func TestToolExecutionClassOnlyAllowsPureLocalReads(t *testing.T) {
	readOnly := []internal.ToolName{"read_file", "list_dir", "grep", "grep_search"}
	for _, name := range readOnly {
		if !IsParallelReadOnlyTool(name) {
			t.Fatalf("%s must be eligible for read-only parallel execution", name)
		}
	}

	sequential := []internal.ToolName{
		"write_file", "edit_file", "run_shell", "fetch_webpage", "web_search",
		"git_helpers", "git_push", "git_create_pr", "ask_user",
		"file_search", "scheduled_tasks", "mcp/untrusted",
	}
	for _, name := range sequential {
		if IsParallelReadOnlyTool(name) {
			t.Fatalf("%s must remain sequential", name)
		}
	}
}

func TestParallelReadOnlyBatchWidthRequiresHomogeneousTurn(t *testing.T) {
	reads := []internal.ToolCall{
		{Name: "read_file"}, {Name: "grep"}, {Name: "list_dir"}, {Name: "grep_search"}, {Name: "read_file"},
	}
	if got := ParallelReadOnlyBatchWidth(reads); got != MaxParallelReadOnlyTools {
		t.Fatalf("parallel width = %d, want bounded %d", got, MaxParallelReadOnlyTools)
	}
	if got := ParallelReadOnlyBatchWidth([]internal.ToolCall{{Name: "read_file"}, {Name: "write_file"}}); got != 0 {
		t.Fatalf("mixed side-effecting turn must stay sequential, got width %d", got)
	}
	if got := ParallelReadOnlyBatchWidth([]internal.ToolCall{{Name: "read_file"}}); got != 0 {
		t.Fatalf("single call is not a parallel batch, got width %d", got)
	}
}
