package agent

import (
	internal "github.com/Problem99-io/kodeblue/internal"
)

// ToolExecutionClass states whether a model-issued tool call can safely share
// a turn with other calls. This is deliberately an allowlist: a new tool is
// sequential until its side effects and shared-state behavior have been
// reviewed. In particular, MCP tools must never be made
// parallel merely because they happen to look read-like.
type ToolExecutionClass string

const (
	ToolExecutionSequential   ToolExecutionClass = "sequential"
	ToolExecutionReadOnlySafe ToolExecutionClass = "read_only_safe"

	// MaxParallelReadOnlyTools bounds concurrent filesystem/search calls in one
	// model turn. It prevents a single response from creating unbounded disk I/O
	// or goroutine fan-out while still letting independent discovery work overlap.
	MaxParallelReadOnlyTools = 4
)

// ToolExecutionClassFor returns the execution contract for a registered tool.
// Only pure local filesystem/search reads are eligible for concurrent execution.
func ToolExecutionClassFor(name internal.ToolName) ToolExecutionClass {
	switch internal.CanonicalToolName(name) {
	case "read_file", "list_dir", "grep":
		return ToolExecutionReadOnlySafe
	default:
		return ToolExecutionSequential
	}
}

// IsParallelReadOnlyTool reports whether the tool can execute alongside other
// calls in the same model turn without changing program-observable state.
func IsParallelReadOnlyTool(name internal.ToolName) bool {
	return ToolExecutionClassFor(name) == ToolExecutionReadOnlySafe
}

// ParallelReadOnlyBatchWidth returns the number of calls that may be run in a
// bounded concurrent phase. A value below two means the caller should preserve
// ordinary sequential execution.
func ParallelReadOnlyBatchWidth(calls []internal.ToolCall) int {
	if len(calls) < 2 {
		return 0
	}
	for _, call := range calls {
		if !IsParallelReadOnlyTool(call.Name) {
			return 0
		}
	}
	return min(len(calls), MaxParallelReadOnlyTools)
}

// canExecuteReadOnlyTurnInParallel performs a side-effect-free preflight before
// any tool starts. The normal execution path repeats the policy check, but this
// preflight ensures we never launch a subset concurrently and then encounter a
// denial or malformed argument half way through the turn.
func (l *Loop) canExecuteReadOnlyTurnInParallel(cfg RunConfig, calls []internal.ToolCall, allowedTools map[string]bool) bool {
	if ParallelReadOnlyBatchWidth(calls) == 0 || l == nil || l.toolGuard == nil {
		return false
	}
	for _, call := range calls {
		if allowedTools != nil && !allowedTools[string(internal.CanonicalToolName(call.Name))] {
			return false
		}
		check, err := l.toolGuard.CheckToolExecutionAtRoot(call.Name, call.Arguments, cfg.BaseDirectory)
		if err != nil || !check.Allowed {
			return false
		}
	}
	return true
}
