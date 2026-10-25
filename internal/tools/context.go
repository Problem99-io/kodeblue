package tools

import (
	"context"

	internal "github.com/Problem99-io/kodeblue/internal"
)

type execContextKey string

const (
	execSessionIDKey        execContextKey = "tools.session_id"
	execRunIDKey            execContextKey = "tools.run_id"
	execSessionCWD          execContextKey = "tools.session_cwd"
	execSessionInstructions execContextKey = "tools.session_instructions"
	execAllowedTools        execContextKey = "tools.allowed_tools"
)

// WithExecutionContext attaches session/run IDs for tool execution.
func WithExecutionContext(ctx context.Context, sessionID internal.SessionID, runID internal.RunID) context.Context {
	ctx = context.WithValue(ctx, execSessionIDKey, sessionID)
	ctx = context.WithValue(ctx, execRunIDKey, runID)
	return ctx
}

// WithSessionCWD attaches a per-session working directory override to the context.
// When set, tools use this directory as their project root instead of the global one.
func WithSessionCWD(ctx context.Context, cwd string) context.Context {
	return context.WithValue(ctx, execSessionCWD, cwd)
}

// WithSessionInstructions attaches session-scoped instructions to the tool context.
func WithSessionInstructions(ctx context.Context, instructions []string) context.Context {
	return context.WithValue(ctx, execSessionInstructions, instructions)
}

// WithAllowedTools attaches the set of tool names the current run is permitted
// to invoke. Keys must be canonical (see internal.CanonicalToolNameString). A
// nil set means "no restriction" — every enabled tool is allowed. This is the
// authoritative per-run allowlist; the registry refuses any other tool.
func WithAllowedTools(ctx context.Context, allowed map[string]bool) context.Context {
	return context.WithValue(ctx, execAllowedTools, allowed)
}

// AllowedToolsFromContext returns the per-run allowed-tool set and whether a
// restriction is in force. ok=false means no restriction (allow all).
func AllowedToolsFromContext(ctx context.Context) (map[string]bool, bool) {
	allowed, ok := ctx.Value(execAllowedTools).(map[string]bool)
	if !ok || allowed == nil {
		return nil, false
	}
	return allowed, true
}

// SessionCWDFromContext extracts the per-session working directory from context.
// Returns empty string if not set.
func SessionCWDFromContext(ctx context.Context) string {
	cwd, _ := ctx.Value(execSessionCWD).(string)
	return cwd
}

// ExecutionContextFromContext extracts session/run IDs from context.
func ExecutionContextFromContext(ctx context.Context) (internal.SessionID, internal.RunID, bool) {
	sessionID, ok1 := ctx.Value(execSessionIDKey).(internal.SessionID)
	runID, ok2 := ctx.Value(execRunIDKey).(internal.RunID)
	if !ok1 || !ok2 {
		return "", "", false
	}
	return sessionID, runID, true
}
