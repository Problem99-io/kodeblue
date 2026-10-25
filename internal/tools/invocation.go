package tools

import "context"

// Invocation identifies one tool call for failure reporting: which run and
// model issued it and where it sat in a parallel batch.
type Invocation struct {
	ID         string
	ToolCallID string
	RunID      string
	BatchID    string
	BatchIndex int
	BatchSize  int
	Provider   string
	Model      string
}

type invocationKey struct{}

// WithInvocation attaches the call's identity to ctx.
func WithInvocation(ctx context.Context, i Invocation) context.Context {
	return context.WithValue(ctx, invocationKey{}, i)
}

// InvocationFromContext returns the identity attached by WithInvocation.
func InvocationFromContext(ctx context.Context) Invocation {
	i, _ := ctx.Value(invocationKey{}).(Invocation)
	return i
}
