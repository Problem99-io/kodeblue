package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	internal "github.com/Problem99-io/kodeblue/internal"
	"github.com/Problem99-io/kodeblue/internal/tools"
)

// toolBatch is one assistant turn's tool calls. They share a batch id (the
// assistant message id) so clients can recognize parallel calls.
type toolBatch struct {
	id    string
	calls []internal.ToolCall
	// allowed is the run's authoritative tool allowlist (nil = no
	// restriction). It is enforced here and passed to the tool context.
	allowed map[string]bool
	// parallel is set when every call is a local read-only operation that
	// passed the policy preflight; such turns run with bounded
	// parallelism. Every other turn runs in order to preserve side effects.
	parallel *parallelTools
	results  []internal.ToolResult
	// attachments are transient images from tool results, forwarded to the
	// next model request.
	attachments []internal.Attachment
}

type parallelTools struct {
	width   int
	results []parallelToolExecution
	workers sync.WaitGroup
	slots   chan struct{}
}

type parallelToolExecution struct {
	result     *tools.Result
	durationMS int64
}

// withMode adds the parallel execution fields to an event payload.
func (b *toolBatch) withMode(payload map[string]any) map[string]any {
	if b.parallel != nil {
		payload["execution_mode"] = "parallel_read_only"
		payload["parallel_width"] = b.parallel.width
	}
	return payload
}

// runToolTurn executes the tool calls of one assistant turn and appends their
// results to the history as one user message.
func (l *Loop) runToolTurn(ctx context.Context, s *runState, batchID string, calls []internal.ToolCall) *runEnd {
	cfg := s.cfg
	b := &toolBatch{id: batchID, calls: calls, allowed: runAllowedToolSet(cfg.Tools)}
	s.toolCallsExecuted += len(calls)
	if l.canExecuteReadOnlyTurnInParallel(cfg, calls, b.allowed) {
		width := min(len(calls), MaxParallelReadOnlyTools)
		b.parallel = &parallelTools{width: width, results: make([]parallelToolExecution, len(calls)), slots: make(chan struct{}, width)}
	}

	// From here until all requested tools have settled, Interrupt must not
	// cancel the run context. It records a steer request, and the run stops at
	// the post-tool, pre-provider boundary.
	l.beginTool(cfg.RunID)
	for i, tc := range calls {
		requested := map[string]any{
			"tool_call_id":   tc.ID,
			"tool_name":      string(tc.Name),
			"arguments":      string(tc.Arguments),
			"batch_id":       batchID,
			"batch_index":    i,
			"batch_size":     len(calls),
			"execution_mode": "sequential",
			"parallel_width": 1,
		}
		l.emitEvent(cfg, internal.EventToolRequested, b.withMode(requested))

		if !l.gateToolCall(s, b, i) {
			continue
		}
		if b.parallel != nil {
			l.startParallelTool(ctx, cfg, b, i)
			continue
		}
		if end := l.runSequentialTool(ctx, s, b, i); end != nil {
			return end
		}
	}
	if b.parallel != nil {
		if end := l.finishParallelTools(ctx, s, b); end != nil {
			return end
		}
	}
	l.endTool(cfg.RunID)

	s.appendMessage(internal.Message{
		ID:          internal.NewMessageID(),
		Role:        "user",
		ToolResults: b.results,
		Attachments: b.attachments,
		CreatedAt:   time.Now(),
	})
	return nil
}

// gateToolCall applies the run's allowlist and the tool policy. A refused call
// gets an error result and allowed=false.
func (l *Loop) gateToolCall(s *runState, b *toolBatch, i int) bool {
	cfg := s.cfg
	tc := b.calls[i]
	deny := func(reason string) bool {
		b.results = append(b.results, internal.ToolResult{ToolCallID: tc.ID, Content: reason, IsError: true})
		l.emitToolFailed(cfg, tc, reason, b.id, i, len(b.calls))
		return false
	}

	// The model is only shown the allowed tools, but a hallucinated or stale
	// tool name must still be refused here rather than dispatched against the
	// global registry.
	if b.allowed != nil && !b.allowed[string(internal.CanonicalToolName(tc.Name))] {
		return deny(fmt.Sprintf("tool denied: %q is not available to this agent", tc.Name))
	}
	if malformedToolArguments(tc.Arguments) {
		return deny("tool arguments were not valid JSON (the call was probably cut off); issue the call again with complete arguments")
	}
	check, err := l.toolGuard.CheckToolExecutionAtRoot(tc.Name, tc.Arguments, cfg.BaseDirectory)
	if err != nil {
		return deny(fmt.Sprintf("policy error: %v", err))
	}
	if !check.Allowed {
		return deny(fmt.Sprintf("tool denied: %s", check.DenyReason))
	}
	return true
}

// toolContext carries the run's identity, instructions, allowlist and working
// directory to a tool.
func (l *Loop) toolContext(ctx context.Context, cfg RunConfig, b *toolBatch, i int) context.Context {
	toolCtx := tools.WithExecutionContext(ctx, cfg.SessionID, cfg.RunID)
	toolCtx = tools.WithInvocation(toolCtx, toolInvocation(cfg, b.calls[i].ID, b.id, i, len(b.calls)))
	toolCtx = tools.WithSessionInstructions(toolCtx, cfg.Instructions)
	toolCtx = tools.WithAllowedTools(toolCtx, b.allowed)
	// Set the working directory for file and shell tools from this run's
	// BaseDirectory, so resolution does not depend on how the run started.
	if cfg.BaseDirectory != "" {
		toolCtx = tools.WithSessionCWD(toolCtx, cfg.BaseDirectory)
	}
	return toolCtx
}

func (l *Loop) executeTool(ctx context.Context, cfg RunConfig, b *toolBatch, i int) (*tools.Result, int64) {
	started := time.Now()
	tc := b.calls[i]
	result, err := l.toolRegistry.Execute(l.toolContext(ctx, cfg, b, i), tc.Name, tc.Arguments)
	if err != nil {
		result = &tools.Result{Content: fmt.Sprintf("execution error: %v", err), IsError: true}
	}
	return result, time.Since(started).Milliseconds()
}

func (l *Loop) emitToolStarted(cfg RunConfig, b *toolBatch, i int) {
	tc := b.calls[i]
	l.emitEvent(cfg, internal.EventToolStarted, b.withMode(map[string]any{
		"tool_call_id": tc.ID,
		"tool_name":    string(tc.Name),
		"batch_id":     b.id,
		"batch_index":  i,
		"batch_size":   len(b.calls),
	}))
}

// recordToolResult emits a finished tool's output and terminal events, and
// adds its result to the batch.
func (l *Loop) recordToolResult(cfg RunConfig, b *toolBatch, i int, result *tools.Result, durationMS int64) {
	tc := b.calls[i]
	output := map[string]any{
		"tool_name":    string(tc.Name),
		"tool_call_id": tc.ID,
		"content":      result.Content,
		"is_error":     result.IsError,
		"batch_id":     b.id,
		"batch_index":  i,
		"batch_size":   len(b.calls),
		"duration_ms":  durationMS,
	}
	if len(result.Metadata) > 0 {
		output["metadata"] = result.Metadata
	}
	l.emitEvent(cfg, internal.EventToolOutput, b.withMode(output))
	if result.IsError {
		l.emitToolExecutionFinished(cfg, tc, "error", "execution", "tool_result_error", "", true, b.id, i, len(b.calls), durationMS)
	} else {
		l.emitToolExecutionFinished(cfg, tc, "success", "execution", "", "", false, b.id, i, len(b.calls), durationMS)
	}
	b.results = append(b.results, internal.ToolResult{
		ToolCallID: tc.ID,
		Content:    result.Content,
		IsError:    result.IsError,
		Metadata:   result.Metadata,
	})
	b.attachments = append(b.attachments, result.Attachments...)
}

func (l *Loop) runSequentialTool(ctx context.Context, s *runState, b *toolBatch, i int) *runEnd {
	cfg := s.cfg
	tc := b.calls[i]
	l.emitToolStarted(cfg, b, i)
	result, durationMS := l.executeTool(ctx, cfg, b, i)

	if ctx.Err() != nil {
		l.emitToolExecutionFinished(cfg, tc, "error", "execution", "cancelled", "", true, b.id, i, len(b.calls), durationMS)
		l.emitPendingToolFailures(cfg, b.calls[i+1:], "tool execution aborted", b.id, i+1, len(b.calls))
		b.results = append(b.results, internal.ToolResult{
			ToolCallID: tc.ID,
			Content:    result.Content,
			IsError:    result.IsError,
			Metadata:   result.Metadata,
		})
		b.results = completePendingToolResults(b.calls, b.results, "tool execution aborted")
		s.messages = appendToolResultsMessage(s.messages, b.results)
		return l.endAborted(s)
	}
	l.recordToolResult(cfg, b, i, result, durationMS)
	return nil
}

func (l *Loop) startParallelTool(ctx context.Context, cfg RunConfig, b *toolBatch, i int) {
	l.emitToolStarted(cfg, b, i)
	p := b.parallel
	started := time.Now()
	p.workers.Add(1)
	go func() {
		defer p.workers.Done()
		select {
		case p.slots <- struct{}{}:
		case <-ctx.Done():
			p.results[i] = parallelToolExecution{
				result:     &tools.Result{Content: "tool execution aborted", IsError: true},
				durationMS: time.Since(started).Milliseconds(),
			}
			return
		}
		defer func() { <-p.slots }()
		result, _ := l.executeTool(ctx, cfg, b, i)
		p.results[i] = parallelToolExecution{result: result, durationMS: time.Since(started).Milliseconds()}
	}()
}

// finishParallelTools waits for a parallel turn and records its results in
// the order the model requested them, whatever order they finished in, so the
// transcript and events stay deterministic.
func (l *Loop) finishParallelTools(ctx context.Context, s *runState, b *toolBatch) *runEnd {
	cfg := s.cfg
	p := b.parallel
	p.workers.Wait()
	if ctx.Err() != nil {
		for i, tc := range b.calls {
			l.emitToolExecutionFinished(cfg, tc, "error", "execution", "cancelled", "", true, b.id, i, len(b.calls), p.results[i].durationMS)
			b.results = append(b.results, internal.ToolResult{ToolCallID: tc.ID, Content: "tool execution aborted", IsError: true})
		}
		s.messages = appendToolResultsMessage(s.messages, b.results)
		return l.endAborted(s)
	}
	for i := range b.calls {
		execution := p.results[i]
		result := execution.result
		if result == nil {
			result = &tools.Result{Content: "execution error: parallel worker returned no result", IsError: true}
		}
		l.recordToolResult(cfg, b, i, result, execution.durationMS)
	}
	return nil
}

// continuationCheckpoint asks whether to keep going every MaxIterations
// turns. The tool turn is finished and its results are in the transcript,
// but nothing has been sent to the model yet, so the run can be held here
// without leaving a tool call unanswered.
func (l *Loop) continuationCheckpoint(ctx context.Context, s *runState, iteration int) *runEnd {
	cfg := s.cfg
	if l.continuationGate == nil || cfg.MaxIterations <= 0 || (iteration+1)%cfg.MaxIterations != 0 {
		return nil
	}
	if cfg.SaveCheckpoint != nil {
		if err := cfg.SaveCheckpoint(s.messages); err != nil {
			return l.endFailed(s, map[string]any{"reason": "failed to persist continuation checkpoint"}, fmt.Errorf("persist continuation checkpoint: %w", err))
		}
	}
	decision, err := l.continuationGate(ctx, ContinuationRequest{
		SessionID:  cfg.SessionID,
		RunID:      cfg.RunID,
		Iterations: iteration + 1,
		ToolCalls:  s.toolCallsExecuted,
	})
	if err != nil {
		if ctx.Err() != nil || errors.Is(err, context.Canceled) {
			return l.endAborted(s)
		}
		return l.endFailed(s, map[string]any{"reason": "continuation gate failed: " + err.Error()}, fmt.Errorf("continuation gate: %w", err))
	}
	if !decision.Continue {
		l.emitEvent(cfg, internal.EventRunAborted, map[string]any{
			"reason":     "stopped by user at continuation checkpoint",
			"iterations": iteration + 1,
		})
		return &runEnd{result: s.result(), err: ErrAborted}
	}

	// Free text typed instead of a plain yes rides along with the held tool
	// results as an ordinary user message.
	if guidance := strings.TrimSpace(decision.Guidance); guidance != "" {
		msg := internal.Message{ID: internal.NewMessageID(), Role: "user", Content: guidance, CreatedAt: time.Now()}
		s.appendMessage(msg)
		l.emitEvent(cfg, internal.EventMessageStarted, map[string]any{"message_id": msg.ID, "content": guidance})
	}
	return nil
}
