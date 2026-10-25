package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"time"

	internal "github.com/Problem99-io/kodeblue/internal"
	"github.com/Problem99-io/kodeblue/internal/provider"
)

// runState is the mutable state of one Run, shared by the turn helpers.
type runState struct {
	cfg           RunConfig
	messages      []internal.Message
	compacted     bool
	usage         provider.Usage
	contextWindow int64
	systemPrompt  string
	// inputTokens is the current prompt size used for compaction decisions:
	// the provider's reported figure after each turn, plus estimates for
	// messages appended since.
	inputTokens int64
	// toolCallsExecuted is reported at continuation checkpoints so the "keep
	// going?" question can say how much work the run has already done.
	toolCallsExecuted int
	// emptyTurns counts replies in a row with no text and no tool call.
	emptyTurns int
}

func (s *runState) result() RunResult {
	return RunResult{Messages: s.messages, Compacted: s.compacted, Usage: s.usage}
}

func (s *runState) appendMessage(m internal.Message) {
	s.messages = append(s.messages, m)
	s.inputTokens += estimateMessageTokens(m)
}

// runEnd is how a run finished, when a turn helper ends it. A nil *runEnd
// means the run continues.
type runEnd struct {
	result RunResult
	err    error
}

func (e *runEnd) values() (RunResult, error) { return e.result, e.err }

func (l *Loop) endAborted(s *runState) *runEnd {
	l.emitEvent(s.cfg, internal.EventRunAborted, map[string]any{"reason": "run aborted"})
	return &runEnd{result: s.result(), err: ErrAborted}
}

func (l *Loop) endInterrupted(s *runState, content, reasoning string, reasoningDetails json.RawMessage) *runEnd {
	result, err := l.interruptedResult(s.cfg, s.messages, s.compacted, s.usage, content, reasoning, reasoningDetails)
	return &runEnd{result: result, err: err}
}

func (l *Loop) endFailed(s *runState, fields map[string]any, err error) *runEnd {
	l.emitEvent(s.cfg, internal.EventRunFailed, fields)
	return &runEnd{result: s.result(), err: err}
}

// startRun builds the run's history (repaired persisted messages plus the new
// user turn) and resolves the context window and system prompt.
func (l *Loop) startRun(ctx context.Context, s *runState, userMessage string, attachments []internal.Attachment) {
	cfg := s.cfg
	s.messages = make([]internal.Message, len(cfg.Messages))
	copy(s.messages, cfg.Messages)
	s.messages, _ = repairDanglingToolCallHistory(s.messages)

	userMessageID := cfg.UserMessageID
	if userMessageID == "" {
		userMessageID = internal.NewMessageID()
	}
	userMessageCreatedAt := cfg.UserMessageCreatedAt
	if userMessageCreatedAt.IsZero() {
		userMessageCreatedAt = time.Now()
	}
	s.messages = append(s.messages, internal.Message{
		ID:          userMessageID,
		Role:        "user",
		Content:     userMessage,
		Attachments: attachments,
		CreatedAt:   userMessageCreatedAt,
	})
	l.emitEvent(cfg, internal.EventMessageStarted, map[string]any{
		"message_id": userMessageID,
		"content":    userMessage,
	})

	s.contextWindow = provider.ResolveContextWindow(ctx, cfg.Provider, cfg.ModelName)
	if cfg.TokenBudget > 0 && cfg.TokenBudget < s.contextWindow {
		s.contextWindow = cfg.TokenBudget
	}
	s.systemPrompt = l.buildSystemPromptAt(cfg, promptNow().UTC())
	s.inputTokens = estimateRequestInputTokens(s.messages, cfg.Tools, s.systemPrompt)
}

// compactIfNeeded compacts the history when the prompt has reached the
// compaction threshold. A failed compaction is logged and the run goes on
// with the full history. afterTools marks the check that follows a tool
// turn (reported as an automatic compaction).
func (l *Loop) compactIfNeeded(ctx context.Context, s *runState, afterTools bool) {
	if l.compactor == nil || s.inputTokens <= 0 || !l.compactor.NeedsCompaction(s.inputTokens, s.contextWindow) {
		return
	}
	cfg := s.cfg
	slog.Info("compacting context", "run_id", cfg.RunID, "input_tokens", s.inputTokens, "context_window", s.contextWindow)
	// Messages produced in this run exist only in memory until a checkpoint.
	// Persist them before they are summarized away, so the full history keeps
	// the raw messages and only marks them compacted.
	if cfg.SaveCheckpoint != nil {
		if err := cfg.SaveCheckpoint(s.messages); err != nil {
			slog.Warn("checkpoint before compaction failed", "run_id", cfg.RunID, "error", err)
		}
	}
	compacted, err := l.compactor.Compact(ctx, cfg.Provider, cfg.SessionID, cfg.RunID, s.messages, CompactOptions{
		ActiveModel:    cfg.ModelName,
		ContextWindow:  s.contextWindow,
		Automatic:      afterTools,
		SystemPrompt:   s.systemPrompt,
		Tools:          cfg.Tools,
		PromptCacheKey: promptCacheKey(cfg),
	})
	if err != nil {
		slog.Warn("compaction failed", "run_id", cfg.RunID, "error", err)
		return
	}
	if !reflect.DeepEqual(s.messages, compacted) {
		s.messages = compacted
		s.compacted = true
		s.inputTokens = estimateRequestInputTokens(s.messages, cfg.Tools, s.systemPrompt)
	}
}

// modelTurn is one streamed model response.
type modelTurn struct {
	content          string
	reasoning        string
	reasoningDetails json.RawMessage
	toolCalls        []internal.ToolCall
	usage            provider.Usage
	usageDetails     *internal.MessageUsage
}

func (t *modelTurn) assistantMessage() internal.Message {
	return internal.Message{
		ID:               internal.NewMessageID(),
		Role:             "assistant",
		Content:          t.content,
		ReasoningContent: t.reasoning,
		ReasoningDetails: t.reasoningDetails,
		ToolCalls:        t.toolCalls,
		Usage:            t.usageDetails,
		CreatedAt:        time.Now(),
	}
}

// streamModelTurn sends the history to the provider and collects the streamed
// response, emitting token and tool-call events as they arrive.
func (l *Loop) streamModelTurn(ctx context.Context, s *runState) (modelTurn, *runEnd) {
	cfg := s.cfg
	streamCtx, cancelStream := context.WithCancel(ctx)
	l.beginProvider(cfg.RunID, cancelStream)
	maxOutputTokens := cfg.MaxOutputTokens
	if maxOutputTokens == 0 {
		maxOutputTokens = 32768
	} else if maxOutputTokens < 0 {
		maxOutputTokens = 0
	}
	// Input plus max_tokens must fit the model's window, or the request is
	// rejected outright: cap the output to what is left, with a fifth of the
	// window as margin (the local estimate runs low next to some vendors'
	// tokenizers, tool schemas especially).
	if maxOutputTokens > 0 && s.contextWindow > 0 {
		room := s.contextWindow - s.inputTokens - s.contextWindow/5
		if room < 1024 {
			room = 1024
		}
		if int64(maxOutputTokens) > room {
			maxOutputTokens = int(room)
		}
	}
	streamCh, err := provider.StreamWithRecovery(streamCtx, cfg.Provider, &provider.Request{
		Model:           cfg.ModelName,
		Messages:        s.messages,
		Tools:           cfg.Tools,
		SystemPrompt:    s.systemPrompt,
		PromptCacheKey:  promptCacheKey(cfg),
		CacheAnchors:    compactionSummaryIndices(s.messages),
		MaxTokens:       maxOutputTokens,
		Temperature:     0.5,
		ReasoningEffort: cfg.ReasoningEffort,
	}, func(recovery provider.ConnectionRecovery) {
		fields := recovery.FailureDiagnostic.Fields()
		fields["state"], fields["attempt"], fields["max_attempts"] = recovery.State, recovery.Attempt, recovery.MaxAttempts
		fields["retry_at"] = recovery.RetryAt
		l.emitEvent(cfg, "provider.connection", fields)
	})
	if err != nil {
		cancelStream()
		l.endProvider(cfg.RunID)
		// A request that died because the run was stopped is a stop, not a
		// failure: the provider client can be sitting in a retry backoff
		// when the user hits the button.
		if ctx.Err() != nil {
			return modelTurn{}, l.endAborted(s)
		}
		if l.isInterrupted(cfg.RunID) {
			return modelTurn{}, l.endInterrupted(s, "", "", nil)
		}
		// The banner the user reads gets plain language for the transient
		// failures the client already retried; the wrapped error keeps the
		// vendor's full response for the logs.
		return modelTurn{}, l.endFailed(s, provider.FailureFields(err), fmt.Errorf("provider stream: %w", err))
	}

	var turn modelTurn
	var content, reasoning strings.Builder
streamLoop:
	for event := range streamCh {
		switch event.Type {
		case provider.EventToken:
			if event.Channel == provider.ChannelReasoning {
				reasoning.WriteString(event.Content)
			} else {
				content.WriteString(event.Content)
			}
			payload := map[string]any{"content": event.Content}
			if event.Channel != "" {
				payload["channel"] = event.Channel
			}
			l.emitEvent(cfg, internal.EventModelToken, payload)
		case provider.EventToolUseDelta:
			// Live, incremental view of a tool call as the model writes it.
			// Transient UI signal only: the authoritative tool call is
			// emitted later via EventToolUse / tool.requested.
			if event.ToolCall != nil {
				l.emitEvent(cfg, internal.EventToolCallStreaming, map[string]any{
					"id":                event.ToolCall.ID,
					"name":              event.ToolCall.Name,
					"partial_arguments": event.ToolCall.Arguments,
				})
			}
		case provider.EventToolUse:
			if event.ToolCall != nil {
				turn.toolCalls = append(turn.toolCalls, internal.ToolCall{
					ID:        event.ToolCall.ID,
					Name:      internal.ToolName(event.ToolCall.Name),
					Arguments: normalizeToolArguments(event.ToolCall.Arguments),
				})
			}
		case provider.EventDone:
			if len(event.ReasoningDetails) > 0 {
				turn.reasoningDetails = event.ReasoningDetails
			}
			if event.Usage != nil {
				turn.usage = *event.Usage
			}
			cancelStream()
			break streamLoop
		case provider.EventError:
			if event.Error != nil {
				cancelStream()
				l.endProvider(cfg.RunID)
				if ctx.Err() != nil {
					return modelTurn{}, l.endAborted(s)
				}
				if l.isInterrupted(cfg.RunID) {
					return modelTurn{}, l.endInterrupted(s, content.String(), reasoning.String(), turn.reasoningDetails)
				}
				return modelTurn{}, l.endFailed(s, provider.FailureFields(event.Error), event.Error)
			}
		}
	}
	cancelStream()
	l.endProvider(cfg.RunID)
	turn.content, turn.reasoning = content.String(), reasoning.String()
	return turn, nil
}

// recordModelTurn books the turn's usage, normalizes a textual ask_user call
// into a real one, and emits model.completed. It ends the run if the user
// stopped or steered it while the response streamed.
func (l *Loop) recordModelTurn(ctx context.Context, s *runState, turn *modelTurn) *runEnd {
	cfg := s.cfg
	s.usage.InputTokens += turn.usage.InputTokens
	s.usage.OutputTokens += turn.usage.OutputTokens
	s.usage.CacheCreationInputTokens += turn.usage.CacheCreationInputTokens
	s.usage.CacheReadInputTokens += turn.usage.CacheReadInputTokens
	s.usage.Cost = addUsageCost(s.usage.Cost, turn.usage.Cost)

	turn.content, turn.toolCalls, _ = normalizeTextualAskUserCall(turn.content, turn.toolCalls, cfg.Tools)
	defs := cfg.Tools
	if len(defs) == 0 && l.toolRegistry != nil {
		defs = l.toolRegistry.List()
	}
	turn.toolCalls = qualifyBareToolNames(turn.toolCalls, defs)

	if ctx.Err() != nil {
		return l.endAborted(s)
	}
	if l.isInterrupted(cfg.RunID) {
		return l.endInterrupted(s, turn.content, turn.reasoning, turn.reasoningDetails)
	}

	usage := turn.usage
	utilization := contextUtilizationPercent(effectiveContextTokens(usage), s.contextWindow)
	payload := map[string]any{
		"content":                     turn.content,
		"model":                       cfg.ModelName,
		"tool_calls":                  len(turn.toolCalls),
		"input_tokens":                usage.InputTokens,
		"output_tokens":               usage.OutputTokens,
		"cache_creation_input_tokens": usage.CacheCreationInputTokens,
		"cache_read_input_tokens":     usage.CacheReadInputTokens,
		"context_window":              s.contextWindow,
		"context_utilization_percent": utilization,
	}
	if usage.Cost != nil {
		payload["cost"] = map[string]any{
			"request_id":              usage.Cost.RequestID,
			"input_cost_usd":          usage.Cost.InputCostUSD,
			"output_cost_usd":         usage.Cost.OutputCostUSD,
			"cache_creation_cost_usd": usage.Cost.CacheCreationCostUSD,
			"cache_read_cost_usd":     usage.Cost.CacheReadCostUSD,
			"raw_total_usd":           usage.Cost.RawTotalUSD,
			"billed_total_usd":        usage.Cost.BilledTotalUSD,
		}
	}
	l.emitEvent(cfg, internal.EventModelCompleted, payload)
	turn.usageDetails = messageUsageWithContext(usage, s.contextWindow)
	if turn.usageDetails != nil {
		turn.usageDetails.ContextUtilizationPercent = utilization
	}

	// Track the real prompt size the provider reported for compaction
	// decisions; messages appended later in this run add estimates.
	if effective := effectiveContextTokens(usage); effective > 0 {
		s.inputTokens = effective
	}
	return nil
}
