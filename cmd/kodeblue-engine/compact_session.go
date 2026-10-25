package main

import (
	"context"
	"fmt"

	internal "github.com/Problem99-io/kodeblue/internal"
	"github.com/Problem99-io/kodeblue/internal/agent"
	"github.com/Problem99-io/kodeblue/internal/api"
	"github.com/Problem99-io/kodeblue/internal/provider"
)

// CompactSession compacts a session's active history now, outside a run.
//
// It holds the session's run lease for the whole compaction, exactly as a run
// does: the summary is an LLM call that can take minutes, and a run started
// meanwhile would append messages the compacted set does not contain. A
// message submitted during compaction is queued instead and delivered once the
// lease is released. The rewrite is also limited to the snapshot it
// summarized, so nothing written after the snapshot can be hidden.
func (a *agentLoopAdapter) CompactSession(ctx context.Context, sessionID string, opts api.RunOptions) (api.CompactResult, error) {
	sid := internal.SessionID(sessionID)
	lease, err := a.runRepo.TryAcquireSessionRunLease(sid)
	if err != nil {
		return api.CompactResult{}, fmt.Errorf("acquire session lease: %w", err)
	}
	if lease == nil {
		return api.CompactResult{}, fmt.Errorf("compact session %s: %w", sessionID, api.ErrSessionBusy)
	}
	defer func() {
		lease.Release()
		a.drainQueue(sid)
	}()
	return a.compactSessionLocked(ctx, sid, opts)
}

func (a *agentLoopAdapter) compactSessionLocked(ctx context.Context, sid internal.SessionID, opts api.RunOptions) (api.CompactResult, error) {
	sessionID := string(sid)
	session, err := a.sessionRepo.Get(sid)
	if err != nil || session == nil {
		return api.CompactResult{}, fmt.Errorf("session not found: %s", sessionID)
	}
	if a.compactor == nil {
		return api.CompactResult{}, fmt.Errorf("compactor is not configured")
	}
	agentDef := a.agentFor(session)

	providerName := selectedProvider(opts, session, agentDef)
	if providerName == "" {
		return api.CompactResult{}, fmt.Errorf("no provider selected for session %s", sessionID)
	}
	p, ok := api.ResolveConfiguredProvider(a.providerRegistry, a.cfg, a.logger.Logger, providerName, opts.Model)
	if !ok {
		return api.CompactResult{}, fmt.Errorf("provider not available: %s (available: %v)", providerName, a.providerRegistry.List())
	}
	history, err := a.messageRepo.GetBySession(sid)
	if err != nil {
		return api.CompactResult{}, fmt.Errorf("load active history: %w", err)
	}
	modelName := selectedModel(opts, session, agentDef, p)

	before := len(history)
	inputTokens := latestStoredContextTokens(history)
	if inputTokens <= 0 {
		usage, err := p.CountTokens(ctx, &provider.Request{Model: modelName, Messages: history})
		if err != nil {
			return api.CompactResult{}, fmt.Errorf("count active history tokens: %w", err)
		}
		inputTokens = usage.InputTokens
	}
	contextWindow := provider.ResolveContextWindow(ctx, p, modelName)
	unchanged := func(active int) api.CompactResult {
		all, _ := a.messageRepo.GetAllBySession(sid)
		return api.CompactResult{
			BeforeActive:     active,
			AfterActive:      active,
			TotalHistory:     len(all),
			InputTokens:      inputTokens,
			AfterInputTokens: inputTokens,
			ContextWindow:    contextWindow,
		}
	}
	if before == 0 {
		return unchanged(0), nil
	}

	// Use the same system prompt and tools as the live agent so the request
	// shares its cached prefix.
	promptCfg := a.promptConfig(session, agentDef)
	compactRunID := internal.NewRunID()
	report, err := a.compactor.CompactWithReport(ctx, p, sid, compactRunID, history, agent.CompactOptions{
		ActiveModel:        modelName,
		ContextWindow:      contextWindow,
		CurrentInputTokens: inputTokens,
		SystemPrompt:       agent.BuildSystemPrompt(promptCfg),
		Tools:              promptCfg.Tools,
		PromptCacheKey:     sessionID,
		Manual:             true,
	})
	if err != nil {
		return api.CompactResult{}, fmt.Errorf("compact session: %w", err)
	}

	publicSummary := report.SummaryContent
	if internal.HasInternalContent(history) {
		publicSummary = ""
	}
	summary := &api.CompactionSummaryResult{
		Content: publicSummary,
		Model:   report.SummaryModel,
		Usage:   report.SummaryUsage,
	}
	compactedMessages := report.Messages
	after := len(compactedMessages)
	if after >= before {
		result := unchanged(before)
		if report.SummaryContent != "" || report.SummaryUsage != nil || report.SummaryModel != "" {
			result.CompactedMessages = report.CompactedMessages
			result.SummaryInputTokens = report.SummaryInputTokens
			result.UsedLLMSummary = report.UsedLLMSummary
			result.UsedFallback = report.UsedFallbackSummary
			result.Summary = summary
		}
		return result, nil
	}

	snapshot := make([]string, len(history))
	for i := range history {
		snapshot[i] = history[i].ID
	}
	if err := a.messageRepo.CompactSnapshot(sid, compactRunID, snapshot, compactedMessages); err != nil {
		return api.CompactResult{}, fmt.Errorf("persist compacted history: %w", err)
	}

	afterInputTokens := int64(0)
	afterUsage, err := p.CountTokens(ctx, &provider.Request{Model: modelName, Messages: compactedMessages})
	if err != nil {
		a.logger.Warn("count compacted history tokens failed", "session_id", sessionID, "error", err)
	} else {
		afterInputTokens = afterUsage.InputTokens
	}

	all, _ := a.messageRepo.GetAllBySession(sid)
	return api.CompactResult{
		Compacted:          true,
		BeforeActive:       before,
		AfterActive:        after,
		TotalHistory:       len(all),
		InputTokens:        inputTokens,
		AfterInputTokens:   afterInputTokens,
		ContextWindow:      contextWindow,
		CompactedMessages:  report.CompactedMessages,
		SummaryInputTokens: report.SummaryInputTokens,
		UsedLLMSummary:     report.UsedLLMSummary,
		UsedFallback:       report.UsedFallbackSummary,
		Summary:            summary,
	}, nil
}
