package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	internal "github.com/Problem99-io/kodeblue/internal"
	"github.com/Problem99-io/kodeblue/internal/api"
	"github.com/Problem99-io/kodeblue/internal/provider"
)

// selectedProvider applies the precedence per-message override > session >
// agent. Empty means nothing selected one.
func selectedProvider(opts api.RunOptions, session *internal.Session, agentDef *internal.AgentDefinition) string {
	switch {
	case opts.Provider != "":
		return opts.Provider
	case session.Provider != "":
		return session.Provider
	case agentDef != nil:
		return agentDef.Provider
	}
	return ""
}

// selectedModel applies the precedence per-message override > session >
// agent > the provider's default.
func selectedModel(opts api.RunOptions, session *internal.Session, agentDef *internal.AgentDefinition, p provider.Provider) string {
	switch {
	case opts.Model != "":
		return opts.Model
	case session.Model != "":
		return session.Model
	case agentDef != nil && agentDef.Model != "":
		return agentDef.Model
	}
	return providerDefaultModel(p)
}

// providerDefaultModel returns the model a provider client uses when a
// session names none.
func providerDefaultModel(p provider.Provider) string {
	if dm, ok := p.(interface{ DefaultModel() string }); ok {
		return strings.TrimSpace(dm.DefaultModel())
	}
	return ""
}

// guardModelSwitchContextWindow refuses a model switch that would leave the
// existing conversation larger than the target model's context window. It only
// acts when the target window is authoritatively known (never on the conservative
// default guess) and there is real prior usage to overflow, so it can never wedge
// a fresh session or a model we don't have a size for. Returns nil when the switch
// is safe.
func guardModelSwitchContextWindow(p provider.Provider, targetModel string, history []internal.Message) error {
	used := latestStoredContextTokens(history)
	if used <= 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	window, known := provider.ResolveContextWindowKnown(ctx, p, targetModel)
	if !known || window <= 0 {
		return nil
	}
	if used > window {
		return fmt.Errorf(
			"cannot switch to %q: its context window (%s tokens) is smaller than this conversation's current context (%s tokens) — compact the conversation or pick a model with a larger context window",
			targetModel, formatTokenCount(window), formatTokenCount(used),
		)
	}
	return nil
}

// clearModelBoundReasoning returns a request-safe copy of history for the first
// turn after an explicit provider/model switch. It deliberately leaves the
// caller's slice untouched and preserves every portable conversation field.
func clearModelBoundReasoning(history []internal.Message) []internal.Message {
	if len(history) == 0 {
		return history
	}
	out := append([]internal.Message(nil), history...)
	for i := range out {
		out[i].ReasoningContent = ""
		out[i].ReasoningDetails = nil
	}
	return out
}

// formatTokenCount renders a token total with thousands separators, e.g. 200000
// -> "200,000", for human-readable error messages.
func formatTokenCount(n int64) string {
	s := strconv.FormatInt(n, 10)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	var b strings.Builder
	for i := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteByte(s[i])
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

// latestStoredContextTokens returns the prompt size of the most recent turn
// that recorded usage, or 0 when none did.
func latestStoredContextTokens(history []internal.Message) int64 {
	for idx := len(history) - 1; idx >= 0; idx-- {
		usage := history[idx].Usage
		if usage == nil {
			continue
		}
		total := usage.InputTokens + usage.CacheCreationInputTokens + usage.CacheReadInputTokens
		if total > 0 {
			return total
		}
		if usage.InputTokens > 0 {
			return usage.InputTokens
		}
	}
	return 0
}
