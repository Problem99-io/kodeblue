package provider

import "context"

// ModelInfo describes a model's capabilities relevant to context management.
type ModelInfo struct {
	ContextWindow int64 // max input tokens
}

// DefaultContextWindow is the conservative fallback used when neither the
// gateway's model catalog nor the registry below reports a context
// window for a model.
const DefaultContextWindow int64 = 100_000

// modelRegistry is a small fallback table of context windows for well-known
// public models. The gateway's model catalog is the source of truth; this is
// consulted only when the catalog does not report a window.
var modelRegistry = map[string]ModelInfo{
	// MiniMax
	"MiniMax-M3":   {ContextWindow: 1_000_000},
	"minimax-m3":   {ContextWindow: 1_000_000},
	"minimax-m2.7": {ContextWindow: 204_800},

	// OpenAI GPT-4o
	"gpt-4o":            {ContextWindow: 128_000},
	"gpt-4o-mini":       {ContextWindow: 128_000},
	"gpt-4o-2024-08-06": {ContextWindow: 128_000},

	// OpenAI GPT-4.1
	"gpt-4.1":      {ContextWindow: 1_000_000},
	"gpt-4.1-mini": {ContextWindow: 1_000_000},
	"gpt-4.1-nano": {ContextWindow: 1_000_000},

	// OpenAI GPT-5
	"gpt-5":        {ContextWindow: 1_000_000},
	"gpt-5.4":      {ContextWindow: 1_000_000},
	"gpt-5.4-nano": {ContextWindow: 128_000},
	"gpt-5.4-mini": {ContextWindow: 128_000},
	"gpt-5.4-pro":  {ContextWindow: 256_000},

	// Anthropic Claude
	"claude-opus-4.8":            {ContextWindow: 200_000},
	"claude-sonnet-4.6":          {ContextWindow: 200_000},
	"claude-haiku-4.5":           {ContextWindow: 200_000},
	"claude-sonnet-4-6":          {ContextWindow: 200_000},
	"claude-opus-4-20250514":     {ContextWindow: 200_000},
	"claude-3-5-sonnet-20241022": {ContextWindow: 200_000},
	"claude-3-5-haiku-20241022":  {ContextWindow: 200_000},

	// Anthropic shorthand aliases
	"claude-sonnet-4":   {ContextWindow: 200_000},
	"claude-opus-4":     {ContextWindow: 200_000},
	"claude-3-5-sonnet": {ContextWindow: 200_000},
	"claude-3-5-haiku":  {ContextWindow: 200_000},

	// Moonshot AI Kimi
	"kimi-k2.6":              {ContextWindow: 262_144},
	"kimi-k2-thinking-turbo": {ContextWindow: 262_144},
}

// GetContextWindow returns the context window size for a model.
// Falls back to DefaultContextWindow for unknown models.
func GetContextWindow(model string) int64 {
	if info, ok := modelRegistry[model]; ok {
		return info.ContextWindow
	}
	return DefaultContextWindow
}

type contextWindowResolver interface {
	ContextWindow(ctx context.Context, model string) (int64, error)
}

// ResolveContextWindow prefers vendor-reported context limits when the provider
// can resolve them, and falls back to the built-in registry otherwise. It is
// resolved fresh on every turn, so a context-window change in the gateway
// takes effect on the next turn without restarting the engine.
func ResolveContextWindow(ctx context.Context, p Provider, model string) int64 {
	if resolver, ok := p.(contextWindowResolver); ok {
		if window, err := resolver.ContextWindow(ctx, model); err == nil && window > 0 {
			return window
		}
	}
	return GetContextWindow(model)
}

// reportedContextWindowResolver is implemented by providers that can report a
// model's context window straight from the gateway catalog, separate
// from any built-in fallback — letting callers tell an authoritative window from
// a guess.
type reportedContextWindowResolver interface {
	ReportedContextWindow(ctx context.Context, model string) (int64, bool)
}

// ResolveContextWindowKnown resolves a model's context window and reports whether
// the value is authoritative — reported live by the gateway
// catalog or present in the built-in registry — as opposed to DefaultContextWindow,
// the conservative guess used for models we don't recognize.
//
// Safety decisions must only act when known is true. In particular the
// model-switch safeguard refuses a switch only when it authoritatively knows the
// target model's window is smaller than the conversation's current size; blocking
// on the default guess would falsely reject models we simply lack a size for.
func ResolveContextWindowKnown(ctx context.Context, p Provider, model string) (window int64, known bool) {
	if resolver, ok := p.(reportedContextWindowResolver); ok {
		if reported, ok := resolver.ReportedContextWindow(ctx, model); ok && reported > 0 {
			return reported, true
		}
	}
	if info, ok := modelRegistry[model]; ok {
		return info.ContextWindow, true
	}
	return DefaultContextWindow, false
}
