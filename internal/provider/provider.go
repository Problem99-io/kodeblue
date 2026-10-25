package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"sort"
	"sync"

	"github.com/Problem99-io/kodeblue/internal"
)

// StreamEventType classifies the kind of streaming event.
type StreamEventType int

const (
	EventToken StreamEventType = iota
	EventToolUse
	EventToolUseDelta
	EventDone
	EventError
)

const (
	ChannelText      = "text"
	ChannelReasoning = "reasoning"
)

// ToolCallEvent carries tool invocation data from the model.
type ToolCallEvent struct {
	ID        string
	Name      string
	Arguments string // raw JSON
}

// SanitizeToolArguments returns a tool call's arguments blob in a form that is
// always safe to replay to a provider in a later request.
//
// Streamed tool-call arguments can be truncated mid-value when a generation is
// cut off — the model hitting its token limit (finish_reason "length"), a
// dropped SSE fragment, or an upstream relay hiccup. The accumulated blob is
// then invalid JSON (e.g. `{"command":"go build ./... 2>` with no closing quote
// or brace). Replaying that fragment in conversation history poisons the whole
// run: OpenAI-compatible providers such as xAI/Grok reject the request with 400
// "Invalid tool arguments received ... EOF while parsing a string", and because
// the malformed turn stays in history, every subsequent turn fails the same way
// — the conversation is wedged until the turn is compacted or dropped.
//
// Valid JSON is returned unchanged (the overwhelmingly common case). An empty
// blob is returned unchanged so providers still treat the call as having no
// arguments. A non-empty blob that does not parse as JSON is replaced with "{}"
// so the outgoing request is always well-formed. A truncated call carried no
// usable arguments anyway, and the agent loop reconciles it with an error
// tool-result, so nothing recoverable is lost by normalizing it here.
func SanitizeToolArguments(raw json.RawMessage) json.RawMessage {
	if len(bytes.TrimSpace(raw)) == 0 {
		return raw
	}
	if json.Valid(raw) {
		return raw
	}
	return json.RawMessage("{}")
}

// Usage tracks token consumption for a request.
type Usage struct {
	InputTokens  int64
	OutputTokens int64

	// Anthropic prompt caching fields.
	CacheCreationInputTokens int64
	CacheReadInputTokens     int64
	Cost                     *CostBreakdown
}

type CostBreakdown struct {
	RequestID            string
	InputCostUSD         float64
	OutputCostUSD        float64
	CacheCreationCostUSD float64
	CacheReadCostUSD     float64
	RawTotalUSD          float64
	BilledTotalUSD       float64
}

// StreamEvent is a normalized event emitted by any provider during streaming.
type StreamEvent struct {
	Type     StreamEventType
	Content  string         // text content for token events
	Channel  string         // text or reasoning for token events
	ToolCall *ToolCallEvent // non-nil for tool_use events
	Usage    *Usage
	Error    error
	Done     bool
	// ReasoningDetails carries the accumulated raw reasoning_details array
	// (OpenRouter-compatible routes) on Done events. It must be replayed
	// verbatim in the next request's assistant message.
	ReasoningDetails json.RawMessage
}

// Request describes what to send to an LLM provider.
type Request struct {
	Model          string
	Messages       []internal.Message
	Tools          []internal.ToolDefinition
	SystemPrompt   string
	PromptCacheKey string
	// CacheAnchors are indices into Messages that stay stable across calls
	// (compaction summaries); providers may place a cache marker there.
	CacheAnchors    []int
	MaxTokens       int
	Temperature     float64
	ReasoningEffort string // OpenAI reasoning_effort (none/minimal/low/medium/high); empty = provider default
	StopSequences   []string
}

// Provider is the interface all LLM adapters implement.
type Provider interface {
	Name() string
	Stream(ctx context.Context, req *Request) (<-chan StreamEvent, error)
	CountTokens(ctx context.Context, req *Request) (*Usage, error)
}

// Registry holds named providers.
type Registry struct {
	mu        sync.RWMutex
	providers map[string]Provider
}

// NewRegistry creates an empty provider registry.
func NewRegistry() *Registry {
	return &Registry{
		providers: make(map[string]Provider),
	}
}

// Register adds a provider under the given name.
func (r *Registry) Register(name string, p Provider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.providers[name] = p
}

// Unregister removes a provider from the registry.
func (r *Registry) Unregister(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.providers, name)
}

// Get retrieves a provider by name.
func (r *Registry) Get(name string) (Provider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[name]
	return p, ok
}

// List returns the sorted names of all registered providers.
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.providers))
	for name := range r.providers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
