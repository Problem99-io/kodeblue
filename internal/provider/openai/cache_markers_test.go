package openai

import (
	"encoding/json"
	"strings"
	"testing"

	internal "github.com/Problem99-io/kodeblue/internal"
	"github.com/Problem99-io/kodeblue/internal/provider"
)

func cacheTestRequest() *provider.Request {
	return &provider.Request{
		Model:          "example-model",
		SystemPrompt:   "system rules",
		PromptCacheKey: "sess_abc",
		Messages: []internal.Message{
			{Role: "user", Content: "first task"},
			{Role: "assistant", ToolCalls: []internal.ToolCall{{ID: "a", Name: "read"}, {ID: "b", Name: "read"}}},
			{Role: "user", ToolResults: []internal.ToolResult{{ToolCallID: "a", Content: "one"}, {ToolCallID: "b", Content: "two"}}},
			{Role: "assistant", Content: "done reading"},
			{Role: "user", Content: "follow up"},
		},
	}
}

func markedIndices(t *testing.T, ar apiRequest) []int {
	t.Helper()
	var out []int
	for i, m := range ar.Messages {
		if parts, ok := m.Content.([]contentPart); ok {
			for _, p := range parts {
				if p.CacheControl != nil {
					out = append(out, i)
				}
			}
		}
	}
	return out
}

func TestCacheMarkersStaticPrefixAndNewestBoundaries(t *testing.T) {
	c := NewClientWithAdvancedOptions("k", "example-model", ClientOptions{Name: "example-gateway", SupportsPromptCacheKey: true,
		CacheCaps: map[string]CacheCaps{"example-model": {Supported: true, MaxMarkers: 4}}})
	ar := c.buildAPIRequest(cacheTestRequest(), true, 0)
	// messages: 0 system, 1 user, 2 assistant(tool calls), 3 tool a, 4 tool b, 5 assistant, 6 user
	got := markedIndices(t, ar)
	want := []int{0, 1, 4, 6} // system, then newest boundaries: 6, end of tool batch 4, 1
	if len(got) != len(want) {
		t.Fatalf("marked %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("marked %v, want %v", got, want)
		}
	}
	if ar.SessionID != "sess_abc" || ar.CacheControl != nil {
		t.Fatalf("session_id=%q top-level=%v", ar.SessionID, ar.CacheControl)
	}
	// Tool a (not a batch end) carries no marker but is still parts-shaped, so
	// its bytes do not change when markers move.
	if _, ok := ar.Messages[3].Content.([]contentPart); !ok {
		t.Fatal("eligible messages must always be serialized as parts")
	}
}

func TestCacheMarkersRespectBudgetAndAnchor(t *testing.T) {
	c := NewClientWithAdvancedOptions("k", "openai/gpt-6-luna", ClientOptions{Name: "openrouter", SupportsPromptCacheKey: true,
		CacheCaps: map[string]CacheCaps{"openai/gpt-6-luna": {Supported: true, MaxMarkers: 3}}})
	req := cacheTestRequest()
	req.Model = "openai/gpt-6-luna"
	req.CacheAnchors = []int{0} // pretend the first user message is a compaction summary
	ar := c.buildAPIRequest(req, true, 0)
	got := markedIndices(t, ar)
	if len(got) != 3 || got[0] != 0 || got[1] != 1 || got[2] != 6 {
		t.Fatalf("marked %v, want [0 1 6] (system, anchor, newest)", got)
	}
}

func TestNoPublishedCapsKeepsLegacyBehavior(t *testing.T) {
	c := NewClientWithAdvancedOptions("k", "anthropic/claude-sonnet-5-5", ClientOptions{Name: "openrouter", SupportsPromptCacheKey: true})
	req := cacheTestRequest()
	req.Model = "anthropic/claude-sonnet-5-5"
	ar := c.buildAPIRequest(req, true, 0)
	if len(markedIndices(t, ar)) != 0 || ar.CacheControl == nil || ar.SessionID != "" {
		t.Fatalf("legacy: markers=%v top=%v session=%q", markedIndices(t, ar), ar.CacheControl, ar.SessionID)
	}
	if _, ok := ar.Messages[1].Content.(string); !ok {
		t.Fatal("without caps the message shape must be unchanged")
	}
}

func TestUnsupportedModelSendsNoMarkers(t *testing.T) {
	c := NewClientWithAdvancedOptions("k", "deepseek/x", ClientOptions{Name: "openrouter", SupportsPromptCacheKey: true,
		CacheCaps: map[string]CacheCaps{"deepseek/x": {Supported: false}}})
	req := cacheTestRequest()
	req.Model = "deepseek/x"
	ar := c.buildAPIRequest(req, true, 0)
	body, _ := json.Marshal(ar)
	if strings.Contains(string(body), "cache_control") {
		t.Fatalf("no markers expected: %s", body)
	}
}
