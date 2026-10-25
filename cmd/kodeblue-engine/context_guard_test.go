package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	internal "github.com/Problem99-io/kodeblue/internal"
	"github.com/Problem99-io/kodeblue/internal/provider"
)

// guardTestProvider reports a context window from a stand-in catalog so it
// satisfies the reported-window resolver the guard relies on.
type guardTestProvider struct {
	window   int64
	reported bool
}

func TestClearModelBoundReasoningPreservesPortableHistory(t *testing.T) {
	history := []internal.Message{{
		ID:               "assistant-1",
		Role:             "assistant",
		Content:          "portable answer",
		ReasoningContent: "model-private thought",
		ReasoningDetails: json.RawMessage(`[{"type":"reasoning.encrypted","data":"ciphertext"}]`),
		ToolCalls: []internal.ToolCall{{
			ID: "call-1",
		}},
	}}

	got := clearModelBoundReasoning(history)
	if got[0].ReasoningContent != "" || len(got[0].ReasoningDetails) != 0 {
		t.Fatalf("model-bound reasoning survived switch: %+v", got[0])
	}
	if got[0].Content != history[0].Content || len(got[0].ToolCalls) != 1 {
		t.Fatalf("portable history was changed: %+v", got[0])
	}
	if history[0].ReasoningContent == "" || len(history[0].ReasoningDetails) == 0 {
		t.Fatal("clearModelBoundReasoning mutated the caller's history")
	}
}

func (guardTestProvider) Name() string { return "guardtest" }
func (guardTestProvider) Stream(ctx context.Context, req *provider.Request) (<-chan provider.StreamEvent, error) {
	return nil, nil
}
func (guardTestProvider) CountTokens(ctx context.Context, req *provider.Request) (*provider.Usage, error) {
	return nil, nil
}
func (p guardTestProvider) ReportedContextWindow(ctx context.Context, model string) (int64, bool) {
	return p.window, p.reported
}

func historyUsing(inputTokens int64) []internal.Message {
	return []internal.Message{{
		Role:  "assistant",
		Usage: &internal.MessageUsage{InputTokens: inputTokens},
	}}
}

func TestGuardModelSwitchContextWindow(t *testing.T) {
	t.Run("blocks when conversation exceeds a known target window", func(t *testing.T) {
		err := guardModelSwitchContextWindow(guardTestProvider{window: 128_000, reported: true}, "small-model", historyUsing(180_000))
		if err == nil {
			t.Fatal("expected the switch to be blocked, got nil")
		}
		// The reason must be actionable: name the model and both numbers.
		for _, want := range []string{"small-model", "128,000", "180,000"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("error %q missing %q", err.Error(), want)
			}
		}
	})

	t.Run("allows when the target window can hold the conversation", func(t *testing.T) {
		if err := guardModelSwitchContextWindow(guardTestProvider{window: 1_000_000, reported: true}, "big-model", historyUsing(180_000)); err != nil {
			t.Fatalf("expected switch to be allowed, got %v", err)
		}
	})

	t.Run("allows a fresh conversation with no prior usage", func(t *testing.T) {
		if err := guardModelSwitchContextWindow(guardTestProvider{window: 1_000, reported: true}, "tiny-model", nil); err != nil {
			t.Fatalf("expected switch allowed on empty history, got %v", err)
		}
	})

	t.Run("fails open when the target window is unknown", func(t *testing.T) {
		// Catalog silent AND model not in the registry -> we must not block on a guess.
		if err := guardModelSwitchContextWindow(guardTestProvider{reported: false}, "unknown-model-xyz", historyUsing(500_000)); err != nil {
			t.Fatalf("expected switch allowed when window unknown, got %v", err)
		}
	})

	t.Run("uses the registry window when the catalog is silent", func(t *testing.T) {
		// claude-haiku-4.5 is 200k in the registry; a 500k conversation cannot move to it.
		if err := guardModelSwitchContextWindow(guardTestProvider{reported: false}, "claude-haiku-4.5", historyUsing(500_000)); err == nil {
			t.Fatal("expected block using registry window, got nil")
		}
	})
}

func TestFormatTokenCount(t *testing.T) {
	cases := map[int64]string{
		0:       "0",
		5:       "5",
		999:     "999",
		1_000:   "1,000",
		200_000: "200,000",
		1000000: "1,000,000",
		1234567: "1,234,567",
	}
	for in, want := range cases {
		if got := formatTokenCount(in); got != want {
			t.Fatalf("formatTokenCount(%d) = %q, want %q", in, got, want)
		}
	}
}
