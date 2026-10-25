package openai

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	internal "github.com/Problem99-io/kodeblue/internal"
	"github.com/Problem99-io/kodeblue/internal/provider"
)

// TestReasoningDetailsAcc_MergesStreamedFragments mirrors the observed
// gpt-5.6-via-OpenRouter stream: a reasoning.summary entry arriving one
// fragment per chunk, followed by a whole reasoning.encrypted entry.
func TestReasoningDetailsAcc_MergesStreamedFragments(t *testing.T) {
	var acc reasoningDetailsAcc
	chunks := []string{
		`[{"type":"reasoning.summary","summary":"**Calculating**\n\nI","format":"openai-responses-v1","index":0}]`,
		`[{"type":"reasoning.summary","summary":" need","format":"openai-responses-v1","index":0}]`,
		`[{"type":"reasoning.summary","summary":" to solve.","format":"openai-responses-v1","index":0}]`,
		`[{"type":"reasoning.encrypted","data":"gAAAAABqWiv","format":"openai-responses-v1","id":"rs_123","index":0}]`,
	}
	for _, c := range chunks {
		acc.add(json.RawMessage(c))
	}

	out := acc.marshal()
	if out == nil {
		t.Fatal("marshal() returned nil")
	}
	var entries []map[string]any
	if err := json.Unmarshal(out, &entries); err != nil {
		t.Fatalf("marshal() produced invalid JSON: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2 (merged summary + encrypted); got %s", len(entries), out)
	}
	if got := entries[0]["summary"]; got != "**Calculating**\n\nI need to solve." {
		t.Errorf("merged summary = %q", got)
	}
	if got := entries[0]["type"]; got != "reasoning.summary" {
		t.Errorf("entry 0 type = %q", got)
	}
	if got := entries[1]["type"]; got != "reasoning.encrypted" {
		t.Errorf("entry 1 type = %q", got)
	}
	if got := entries[1]["data"]; got != "gAAAAABqWiv" {
		t.Errorf("encrypted data = %q", got)
	}
	if got := entries[1]["id"]; got != "rs_123" {
		t.Errorf("encrypted id = %q", got)
	}
}

// TestReasoningDetailsAcc_NewEntryOnIndexOrTypeChange verifies that a change
// in index or type starts a new entry instead of merging, preserving the
// block sequence.
func TestReasoningDetailsAcc_NewEntryOnIndexOrTypeChange(t *testing.T) {
	var acc reasoningDetailsAcc
	for _, c := range []string{
		`[{"type":"reasoning.text","text":"first ","index":0}]`,
		`[{"type":"reasoning.text","text":"block","index":0}]`,
		`[{"type":"reasoning.text","text":"second block","index":1}]`,
		`[{"type":"reasoning.text","text":" more","index":1,"signature":"sig-xyz"}]`,
	} {
		acc.add(json.RawMessage(c))
	}

	var entries []map[string]any
	if err := json.Unmarshal(acc.marshal(), &entries); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2; got %v", len(entries), entries)
	}
	if entries[0]["text"] != "first block" {
		t.Errorf("entry 0 text = %q", entries[0]["text"])
	}
	if entries[1]["text"] != "second block more" {
		t.Errorf("entry 1 text = %q", entries[1]["text"])
	}
	if entries[1]["signature"] != "sig-xyz" {
		t.Errorf("entry 1 signature = %q", entries[1]["signature"])
	}
}

func TestReasoningDetailsAcc_EmptyAndMalformed(t *testing.T) {
	var acc reasoningDetailsAcc
	if acc.marshal() != nil {
		t.Error("empty accumulator should marshal to nil")
	}
	acc.add(json.RawMessage(`{"not":"an array"}`))
	acc.add(json.RawMessage(`garbage`))
	if acc.marshal() != nil {
		t.Error("malformed input must be dropped, marshal should stay nil")
	}
}

// TestBuildAPIRequest_ReplaysReasoningDetailsVerbatim asserts the assistant
// message carries the stored reasoning_details array unmodified — including
// for the "openai" provider name, where the plaintext reasoning_content is
// stripped (forbid list) but reasoning_details must survive: the field only
// ever exists when the route emitted it, and such routes accept it back.
func TestBuildAPIRequest_ReplaysReasoningDetailsVerbatim(t *testing.T) {
	details := json.RawMessage(`[{"type":"reasoning.summary","summary":"thinking...","format":"openai-responses-v1","index":0},{"type":"reasoning.encrypted","data":"gAAAAABqWiv","format":"openai-responses-v1","id":"rs_123","index":0}]`)

	for _, providerName := range []string{"openai", "moonshotai", "deepseek"} {
		t.Run(providerName, func(t *testing.T) {
			client := NewClientWithAdvancedOptions("test-key", "some-model", ClientOptions{Name: providerName})
			req := &provider.Request{
				Model: "some-model",
				Messages: []internal.Message{
					{Role: "user", Content: "question", CreatedAt: time.Now()},
					{
						Role:             "assistant",
						Content:          "answer",
						ReasoningContent: "plaintext reasoning",
						ReasoningDetails: details,
						CreatedAt:        time.Now(),
					},
					{Role: "user", Content: "follow-up", CreatedAt: time.Now()},
				},
			}

			ar := client.buildAPIRequest(req, false, 0)
			var assistant *apiMessage
			for i := range ar.Messages {
				if ar.Messages[i].Role == "assistant" {
					assistant = &ar.Messages[i]
				}
			}
			if assistant == nil {
				t.Fatal("no assistant message in request")
			}
			if string(assistant.ReasoningDetails) != string(details) {
				t.Errorf("reasoning_details not replayed verbatim:\ngot  %s\nwant %s", assistant.ReasoningDetails, details)
			}

			body, err := json.Marshal(ar)
			if err != nil {
				t.Fatalf("marshal request: %v", err)
			}
			if !strings.Contains(string(body), `"reasoning_details"`) {
				t.Error("serialized request body missing reasoning_details")
			}
		})
	}
}

// TestBuildAPIRequest_OmitsReasoningDetailsWhenAbsent ensures no
// reasoning_details key leaks onto the wire for messages that have none.
func TestBuildAPIRequest_OmitsReasoningDetailsWhenAbsent(t *testing.T) {
	client := NewClientWithAdvancedOptions("test-key", "some-model", ClientOptions{Name: "deepseek"})
	req := &provider.Request{
		Model: "some-model",
		Messages: []internal.Message{
			{Role: "user", Content: "question", CreatedAt: time.Now()},
			{Role: "assistant", Content: "answer", ReasoningContent: "thinking", CreatedAt: time.Now()},
		},
	}
	body, err := json.Marshal(client.buildAPIRequest(req, false, 0))
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	if strings.Contains(string(body), `"reasoning_details"`) {
		t.Errorf("request body must not contain reasoning_details when absent: %s", body)
	}
}

// TestBuildAPIRequest_ReasoningDetailsOnlyOnAssistantMessages guards against
// echoing details on user/tool messages if a Message ever carries them.
func TestBuildAPIRequest_ReasoningDetailsOnlyOnAssistantMessages(t *testing.T) {
	details := json.RawMessage(`[{"type":"reasoning.text","text":"x","index":0}]`)
	client := NewClientWithAdvancedOptions("test-key", "some-model", ClientOptions{Name: "deepseek"})
	req := &provider.Request{
		Model: "some-model",
		Messages: []internal.Message{
			{Role: "user", Content: "question", ReasoningDetails: details, CreatedAt: time.Now()},
		},
	}
	ar := client.buildAPIRequest(req, false, 0)
	for _, m := range ar.Messages {
		if len(m.ReasoningDetails) > 0 {
			t.Errorf("role %q message must not carry reasoning_details", m.Role)
		}
	}
}

// TestStream_DoneEventCarriesAccumulatedReasoningDetails drives parseSSE via
// a fake SSE server emitting reasoning_details deltas and asserts the Done
// event carries the merged array.
func TestStream_DoneEventCarriesAccumulatedReasoningDetails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		lines := []string{
			`data: {"id":"x","choices":[{"index":0,"delta":{"reasoning":"thinking","reasoning_details":[{"type":"reasoning.summary","summary":"part one ","format":"openai-responses-v1","index":0}]},"finish_reason":null}]}`,
			`data: {"id":"x","choices":[{"index":0,"delta":{"reasoning_details":[{"type":"reasoning.summary","summary":"part two","format":"openai-responses-v1","index":0}]},"finish_reason":null}]}`,
			`data: {"id":"x","choices":[{"index":0,"delta":{"reasoning_details":[{"type":"reasoning.encrypted","data":"ENCDATA","format":"openai-responses-v1","id":"rs_9","index":0}]},"finish_reason":null}]}`,
			`data: {"id":"x","choices":[{"index":0,"delta":{"content":"answer"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`,
			`data: [DONE]`,
		}
		for _, l := range lines {
			_, _ = io.WriteString(w, l+"\n\n")
		}
	}))
	defer server.Close()

	client := NewClientWithAdvancedOptions("test-key", "gpt-5.6-luna", ClientOptions{
		Name:                "openai",
		BaseURL:             server.URL,
		ChatCompletionsPath: "/v1/chat/completions",
	})

	ch, err := client.Stream(context.Background(), &provider.Request{
		Model:     "gpt-5.6-luna",
		MaxTokens: 64,
		Messages:  []internal.Message{{Role: "user", Content: "hi"}},
	})
	if err != nil {
		t.Fatalf("Stream() error = %v", err)
	}

	var details json.RawMessage
	for ev := range ch {
		if ev.Type == provider.EventDone {
			details = ev.ReasoningDetails
		}
	}
	if details == nil {
		t.Fatal("Done event carried no reasoning details")
	}
	var entries []map[string]any
	if err := json.Unmarshal(details, &entries); err != nil {
		t.Fatalf("invalid reasoning details JSON: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2; got %s", len(entries), details)
	}
	if entries[0]["summary"] != "part one part two" {
		t.Errorf("merged summary = %q", entries[0]["summary"])
	}
	if entries[1]["data"] != "ENCDATA" || entries[1]["id"] != "rs_9" {
		t.Errorf("encrypted entry = %v", entries[1])
	}
}
