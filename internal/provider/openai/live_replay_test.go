package openai

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	internal "github.com/Problem99-io/kodeblue/internal"
	"github.com/Problem99-io/kodeblue/internal/provider"
)

// TestLiveReasoningReplayAgainstGateway drives the real client
// end-to-end against a live OpenAI-compatible gateway: turn 1 elicits a tool call
// (capturing streamed reasoning exactly like the agent loop does), turn 2
// replays the assistant message with ReasoningContent plus the tool result
// and must complete successfully.
//
// Opt-in: skipped unless KODEBLUE_LIVE_REPLAY_TEST=1. Requires
// KODEBLUE_LIVE_REPLAY_BASE_URL and KODEBLUE_LIVE_REPLAY_API_KEY. Model/provider
// pairs can be overridden via KODEBLUE_LIVE_REPLAY_TARGETS
// (comma-separated "provider:model" entries).
func TestLiveReasoningReplayAgainstGateway(t *testing.T) {
	if os.Getenv("KODEBLUE_LIVE_REPLAY_TEST") != "1" {
		t.Skip("set KODEBLUE_LIVE_REPLAY_TEST=1 to run the live replay test")
	}
	baseURL := strings.TrimRight(strings.TrimSpace(os.Getenv("KODEBLUE_LIVE_REPLAY_BASE_URL")), "/")
	apiKey := strings.TrimSpace(os.Getenv("KODEBLUE_LIVE_REPLAY_API_KEY"))
	if baseURL == "" || apiKey == "" {
		t.Fatal("KODEBLUE_LIVE_REPLAY_BASE_URL and KODEBLUE_LIVE_REPLAY_API_KEY must be set")
	}

	targets := []struct{ providerName, model string }{
		{"deepseek", "deepseek-v4-pro"},
		{"moonshotai", "kimi-k2.6"},
		{"minimax", "minimax-m3"},
	}
	if raw := strings.TrimSpace(os.Getenv("KODEBLUE_LIVE_REPLAY_TARGETS")); raw != "" {
		targets = targets[:0]
		for _, entry := range strings.Split(raw, ",") {
			providerName, model, ok := strings.Cut(strings.TrimSpace(entry), ":")
			if !ok {
				t.Fatalf("invalid KODEBLUE_LIVE_REPLAY_TARGETS entry %q, want provider:model", entry)
			}
			targets = append(targets, struct{ providerName, model string }{providerName, model})
		}
	}

	weatherTool := internal.ToolDefinition{
		Name:        "get_weather",
		Description: "Get the current weather for a location",
		Parameters:  json.RawMessage(`{"type":"object","properties":{"location":{"type":"string"}},"required":["location"]}`),
	}

	for _, target := range targets {
		t.Run(target.providerName, func(t *testing.T) {
			// Mirror provider_runtime.newGatewayProvider.
			client := NewClientWithAdvancedOptions(apiKey, target.model, ClientOptions{
				Name:                  target.providerName,
				BaseURL:               baseURL,
				ChatCompletionsPath:   "/v1/chat/completions",
				ModelsPath:            "/v1/models?provider=" + target.providerName,
				AuthHeaderName:        "Authorization",
				AuthHeaderValuePrefix: "Bearer ",
			})

			userMsg := internal.Message{
				ID:   internal.NewMessageID(),
				Role: "user",
				Content: "What is the weather in Paris right now? " +
					"You must call the get_weather tool to find out.",
			}

			// ---- Turn 1: elicit reasoning + a tool call, accumulated the
			// same way agent.Loop consumes the stream.
			turn1 := streamTurn(t, client, &provider.Request{
				Model:     target.model,
				MaxTokens: 2048,
				Messages:  []internal.Message{userMsg},
				Tools:     []internal.ToolDefinition{weatherTool},
			})
			if len(turn1.toolCalls) == 0 {
				t.Fatalf("turn 1 produced no tool call (content: %q)", truncate(turn1.content, 200))
			}
			t.Logf("turn 1: reasoning=%d bytes, tool_calls=%d", len(turn1.reasoning), len(turn1.toolCalls))

			assistantMsg := internal.Message{
				ID:               internal.NewMessageID(),
				Role:             "assistant",
				Content:          turn1.content,
				ReasoningContent: turn1.reasoning,
				ReasoningDetails: turn1.reasoningDetails,
				ToolCalls:        turn1.toolCalls,
				CreatedAt:        time.Now(),
			}
			toolResults := make([]internal.ToolResult, 0, len(turn1.toolCalls))
			for _, tc := range turn1.toolCalls {
				toolResults = append(toolResults, internal.ToolResult{
					ToolCallID: tc.ID,
					Content:    "22C and sunny",
				})
			}
			toolMsg := internal.Message{
				ID:          internal.NewMessageID(),
				Role:        "user",
				ToolResults: toolResults,
				CreatedAt:   time.Now(),
			}

			req2 := &provider.Request{
				Model:     target.model,
				MaxTokens: 2048,
				Messages:  []internal.Message{userMsg, assistantMsg, toolMsg},
				Tools:     []internal.ToolDefinition{weatherTool},
			}

			// Sanity: the replayed request body must carry the reasoning.
			if turn1.reasoning != "" {
				body, err := client.buildRequestBody(req2)
				if err != nil {
					t.Fatalf("buildRequestBody(turn 2) error = %v", err)
				}
				if !strings.Contains(string(body), `"reasoning_content"`) {
					t.Fatalf("turn 2 request body missing reasoning_content: %s", truncate(string(body), 500))
				}
			}

			// ---- Turn 2: the provider must accept the replayed reasoning.
			turn2 := streamTurn(t, client, req2)
			if strings.TrimSpace(turn2.content) == "" && len(turn2.toolCalls) == 0 {
				t.Fatal("turn 2 produced neither content nor tool calls")
			}
			t.Logf("turn 2: content=%q extra_tool_calls=%d", truncate(turn2.content, 120), len(turn2.toolCalls))
		})
	}
}

// TestLiveReasoningDetailsReplayAgainstGateway exercises the
// structured reasoning_details path with gpt-5.6 (relayed via OpenRouter):
// turn 1 (no tools) captures the streamed reasoning_details array from the
// Done event, turn 2 replays it verbatim on the assistant message — with
// tools attached, matching the agentic request shape — and must complete.
//
// Opt-in like TestLiveReasoningReplayAgainstGateway. Model
// overridable via KODEBLUE_LIVE_REPLAY_DETAILS_MODEL (default gpt-5.6-luna).
func TestLiveReasoningDetailsReplayAgainstGateway(t *testing.T) {
	if os.Getenv("KODEBLUE_LIVE_REPLAY_TEST") != "1" {
		t.Skip("set KODEBLUE_LIVE_REPLAY_TEST=1 to run the live replay test")
	}
	baseURL := strings.TrimRight(strings.TrimSpace(os.Getenv("KODEBLUE_LIVE_REPLAY_BASE_URL")), "/")
	apiKey := strings.TrimSpace(os.Getenv("KODEBLUE_LIVE_REPLAY_API_KEY"))
	if baseURL == "" || apiKey == "" {
		t.Fatal("KODEBLUE_LIVE_REPLAY_BASE_URL and KODEBLUE_LIVE_REPLAY_API_KEY must be set")
	}
	model := strings.TrimSpace(os.Getenv("KODEBLUE_LIVE_REPLAY_DETAILS_MODEL"))
	if model == "" {
		model = "gpt-5.6-luna"
	}

	client := NewClientWithAdvancedOptions(apiKey, model, ClientOptions{
		Name:                  "openai",
		BaseURL:               baseURL,
		ChatCompletionsPath:   "/v1/chat/completions",
		ModelsPath:            "/v1/models?provider=openai",
		AuthHeaderName:        "Authorization",
		AuthHeaderValuePrefix: "Bearer ",
	})

	userMsg := internal.Message{
		ID:   internal.NewMessageID(),
		Role: "user",
		Content: "A farmer has chickens and rabbits, 35 heads and 94 legs total. " +
			"How many chickens? Think it through, answer with just the number.",
	}

	// ---- Turn 1: no tools, so the OpenRouter route emits reasoning
	// (gpt-5.6 currently runs without reasoning when tools are attached).
	turn1 := streamTurn(t, client, &provider.Request{
		Model:           model,
		MaxTokens:       4096,
		ReasoningEffort: "high",
		Messages:        []internal.Message{userMsg},
	})
	if len(turn1.reasoningDetails) == 0 {
		t.Fatalf("turn 1 returned no reasoning_details (content: %q, reasoning: %d bytes)",
			truncate(turn1.content, 120), len(turn1.reasoning))
	}
	t.Logf("turn 1: content=%q details=%s", truncate(turn1.content, 60), truncate(string(turn1.reasoningDetails), 200))

	assistantMsg := internal.Message{
		ID:               internal.NewMessageID(),
		Role:             "assistant",
		Content:          turn1.content,
		ReasoningContent: turn1.reasoning,
		ReasoningDetails: turn1.reasoningDetails,
		CreatedAt:        time.Now(),
	}
	followUp := internal.Message{
		ID:        internal.NewMessageID(),
		Role:      "user",
		Content:   "And how many rabbits? Just the number.",
		CreatedAt: time.Now(),
	}
	calculatorTool := internal.ToolDefinition{
		Name:        "calculator",
		Description: "Evaluate a math expression",
		Parameters:  json.RawMessage(`{"type":"object","properties":{"expression":{"type":"string"}},"required":["expression"]}`),
	}
	req2 := &provider.Request{
		Model:           model,
		MaxTokens:       4096,
		ReasoningEffort: "high",
		Messages:        []internal.Message{userMsg, assistantMsg, followUp},
		Tools:           []internal.ToolDefinition{calculatorTool},
	}

	// Sanity: the turn-2 body must replay the details verbatim.
	body, err := client.buildRequestBody(req2)
	if err != nil {
		t.Fatalf("buildRequestBody(turn 2) error = %v", err)
	}
	if !strings.Contains(string(body), string(turn1.reasoningDetails)) {
		t.Fatalf("turn 2 request body does not carry reasoning_details verbatim: %s", truncate(string(body), 800))
	}

	// ---- Turn 2: the route must accept the replayed details.
	turn2 := streamTurn(t, client, req2)
	if strings.TrimSpace(turn2.content) == "" && len(turn2.toolCalls) == 0 {
		t.Fatal("turn 2 produced neither content nor tool calls")
	}
	t.Logf("turn 2: content=%q tool_calls=%d", truncate(turn2.content, 120), len(turn2.toolCalls))
}

// turnResult is what streamTurn accumulates from one provider stream,
// mirroring agent.Loop's consumption.
type turnResult struct {
	content          string
	reasoning        string
	toolCalls        []internal.ToolCall
	reasoningDetails json.RawMessage
}

// streamTurn consumes a provider stream the same way agent.Loop does.
func streamTurn(t *testing.T, client *Client, req *provider.Request) turnResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	streamCh, err := client.Stream(ctx, req)
	if err != nil {
		t.Fatalf("Stream() error = %v", err)
	}

	var out turnResult
	var contentBuf, reasoningBuf strings.Builder
	finish := func() turnResult {
		out.content = contentBuf.String()
		out.reasoning = reasoningBuf.String()
		return out
	}
	for event := range streamCh {
		switch event.Type {
		case provider.EventToken:
			if event.Channel == provider.ChannelReasoning {
				reasoningBuf.WriteString(event.Content)
			} else {
				contentBuf.WriteString(event.Content)
			}
		case provider.EventToolUse:
			if event.ToolCall != nil {
				out.toolCalls = append(out.toolCalls, internal.ToolCall{
					ID:        event.ToolCall.ID,
					Name:      internal.ToolName(event.ToolCall.Name),
					Arguments: json.RawMessage(event.ToolCall.Arguments),
				})
			}
		case provider.EventError:
			if event.Error != nil {
				t.Fatalf("stream error: %v", event.Error)
			}
		case provider.EventDone:
			if len(event.ReasoningDetails) > 0 {
				out.reasoningDetails = event.ReasoningDetails
			}
			return finish()
		}
	}
	return finish()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
