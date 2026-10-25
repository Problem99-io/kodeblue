package openai

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Problem99-io/kodeblue/internal"
	"github.com/Problem99-io/kodeblue/internal/provider"
)

// Cache policy is caller markers plus the gateway's translation of them
// (see cache_markers.go).

func TestBuildAPIRequest_SetsPromptCacheKeyForOpenAI(t *testing.T) {
	client := NewClient("test-key", "gpt-5.4")
	req := &provider.Request{Model: "gpt-5.4", MaxTokens: 256, PromptCacheKey: "sess_123"}

	apiReq := client.buildAPIRequest(req, true, req.MaxTokens)
	if apiReq.PromptCacheKey != "sess_123" {
		t.Fatalf("PromptCacheKey = %q, want %q", apiReq.PromptCacheKey, "sess_123")
	}

	body, err := json.Marshal(apiReq)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if !jsonContainsField(body, "prompt_cache_key", "sess_123") {
		t.Fatalf("serialized request missing prompt_cache_key=sess_123: %s", string(body))
	}
}

func TestBuildAPIRequest_SetsPromptCacheKeyForGatewayProvider(t *testing.T) {
	client := NewClientWithAdvancedOptions("test-key", "minimax-m2.7", ClientOptions{
		Name:                   "minimax",
		BaseURL:                "http://127.0.0.1:9090",
		SupportsPromptCacheKey: true,
	})
	req := &provider.Request{Model: "minimax-m2.7", MaxTokens: 256, PromptCacheKey: "sess_123"}

	apiReq := client.buildAPIRequest(req, true, req.MaxTokens)
	if apiReq.PromptCacheKey != "sess_123" {
		t.Fatalf("PromptCacheKey = %q, want %q", apiReq.PromptCacheKey, "sess_123")
	}

	body, err := json.Marshal(apiReq)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if !jsonContainsField(body, "prompt_cache_key", "sess_123") {
		t.Fatalf("serialized request missing prompt_cache_key=sess_123: %s", string(body))
	}
}

func TestBuildAPIRequest_SetsCacheControlForAnthropicClaudeOnOpenAICompatPath(t *testing.T) {
	client := NewClientWithAdvancedOptions("test-key", "claude-sonnet-4.6", ClientOptions{
		Name:    "anthropic",
		BaseURL: "http://127.0.0.1:9090",
	})
	req := &provider.Request{Model: "claude-sonnet-4.6", MaxTokens: 256}

	apiReq := client.buildAPIRequest(req, true, req.MaxTokens)
	if apiReq.CacheControl == nil || apiReq.CacheControl.Type != "ephemeral" {
		t.Fatalf("CacheControl = %#v, want ephemeral cache control", apiReq.CacheControl)
	}

	body, err := json.Marshal(apiReq)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if !jsonContainsNestedField(body, []string{"cache_control", "type"}, "ephemeral") {
		t.Fatalf("serialized request missing cache_control.type=ephemeral: %s", string(body))
	}
}

func TestBuildAPIRequest_DoesNotSetCacheControlForNonClaudeOpenAICompatModels(t *testing.T) {
	client := NewClientWithAdvancedOptions("test-key", "gpt-5.4", ClientOptions{
		Name:    "anthropic",
		BaseURL: "http://127.0.0.1:9090",
	})
	req := &provider.Request{Model: "gpt-5.4", MaxTokens: 256}

	apiReq := client.buildAPIRequest(req, true, req.MaxTokens)
	if apiReq.CacheControl != nil {
		t.Fatalf("CacheControl = %#v, want nil", apiReq.CacheControl)
	}

	body, err := json.Marshal(apiReq)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if jsonContainsAnyField(body, "cache_control") {
		t.Fatalf("serialized request unexpectedly included cache_control: %s", string(body))
	}
}

func TestBuildAPIRequest_SerializesFileAndImageAttachments(t *testing.T) {
	client := NewClient("test-key", "gpt-5.4")
	req := &provider.Request{
		Model:     "gpt-5.4",
		MaxTokens: 256,
		Messages: []internal.Message{
			{
				Role:    "user",
				Content: "review these",
				Attachments: []internal.Attachment{
					{MediaType: "image/png", FileName: "shot.png", Data: "aW1n"},
					{MediaType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", FileName: "memo.docx", Data: "ZG9j"},
					{MediaType: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", FileName: "data.xlsx", Data: "eGxz"},
				},
			},
		},
	}

	apiReq := client.buildAPIRequest(req, false, req.MaxTokens)
	body, err := json.Marshal(apiReq)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	// Decode and locate the user message's content parts.
	var decoded struct {
		Messages []struct {
			Role    string `json:"role"`
			Content []struct {
				Type     string `json:"type"`
				Text     string `json:"text"`
				ImageURL *struct {
					URL string `json:"url"`
				} `json:"image_url"`
				File *struct {
					Filename string `json:"filename"`
					FileData string `json:"file_data"`
				} `json:"file"`
			} `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v\nbody: %s", err, string(body))
	}
	if len(decoded.Messages) != 1 {
		t.Fatalf("got %d messages, want 1: %s", len(decoded.Messages), string(body))
	}
	parts := decoded.Messages[0].Content

	var gotText, gotImage bool
	files := map[string]string{} // filename -> file_data
	for _, p := range parts {
		switch p.Type {
		case "text":
			if p.Text == "review these" {
				gotText = true
			}
		case "image_url":
			if p.ImageURL != nil && p.ImageURL.URL == "data:image/png;base64,aW1n" {
				gotImage = true
			}
		case "file":
			if p.File != nil {
				files[p.File.Filename] = p.File.FileData
			}
		}
	}

	if !gotText {
		t.Errorf("missing text part: %s", string(body))
	}
	if !gotImage {
		t.Errorf("missing image_url part: %s", string(body))
	}
	wantFiles := map[string]string{
		"memo.docx": "data:application/vnd.openxmlformats-officedocument.wordprocessingml.document;base64,ZG9j",
		"data.xlsx": "data:application/vnd.openxmlformats-officedocument.spreadsheetml.sheet;base64,eGxz",
	}
	for name, want := range wantFiles {
		if got := files[name]; got != want {
			t.Errorf("file %q file_data = %q, want %q", name, got, want)
		}
	}
}

// PDFs must never reach a model, whatever the caller did to get one this far.
func TestBuildAPIRequest_RefusesPDFAttachments(t *testing.T) {
	client := NewClient("test-key", "gpt-5.4")
	req := &provider.Request{
		Model:     "gpt-5.4",
		MaxTokens: 256,
		Messages: []internal.Message{
			{
				Role:    "user",
				Content: "summarize",
				Attachments: []internal.Attachment{
					{MediaType: "application/pdf", FileName: "report.pdf", Data: "cGRm"},
					// A mislabeled PDF must be caught by its extension too.
					{MediaType: "application/octet-stream", FileName: "invoice.PDF", Data: "cGRm"},
				},
			},
		},
	}

	body, err := json.Marshal(client.buildAPIRequest(req, false, req.MaxTokens))
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if strings.Contains(string(body), "cGRm") {
		t.Fatalf("PDF payload was serialized into the request: %s", string(body))
	}
	if !strings.Contains(string(body), "temporarily disabled") {
		t.Errorf("request does not tell the model the PDFs were withheld: %s", string(body))
	}
	for _, name := range []string{"report.pdf", "invoice.PDF"} {
		if !strings.Contains(string(body), name) {
			t.Errorf("withheld attachment %q is not named: %s", name, string(body))
		}
	}
}

// Replayed history carries attachment descriptors with no payload, because the
// payloads are deliberately not persisted. Such a turn must still produce a
// valid, non-empty content array that names what was attached.
func TestBuildAPIRequest_NamesAttachmentsWhosePayloadWasDropped(t *testing.T) {
	client := NewClient("test-key", "gpt-5.4")
	req := &provider.Request{
		Model:     "gpt-5.4",
		MaxTokens: 256,
		Messages: []internal.Message{
			{
				Role: "user",
				Attachments: []internal.Attachment{
					{MediaType: "image/png", FileName: "shot.png"},
					{MediaType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", FileName: "memo.docx"},
				},
			},
		},
	}

	body, err := json.Marshal(client.buildAPIRequest(req, false, req.MaxTokens))
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	var decoded struct {
		Messages []struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v\nbody: %s", err, string(body))
	}
	if len(decoded.Messages) != 1 || len(decoded.Messages[0].Content) != 1 {
		t.Fatalf("want exactly one content part, got: %s", string(body))
	}
	part := decoded.Messages[0].Content[0]
	if part.Type != "text" {
		t.Fatalf("part type = %q, want text: %s", part.Type, string(body))
	}
	if !strings.Contains(part.Text, "shot.png") || !strings.Contains(part.Text, "memo.docx") {
		t.Errorf("placeholder text does not name the attachments: %q", part.Text)
	}
}

func TestStream_SendsFileAttachmentsOverTheWire(t *testing.T) {
	var captured []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "data: {\"id\":\"x\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1}}\n\n")
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer server.Close()

	client := NewClientWithAdvancedOptions("test-key", "gpt-5.4", ClientOptions{
		Name:                "openai",
		BaseURL:             server.URL,
		ChatCompletionsPath: "/v1/relay/openai",
	})

	req := &provider.Request{
		Model:     "gpt-5.4",
		MaxTokens: 64,
		Messages: []internal.Message{{
			Role:    "user",
			Content: "summarize",
			Attachments: []internal.Attachment{
				{MediaType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", FileName: "memo.docx", Data: "ZG9j"},
			},
		}},
	}

	ch, err := client.Stream(context.Background(), req)
	if err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	for range ch { // drain so the request completes
	}

	if len(captured) == 0 {
		t.Fatal("server captured no request body")
	}

	var decoded struct {
		Messages []struct {
			Content []struct {
				Type string `json:"type"`
				File *struct {
					Filename string `json:"filename"`
					FileData string `json:"file_data"`
				} `json:"file"`
			} `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(captured, &decoded); err != nil {
		t.Fatalf("Unmarshal wire body error = %v\nbody: %s", err, string(captured))
	}

	var found bool
	for _, m := range decoded.Messages {
		for _, p := range m.Content {
			if p.Type == "file" && p.File != nil {
				found = true
				if p.File.Filename != "memo.docx" {
					t.Errorf("filename = %q, want memo.docx", p.File.Filename)
				}
				wantData := "data:application/vnd.openxmlformats-officedocument.wordprocessingml.document;base64,ZG9j"
				if p.File.FileData != wantData {
					t.Errorf("file_data = %q, want %q", p.File.FileData, wantData)
				}
			}
		}
	}
	if !found {
		t.Fatalf("wire payload missing file content part: %s", string(captured))
	}
}

func TestBuildAPIRequest_DoesNotSetPromptCacheKeyForVLLM(t *testing.T) {
	client := NewClientWithOptions("test-key", "gpt-5.4", "http://localhost:8000", "vllm")
	req := &provider.Request{Model: "gpt-5.4", MaxTokens: 256, PromptCacheKey: "sess_123"}

	apiReq := client.buildAPIRequest(req, true, req.MaxTokens)
	if apiReq.PromptCacheKey != "" {
		t.Fatalf("PromptCacheKey = %q, want empty", apiReq.PromptCacheKey)
	}

	body, err := json.Marshal(apiReq)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if jsonContainsAnyField(body, "prompt_cache_key") {
		t.Fatalf("serialized request unexpectedly included prompt_cache_key: %s", string(body))
	}
}

func TestBuildAPIRequest_DoesNotSet24hPromptCacheRetentionForUnsupportedOpenAIModels(t *testing.T) {
	client := NewClient("test-key", "gpt-5.4-nano")
	req := &provider.Request{Model: "gpt-5.4-nano", MaxTokens: 256}

	apiReq := client.buildAPIRequest(req, true, req.MaxTokens)
	if apiReq.PromptCacheRetention != "" {
		t.Fatalf("PromptCacheRetention = %q, want empty", apiReq.PromptCacheRetention)
	}

	body, err := json.Marshal(apiReq)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if jsonContainsAnyField(body, "prompt_cache_retention") {
		t.Fatalf("serialized request unexpectedly included prompt_cache_retention: %s", string(body))
	}
}

func TestBuildAPIRequest_DoesNotSet24hPromptCacheRetentionForVLLM(t *testing.T) {
	client := NewClientWithOptions("test-key", "gpt-5.4", "http://localhost:8000", "vllm")
	req := &provider.Request{Model: "gpt-5.4", MaxTokens: 256}

	apiReq := client.buildAPIRequest(req, true, req.MaxTokens)
	if apiReq.PromptCacheRetention != "" {
		t.Fatalf("PromptCacheRetention = %q, want empty", apiReq.PromptCacheRetention)
	}

	body, err := json.Marshal(apiReq)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if jsonContainsAnyField(body, "prompt_cache_retention") {
		t.Fatalf("serialized request unexpectedly included prompt_cache_retention: %s", string(body))
	}
}

func TestBuildAPIRequest_SerializesTemperature(t *testing.T) {
	client := NewClient("test-key", "gpt-5.4")
	req := &provider.Request{Model: "gpt-5.4", MaxTokens: 256, Temperature: 0.8}

	apiReq := client.buildAPIRequest(req, true, req.MaxTokens)
	if apiReq.Temperature != 0.8 {
		t.Fatalf("Temperature = %v, want 0.8", apiReq.Temperature)
	}

	body, err := json.Marshal(apiReq)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if !jsonContainsNumericField(body, "temperature", 0.8) {
		t.Fatalf("serialized request missing temperature=0.8: %s", string(body))
	}
}

func TestBuildAPIRequest_ReasoningReplayPolicyByProvider(t *testing.T) {
	// Default policy is to replay assistant reasoning_content back to the
	// provider; only providers on the forbid list have it stripped.
	cases := []struct {
		providerName string
		model        string
		wantReplay   bool
	}{
		{"moonshotai", "kimi-k2.6", true},
		{"deepseek", "deepseek-v4-pro", true},
		{"minimax", "minimax-m3", true},
		{"qwen", "qwen3.7-max", true},
		{"x-ai", "grok-4.5", true},
		{"z-ai", "glm-5.2", true},
		{"vllm", "local-model", true},
		{"anthropic", "claude-opus-4.8", true},
		{"OpenAI", "gpt-5.4", false}, // forbid list is case-insensitive
		{"openai", "gpt-5.4", false},
	}

	for _, tc := range cases {
		t.Run(tc.providerName, func(t *testing.T) {
			client := NewClientWithAdvancedOptions("test-key", tc.model, ClientOptions{Name: tc.providerName})
			req := &provider.Request{
				Messages: []internal.Message{{
					ID:               "msg_1",
					Role:             "assistant",
					ReasoningContent: "inspect files before tool use",
					ToolCalls: []internal.ToolCall{{
						ID:        "tasks:1",
						Name:      internal.ToolName("read_file"),
						Arguments: json.RawMessage(`{"path":"README.md"}`),
					}},
				}},
			}

			body, err := client.buildRequestBody(req)
			if err != nil {
				t.Fatalf("buildRequestBody() error = %v", err)
			}
			gotReplay := strings.Contains(string(body), `"reasoning_content":"inspect files before tool use"`)
			if gotReplay != tc.wantReplay {
				t.Fatalf("provider %q: reasoning_content replayed = %v, want %v; body: %s", tc.providerName, gotReplay, tc.wantReplay, string(body))
			}
		})
	}
}

func TestBuildAPIRequest_OmitsTemperatureForKimiProviders(t *testing.T) {
	// The gateway's Kimi provider ("moonshotai") carries the
	// fixed-temperature Kimi constraint and must omit temperature.
	for _, name := range []string{"moonshotai"} {
		t.Run(name, func(t *testing.T) {
			client := NewClientWithAdvancedOptions("test-key", "kimi-for-coding", ClientOptions{Name: name})
			req := &provider.Request{Model: "kimi-for-coding", MaxTokens: 256, Temperature: 0.5}

			apiReq := client.buildAPIRequest(req, true, req.MaxTokens)
			if apiReq.Temperature != 0 {
				t.Fatalf("Temperature = %v, want 0 (omitted): Kimi models reject any temperature != 1", apiReq.Temperature)
			}

			body, err := json.Marshal(apiReq)
			if err != nil {
				t.Fatalf("Marshal() error = %v", err)
			}
			var decoded map[string]any
			if err := json.Unmarshal(body, &decoded); err != nil {
				t.Fatalf("Unmarshal() error = %v", err)
			}
			if _, present := decoded["temperature"]; present {
				t.Fatalf("serialized %s request must omit temperature entirely: %s", name, string(body))
			}
		})
	}
}

func TestBuildAPIRequest_ReplayOmitsEmptyReasoningContent(t *testing.T) {
	// Assistant messages that never had reasoning must not grow an empty
	// reasoning_content field under the replay-by-default policy.
	client := NewClientWithAdvancedOptions("test-key", "deepseek-v4-pro", ClientOptions{Name: "deepseek"})
	req := &provider.Request{
		Messages: []internal.Message{{
			ID:      "msg_1",
			Role:    "assistant",
			Content: "plain answer with no thinking",
		}},
	}

	body, err := client.buildRequestBody(req)
	if err != nil {
		t.Fatalf("buildRequestBody() error = %v", err)
	}
	if strings.Contains(string(body), `"reasoning_content"`) {
		t.Fatalf("serialized request unexpectedly included empty reasoning_content: %s", string(body))
	}
}

func TestBuildAPIRequest_OmitsReasoningContentForStandardOpenAI(t *testing.T) {
	client := NewClient("test-key", "gpt-5.4")
	req := &provider.Request{
		Messages: []internal.Message{{
			ID:               "msg_1",
			Role:             "assistant",
			ReasoningContent: "keep internal reasoning out of standard chat history",
			Content:          "visible answer",
		}},
	}

	body, err := client.buildRequestBody(req)
	if err != nil {
		t.Fatalf("buildRequestBody() error = %v", err)
	}
	if strings.Contains(string(body), `"reasoning_content"`) {
		t.Fatalf("serialized request unexpectedly included reasoning_content: %s", string(body))
	}
}

func TestApplyRequestHeadersSetsAuthorization(t *testing.T) {
	client := NewClient("test-key", "gpt-5.4")
	httpReq, err := http.NewRequest(http.MethodPost, "https://example.com/v1/chat/completions", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}

	client.applyRequestHeaders(httpReq)

	if got := httpReq.Header.Get("Authorization"); got != "Bearer test-key" {
		t.Fatalf("Authorization = %q, want %q", got, "Bearer test-key")
	}
}

func jsonContainsField(body []byte, key, wantValue string) bool {
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		return false
	}
	value, ok := decoded[key].(string)
	return ok && value == wantValue
}

func jsonContainsAnyField(body []byte, key string) bool {
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		return false
	}
	_, ok := decoded[key]
	return ok
}

func jsonContainsNestedField(body []byte, path []string, wantValue string) bool {
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		return false
	}
	current := any(decoded)
	for _, key := range path {
		object, ok := current.(map[string]any)
		if !ok {
			return false
		}
		current, ok = object[key]
		if !ok {
			return false
		}
	}
	value, ok := current.(string)
	return ok && value == wantValue
}

func jsonContainsNumericField(body []byte, key string, wantValue float64) bool {
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		return false
	}
	value, ok := decoded[key].(float64)
	return ok && value == wantValue
}

func TestExtractReasoningTextFromStringField(t *testing.T) {
	delta := chunkDelta{ReasoningContent: json.RawMessage(`"step one"`)}
	if got := extractReasoningText(delta); got != "step one" {
		t.Fatalf("extractReasoningText() = %q, want %q", got, "step one")
	}
}

func TestExtractReasoningTextFromStructuredField(t *testing.T) {
	delta := chunkDelta{Reasoning: json.RawMessage(`[{"type":"summary_text","text":"alpha "},{"text":"beta"}]`)}
	if got := extractReasoningText(delta); got != "alpha beta" {
		t.Fatalf("extractReasoningText() = %q, want %q", got, "alpha beta")
	}
}

func TestExtractReasoningTextAddsBoundarySpacesForStructuredParts(t *testing.T) {
	delta := chunkDelta{ReasoningContent: json.RawMessage(`[{"text":"The"},{"text":"user"},{"text":"wants"},{"text":"tool calls."}]`)}
	if got := extractReasoningText(delta); got != "The user wants tool calls." {
		t.Fatalf("extractReasoningText() = %q, want %q", got, "The user wants tool calls.")
	}
}

func TestGetContextWindowIncludesGPT54(t *testing.T) {
	if got := provider.GetContextWindow("gpt-5.4"); got != 1_000_000 {
		t.Fatalf("GetContextWindow(gpt-5.4) = %d, want %d", got, int64(1_000_000))
	}
}

func newModelsTestServer(t *testing.T, payloadByPath map[string]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload, ok := payloadByPath[r.URL.RequestURI()]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(payload))
	}))
}

func TestContextWindowUsesModelsEndpointWhenAvailable(t *testing.T) {
	server := newModelsTestServer(t, map[string]string{
		"/v1/models?provider=minimax": `{"object":"list","data":[{"id":"MiniMax-M3","context_window":1000000}]}`,
	})
	defer server.Close()

	client := NewClientWithAdvancedOptions("test-key", "MiniMax-M3", ClientOptions{
		Name:       "minimax",
		BaseURL:    server.URL,
		ModelsPath: "/v1/models?provider=minimax",
	})

	got, err := client.ContextWindow(context.Background(), "MiniMax-M3")
	if err != nil {
		t.Fatalf("ContextWindow() error = %v", err)
	}
	if got != 1_000_000 {
		t.Fatalf("ContextWindow() = %d, want %d", got, int64(1_000_000))
	}
}

func TestContextWindowFallsBackToLocalRegistryWhenModelsEndpointMissing(t *testing.T) {
	server := newModelsTestServer(t, map[string]string{})
	defer server.Close()

	client := NewClientWithAdvancedOptions("test-key", "MiniMax-M3", ClientOptions{
		Name:       "minimax",
		BaseURL:    server.URL,
		ModelsPath: "/v1/models?provider=minimax",
	})

	got, err := client.ContextWindow(context.Background(), "MiniMax-M3")
	if err != nil {
		t.Fatalf("ContextWindow() error = %v", err)
	}
	if got != 1_000_000 {
		t.Fatalf("ContextWindow() = %d, want local fallback %d", got, int64(1_000_000))
	}
}

func TestReportedContextWindow(t *testing.T) {
	server := newModelsTestServer(t, map[string]string{
		"/v1/models?provider=minimax": `{"object":"list","data":[{"id":"MiniMax-M3","context_window":250000},{"id":"minimax-zero"}]}`,
	})
	defer server.Close()

	client := NewClientWithAdvancedOptions("test-key", "MiniMax-M3", ClientOptions{
		Name:       "minimax",
		BaseURL:    server.URL,
		ModelsPath: "/v1/models?provider=minimax",
	})

	// Catalog reports a positive window -> (value, true).
	if w, ok := client.ReportedContextWindow(context.Background(), "MiniMax-M3"); !ok || w != 250_000 {
		t.Fatalf("ReportedContextWindow(MiniMax-M3) = (%d, %v), want (250000, true)", w, ok)
	}
	// Catalog carries the model but no positive window -> (0, false), NO fallback.
	// This is what lets the switch safeguard tell an authoritative window from a guess.
	if w, ok := client.ReportedContextWindow(context.Background(), "minimax-zero"); ok || w != 0 {
		t.Fatalf("ReportedContextWindow(minimax-zero) = (%d, %v), want (0, false)", w, ok)
	}
	// Model absent from the catalog -> (0, false).
	if w, ok := client.ReportedContextWindow(context.Background(), "ghost-model"); ok || w != 0 {
		t.Fatalf("ReportedContextWindow(ghost-model) = (%d, %v), want (0, false)", w, ok)
	}
}

// A zero/absent catalog window must NOT change ContextWindow's behavior: it still
// falls back to the built-in registry, so compaction sizing is unaffected.
func TestContextWindowFallsBackWhenCatalogReportsZero(t *testing.T) {
	server := newModelsTestServer(t, map[string]string{
		"/v1/models?provider=minimax": `{"object":"list","data":[{"id":"MiniMax-M3"}]}`,
	})
	defer server.Close()

	client := NewClientWithAdvancedOptions("test-key", "MiniMax-M3", ClientOptions{
		Name:       "minimax",
		BaseURL:    server.URL,
		ModelsPath: "/v1/models?provider=minimax",
	})

	got, err := client.ContextWindow(context.Background(), "MiniMax-M3")
	if err != nil {
		t.Fatalf("ContextWindow() error = %v", err)
	}
	if got != 1_000_000 {
		t.Fatalf("ContextWindow() = %d, want registry fallback %d", got, int64(1_000_000))
	}
}

func TestParseSSE_PreservesCachedTokensOnFinalChoiceUsageChunk(t *testing.T) {
	client := NewClient("test-key", "gpt-5.4-mini")
	body := "data: {\"id\":\"chatcmpl-123\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":43789,\"completion_tokens\":167,\"prompt_tokens_details\":{\"cached_tokens\":43616}}}\n\n"
	resp := &http.Response{Body: io.NopCloser(bufio.NewReader(strings.NewReader(body)))}
	ctx := context.Background()
	ch := make(chan provider.StreamEvent, 8)

	go client.parseSSE(ctx, resp, ch)

	var done *provider.Usage
	for event := range ch {
		if event.Type == provider.EventDone {
			done = event.Usage
		}
	}

	if done == nil {
		t.Fatal("expected done usage event")
	}
	if done.InputTokens != 173 {
		t.Fatalf("InputTokens = %d, want %d", done.InputTokens, int64(173))
	}
	if done.OutputTokens != 167 {
		t.Fatalf("OutputTokens = %d, want %d", done.OutputTokens, int64(167))
	}
	if done.CacheReadInputTokens != 43616 {
		t.Fatalf("CacheReadInputTokens = %d, want %d", done.CacheReadInputTokens, int64(43616))
	}
}

func TestParseSSE_PreservesCacheWriteTokensOnFinalChoiceUsageChunk(t *testing.T) {
	client := NewClient("test-key", "claude-sonnet-4.6")
	body := "data: {\"id\":\"chatcmpl-123\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":5000,\"completion_tokens\":120,\"prompt_tokens_details\":{\"cached_tokens\":0,\"cache_write_tokens\":4096}}}\n\n"
	resp := &http.Response{Body: io.NopCloser(bufio.NewReader(strings.NewReader(body)))}
	ctx := context.Background()
	ch := make(chan provider.StreamEvent, 8)

	go client.parseSSE(ctx, resp, ch)

	var done *provider.Usage
	for event := range ch {
		if event.Type == provider.EventDone {
			done = event.Usage
		}
	}

	if done == nil {
		t.Fatal("expected done usage event")
	}
	if done.InputTokens != 904 {
		t.Fatalf("InputTokens = %d, want %d", done.InputTokens, int64(904))
	}
	if done.OutputTokens != 120 {
		t.Fatalf("OutputTokens = %d, want %d", done.OutputTokens, int64(120))
	}
	if done.CacheCreationInputTokens != 4096 {
		t.Fatalf("CacheCreationInputTokens = %d, want %d", done.CacheCreationInputTokens, int64(4096))
	}
	if done.CacheReadInputTokens != 0 {
		t.Fatalf("CacheReadInputTokens = %d, want 0", done.CacheReadInputTokens)
	}
}

func TestParseSSE_ToolCallsEndTurnBeforeTransportEOF(t *testing.T) {
	client := NewClient("test-key", "gpt-5.4-mini")
	body := strings.Join([]string{
		"data: {\"id\":\"chatcmpl-123\",\"choices\":[{\"index\":0,\"delta\":{\"reasoning_content\":\"thinking\"},\"finish_reason\":null}]}",
		"",
		"data: {\"id\":\"chatcmpl-123\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"type\":\"function\",\"function\":{\"name\":\"read_file\",\"arguments\":\"{\\\"path\\\":\\\"README.md\\\"}\"}}]},\"finish_reason\":\"tool_calls\"}]}",
		"",
		"data: {\"id\":\"chatcmpl-123\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"should not be seen\"},\"finish_reason\":null}]}",
		"",
	}, "\n")
	resp := &http.Response{Body: io.NopCloser(bufio.NewReader(strings.NewReader(body)))}
	ctx := context.Background()
	ch := make(chan provider.StreamEvent, 8)

	go client.parseSSE(ctx, resp, ch)

	var events []provider.StreamEvent
	var deltas []provider.StreamEvent
	for event := range ch {
		if event.Type == provider.EventToolUseDelta {
			deltas = append(deltas, event)
			continue
		}
		events = append(events, event)
	}

	// The live tool-call deltas stream the arguments as they arrive; they do
	// not change the authoritative sequence asserted below.
	if len(deltas) == 0 {
		t.Fatal("expected at least one tool-use delta event")
	}
	for _, d := range deltas {
		if d.ToolCall == nil || d.ToolCall.ID != "call_1" {
			t.Fatalf("delta event = %#v, want tool-use delta for call_1", d)
		}
	}

	if len(events) != 3 {
		t.Fatalf("event count = %d, want 3", len(events))
	}
	if events[0].Type != provider.EventToken || events[0].Channel != provider.ChannelReasoning || events[0].Content != "thinking" {
		t.Fatalf("first event = %#v, want reasoning token", events[0])
	}
	if events[1].Type != provider.EventToolUse || events[1].ToolCall == nil || events[1].ToolCall.ID != "call_1" {
		t.Fatalf("second event = %#v, want tool use for call_1", events[1])
	}
	if events[2].Type != provider.EventDone {
		t.Fatalf("third event = %#v, want done event", events[2])
	}
}

func TestParseSSE_WaitsForUsageOnlyChunkAfterStop(t *testing.T) {
	client := NewClient("test-key", "gpt-5.4-mini")
	body := strings.Join([]string{
		"data: {\"id\":\"chatcmpl-123\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hi!\"},\"finish_reason\":null}]}",
		"",
		"data: {\"id\":\"chatcmpl-123\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}",
		"",
		"data: {\"id\":\"chatcmpl-123\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"should not be seen\"},\"finish_reason\":null}]}",
		"",
		"data: {\"id\":\"chatcmpl-123\",\"choices\":[],\"usage\":{\"prompt_tokens\":19081,\"completion_tokens\":35,\"prompt_tokens_details\":{\"cached_tokens\":0}}}",
		"",
	}, "\n")
	resp := &http.Response{Body: io.NopCloser(bufio.NewReader(strings.NewReader(body)))}
	ctx := context.Background()
	ch := make(chan provider.StreamEvent, 8)

	go client.parseSSE(ctx, resp, ch)

	var events []provider.StreamEvent
	for event := range ch {
		events = append(events, event)
	}

	if len(events) != 2 {
		t.Fatalf("event count = %d, want 2", len(events))
	}
	if events[0].Type != provider.EventToken || events[0].Content != "Hi!" {
		t.Fatalf("first event = %#v, want token event", events[0])
	}
	if events[1].Type != provider.EventDone || events[1].Usage == nil {
		t.Fatalf("second event = %#v, want done event with usage", events[1])
	}
	if events[1].Usage.InputTokens != 19081 {
		t.Fatalf("InputTokens = %d, want %d", events[1].Usage.InputTokens, int64(19081))
	}
	if events[1].Usage.OutputTokens != 35 {
		t.Fatalf("OutputTokens = %d, want %d", events[1].Usage.OutputTokens, int64(35))
	}
}

// streamToolArgsForTest drives a full SSE body through Stream() against an
// OpenRouter-style endpoint and returns the final accumulated tool-call args.
func streamToolArgsForTest(t *testing.T, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	c := NewClientWithAdvancedOptions("k", "anthropic/claude-opus-4", ClientOptions{
		BaseURL:             srv.URL,
		Name:                "openrouter",
		ChatCompletionsPath: "/api/v1/chat/completions",
	})
	ch, err := c.Stream(context.Background(), &provider.Request{Messages: []internal.Message{}})
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	var args string
	for ev := range ch {
		if ev.Type == provider.EventError {
			t.Fatalf("unexpected stream error: %v", ev.Error)
		}
		if ev.Type == provider.EventToolUse && ev.ToolCall != nil {
			args = ev.ToolCall.Arguments
		}
	}
	return args
}

// TestParseSSE_ToolArgsSurviveMissingDataSpace guards against a regression where
// a streamed tool-call argument fragment was silently dropped because its
// `data:` line lacked the optional space after the colon. The SSE field is
// `data` regardless of that space; dropping the line corrupted the accumulated
// arguments (e.g. losing the opening `{"` so they began with a bare `s`, which
// surfaced downstream as `invalid character 's' looking for beginning of value`).
func TestParseSSE_ToolArgsSurviveMissingDataSpace(t *testing.T) {
	body := strings.Join([]string{
		`: OPENROUTER PROCESSING`,
		``,
		`data: {"id":"gen-x","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"toolu_x","type":"function","function":{"name":"create_definition","arguments":""}}]},"finish_reason":null}]}`,
		``,
		// First argument fragment carries the opening `{"`, sent WITHOUT the
		// space after `data:`. Pre-fix this line was skipped entirely.
		`data:{"id":"gen-x","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\""}}]},"finish_reason":null}]}`,
		``,
		`data: {"id":"gen-x","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"snippet\":\"hi\"}"}}]},"finish_reason":null}]}`,
		``,
		`data: {"id":"gen-x","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`,
		``,
		`data: [DONE]`,
		``,
	}, "\n")

	args := streamToolArgsForTest(t, body)
	if !json.Valid([]byte(args)) {
		t.Fatalf("accumulated tool args not valid JSON: %q", args)
	}
	var params struct {
		Snippet string `json:"snippet"`
	}
	if err := json.Unmarshal([]byte(args), &params); err != nil {
		t.Fatalf("unmarshal args: %v (args=%q)", err, args)
	}
	if params.Snippet != "hi" {
		t.Fatalf("snippet = %q, want %q (args=%q)", params.Snippet, "hi", args)
	}
}

// TestParseSSE_ToolArgsSurviveMultiLineDataField guards against a regression
// where a single SSE event whose `data:` payload was split across multiple
// lines (which the spec says to join with "\n") aborted the stream on half a
// JSON object instead of reassembling it.
func TestParseSSE_ToolArgsSurviveMultiLineDataField(t *testing.T) {
	full := `data: {"id":"gen-x","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"toolu_x","type":"function","function":{"name":"create_definition","arguments":"{\"snippet\":\"hi\"}"}}]},"finish_reason":null}]}`
	splitAt := strings.Index(full, `"choices"`)
	body := strings.Join([]string{
		full[:splitAt],            // first physical line: incomplete JSON
		"data: " + full[splitAt:], // continuation as a second data: line
		``,
		`data: {"id":"gen-x","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`,
		``,
		`data: [DONE]`,
		``,
	}, "\n")

	args := streamToolArgsForTest(t, body)
	if !json.Valid([]byte(args)) {
		t.Fatalf("accumulated tool args not valid JSON: %q", args)
	}
	var params struct {
		Snippet string `json:"snippet"`
	}
	if err := json.Unmarshal([]byte(args), &params); err != nil {
		t.Fatalf("unmarshal args: %v (args=%q)", err, args)
	}
	if params.Snippet != "hi" {
		t.Fatalf("snippet = %q, want %q (args=%q)", params.Snippet, "hi", args)
	}
}

func newKimiTestClient(model string) *Client {
	return NewClientWithAdvancedOptions("test-key", model, ClientOptions{Name: "moonshotai"})
}

func TestKimiReasoningForModel(t *testing.T) {
	cases := []struct {
		name       string
		model      string
		mode       string
		wantEffort string
		wantThink  string // apiThinking.Type, "" = nil thinking
	}{
		{"default is a no-op", "kimi-k2.6", "", "", ""},
		{"explicit default is a no-op", "kimi-k2.6", "default", "", ""},
		{"k3 on -> reasoning_effort max", "kimi-k3", "on", "max", ""},
		{"k3 off -> nothing (no disable on k3)", "kimi-k3", "off", "", ""},
		{"coding on -> thinking enabled", "kimi-for-coding", "on", "", "enabled"},
		{"coding off -> no-op (always thinks)", "kimi-for-coding", "off", "", ""},
		{"k2.7-code off -> no-op (always thinks)", "kimi-k2.7-code", "off", "", ""},
		{"k2.6 on -> thinking enabled", "kimi-k2.6", "on", "", "enabled"},
		{"k2.6 off -> thinking disabled", "kimi-k2.6", "off", "", "disabled"},
		{"k2.5 off -> thinking disabled", "kimi-k2.5", "off", "", "disabled"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			effort, thinking := kimiReasoningForModel(tc.model, tc.mode)
			if effort != tc.wantEffort {
				t.Fatalf("effort = %q, want %q", effort, tc.wantEffort)
			}
			if tc.wantThink == "" {
				if thinking != nil {
					t.Fatalf("thinking = %+v, want nil", thinking)
				}
			} else {
				if thinking == nil || thinking.Type != tc.wantThink {
					t.Fatalf("thinking = %+v, want type %q", thinking, tc.wantThink)
				}
			}
		})
	}
}

func TestBuildAPIRequest_KimiReasoningOnCodingSendsThinkingNotEffort(t *testing.T) {
	client := newKimiTestClient("kimi-for-coding")
	req := &provider.Request{Model: "kimi-for-coding", MaxTokens: 256, ReasoningEffort: "on"}
	apiReq := client.buildAPIRequest(req, true, req.MaxTokens)

	if apiReq.Thinking == nil || apiReq.Thinking.Type != "enabled" {
		t.Fatalf("Thinking = %+v, want type=enabled", apiReq.Thinking)
	}
	if apiReq.ReasoningEffort != "" {
		t.Fatalf("ReasoningEffort = %q, want empty (coding uses thinking, not effort)", apiReq.ReasoningEffort)
	}
	body, err := json.Marshal(apiReq)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if !strings.Contains(string(body), `"thinking":{"type":"enabled"}`) {
		t.Fatalf("serialized request missing thinking object: %s", string(body))
	}
	if strings.Contains(string(body), "reasoning_effort") {
		t.Fatalf("serialized request should not carry reasoning_effort for coding model: %s", string(body))
	}
}

func TestBuildAPIRequest_KimiReasoningOnK3SendsMaxEffort(t *testing.T) {
	client := newKimiTestClient("kimi-k3")
	req := &provider.Request{Model: "kimi-k3", MaxTokens: 256, ReasoningEffort: "on"}
	apiReq := client.buildAPIRequest(req, true, req.MaxTokens)

	if apiReq.ReasoningEffort != "max" {
		t.Fatalf("ReasoningEffort = %q, want max", apiReq.ReasoningEffort)
	}
	if apiReq.Thinking != nil {
		t.Fatalf("Thinking = %+v, want nil for k3", apiReq.Thinking)
	}
}

func TestBuildAPIRequest_KimiReasoningDefaultSendsNeither(t *testing.T) {
	client := newKimiTestClient("kimi-for-coding")
	req := &provider.Request{Model: "kimi-for-coding", MaxTokens: 256}
	apiReq := client.buildAPIRequest(req, true, req.MaxTokens)

	if apiReq.ReasoningEffort != "" || apiReq.Thinking != nil {
		t.Fatalf("expected no reasoning params, got effort=%q thinking=%+v", apiReq.ReasoningEffort, apiReq.Thinking)
	}
}

func TestBuildAPIRequest_NonKimiKeepsReasoningEffortPassthrough(t *testing.T) {
	client := NewClientWithAdvancedOptions("test-key", "gpt-5.4", ClientOptions{Name: "openai"})
	req := &provider.Request{Model: "gpt-5.4", MaxTokens: 256, ReasoningEffort: "high"}
	apiReq := client.buildAPIRequest(req, true, req.MaxTokens)

	if apiReq.ReasoningEffort != "high" {
		t.Fatalf("ReasoningEffort = %q, want high (passthrough)", apiReq.ReasoningEffort)
	}
	if apiReq.Thinking != nil {
		t.Fatalf("Thinking = %+v, want nil for non-Kimi", apiReq.Thinking)
	}
}

func TestDeepseekReasoning(t *testing.T) {
	cases := []struct {
		level        string
		wantEffort   string
		wantThinking string // "" means nil
	}{
		// DeepSeek takes low/high/max. Both the effort and the thinking mode go
		// on the wire.
		{"", "", ""},
		{"default", "", ""},
		{"none", "", "disabled"},
		{"off", "", "disabled"},
		{"minimal", "low", "enabled"},
		{"low", "low", "enabled"},
		{"medium", "high", "enabled"},
		{"high", "high", "enabled"},
		// xhigh is OpenRouter's spelling of the top rung; DeepSeek would map it
		// down to high, so it must be translated to max rather than forwarded.
		{"xhigh", "max", "enabled"},
		{"max", "max", "enabled"},
		{"  XHigh  ", "max", "enabled"},
	}
	for _, tc := range cases {
		effort, thinking := deepseekReasoning(tc.level)
		if effort != tc.wantEffort {
			t.Errorf("deepseekReasoning(%q) effort = %q, want %q", tc.level, effort, tc.wantEffort)
		}
		got := ""
		if thinking != nil {
			got = thinking.Type
		}
		if got != tc.wantThinking {
			t.Errorf("deepseekReasoning(%q) thinking = %q, want %q", tc.level, got, tc.wantThinking)
		}
	}
}

func TestBuildAPIRequest_DeepSeekReasoningIsProviderBound(t *testing.T) {
	// Every model under the deepseek provider gets the same treatment, including
	// ones this build has never heard of.
	for _, model := range []string{"deepseek-v4-flash", "deepseek-v4-pro", "deepseek-v9-unknown"} {
		client := NewClientWithAdvancedOptions("test-key", model, ClientOptions{Name: "deepseek"})
		req := &provider.Request{Model: model, MaxTokens: 256, ReasoningEffort: "max"}
		apiReq := client.buildAPIRequest(req, true, req.MaxTokens)

		if apiReq.ReasoningEffort != "max" {
			t.Errorf("%s: ReasoningEffort = %q, want max", model, apiReq.ReasoningEffort)
		}
		if apiReq.Thinking == nil || apiReq.Thinking.Type != "enabled" {
			t.Errorf("%s: Thinking = %+v, want enabled", model, apiReq.Thinking)
		}
	}
}

func TestBuildAPIRequest_DeepSeekModelOnAnotherProviderKeepsPassthrough(t *testing.T) {
	// The binding is on the provider, not the model id: a deepseek-named model
	// relayed by openrouter must not be rewritten.
	client := NewClientWithAdvancedOptions("test-key", "deepseek/deepseek-v4-pro", ClientOptions{Name: "openrouter"})
	req := &provider.Request{Model: "deepseek/deepseek-v4-pro", MaxTokens: 256, ReasoningEffort: "medium"}
	apiReq := client.buildAPIRequest(req, true, req.MaxTokens)

	if apiReq.ReasoningEffort != "medium" {
		t.Fatalf("ReasoningEffort = %q, want medium (passthrough)", apiReq.ReasoningEffort)
	}
	if apiReq.Thinking != nil {
		t.Fatalf("Thinking = %+v, want nil for a non-deepseek provider", apiReq.Thinking)
	}
}

func TestBuildAPIRequest_KimiPerTaskDefaultSendsNeither(t *testing.T) {
	// There is no operator-level default any more: a per-task "default" is a
	// no-op and sends no reasoning parameters.
	client := newKimiTestClient("kimi-k2.6")
	req := &provider.Request{Model: "kimi-k2.6", MaxTokens: 256, ReasoningEffort: "default"}
	apiReq := client.buildAPIRequest(req, true, req.MaxTokens)

	if apiReq.ReasoningEffort != "" || apiReq.Thinking != nil {
		t.Fatalf("expected no reasoning params, got effort=%q thinking=%+v", apiReq.ReasoningEffort, apiReq.Thinking)
	}
}

func TestKimiReasoningForModel_NormalizesLadderTokens(t *testing.T) {
	// Ladder tokens from the generic effort picker still map: any non-off value
	// means thinking on; k3 → max.
	if _, th := kimiReasoningForModel("kimi-k2.6", "high"); th == nil || th.Type != "enabled" {
		t.Fatalf("k2.6 high: thinking = %+v, want enabled", th)
	}
	if eff, _ := kimiReasoningForModel("kimi-k3", "medium"); eff != "max" {
		t.Fatalf("k3 medium: effort = %q, want max", eff)
	}
	if _, th := kimiReasoningForModel("kimi-k2.6", "none"); th == nil || th.Type != "disabled" {
		t.Fatalf("k2.6 none: thinking = %+v, want disabled (none = off)", th)
	}
	// Coding models can't disable — off must be a no-op there.
	if eff, th := kimiReasoningForModel("kimi-for-coding", "none"); eff != "" || th != nil {
		t.Fatalf("coding none: effort=%q thinking=%+v, want both empty (coding always thinks)", eff, th)
	}
}

// TestBuildAPIRequest_SanitizesTruncatedToolArguments reproduces the reported
// failure: a prior assistant turn stored a tool call whose arguments were
// truncated mid-string (the model was cut off), and replaying it made
// xAI/Grok 400 the whole request with "Invalid tool arguments received ...
// EOF while parsing a string". The OpenAI-compatible wire format encodes the
// arguments as a JSON *string*, so the request marshals fine even when broken;
// the provider fails only when it parses that string as the tool arguments.
// After the fix the replayed arguments must themselves be valid JSON.
func TestBuildAPIRequest_SanitizesTruncatedToolArguments(t *testing.T) {
	client := NewClientWithAdvancedOptions("test-key", "grok-4.5", ClientOptions{Name: "x-ai"})
	req := &provider.Request{
		Messages: []internal.Message{{
			ID:   "msg_1",
			Role: "assistant",
			ToolCalls: []internal.ToolCall{{
				ID:   "call_truncated",
				Name: internal.ToolName("run_shell"),
				// Truncated mid-string: no closing quote or brace.
				Arguments: json.RawMessage(`{"command":"find backend && go build ./... 2>`),
			}},
		}},
	}

	body, err := client.buildRequestBody(req)
	if err != nil {
		t.Fatalf("buildRequestBody() error = %v", err)
	}

	// Decode the wire body the way the provider does and pull out the replayed
	// tool-call arguments string.
	var wire struct {
		Messages []struct {
			ToolCalls []struct {
				Function struct {
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		t.Fatalf("unmarshal wire body: %v; body: %s", err, string(body))
	}

	var args string
	for _, m := range wire.Messages {
		for _, tc := range m.ToolCalls {
			args = tc.Function.Arguments
		}
	}
	if args == "" {
		t.Fatalf("no tool-call arguments found on the wire; body: %s", string(body))
	}
	// This is the exact parse xAI performs and that was failing before the fix.
	if !json.Valid([]byte(args)) {
		t.Fatalf("replayed tool arguments are not valid JSON (would 400 upstream): %q", args)
	}
	if args != "{}" {
		t.Fatalf("truncated arguments should be repaired to {}, got %q", args)
	}
}

// TestBuildAPIRequest_PreservesValidToolArguments guards against the fix
// mangling healthy tool calls — valid arguments must ride through untouched.
func TestBuildAPIRequest_PreservesValidToolArguments(t *testing.T) {
	client := NewClientWithAdvancedOptions("test-key", "grok-4.5", ClientOptions{Name: "x-ai"})
	req := &provider.Request{
		Messages: []internal.Message{{
			ID:   "msg_1",
			Role: "assistant",
			ToolCalls: []internal.ToolCall{{
				ID:        "call_ok",
				Name:      internal.ToolName("read_file"),
				Arguments: json.RawMessage(`{"path":"backend/main.go"}`),
			}},
		}},
	}

	body, err := client.buildRequestBody(req)
	if err != nil {
		t.Fatalf("buildRequestBody() error = %v", err)
	}
	if !strings.Contains(string(body), `{\"path\":\"backend/main.go\"}`) {
		t.Fatalf("valid tool arguments were not preserved verbatim; body: %s", string(body))
	}
}

func TestParseSSE_ReportsTruncatedStream(t *testing.T) {
	// Reasoning streams, then the connection closes with no finish_reason and
	// no [DONE]. Pre-fix this returned silently: the agent loop saw the channel
	// close, treated the partial text as a finished turn with zero usage and no
	// tool calls, and continued from truncated reasoning.
	client := NewClient("test-key", "gpt-5.4-mini")
	body := "data: {\"id\":\"chatcmpl-123\",\"choices\":[{\"index\":0,\"delta\":{\"reasoning\":\"thinking hard abo\"}}]}\n\n"
	resp := &http.Response{Body: io.NopCloser(bufio.NewReader(strings.NewReader(body)))}
	ch := make(chan provider.StreamEvent, 8)

	go client.parseSSE(context.Background(), resp, ch)

	var sawError, sawDone bool
	for event := range ch {
		switch event.Type {
		case provider.EventError:
			sawError = true
			if !strings.Contains(event.Error.Error(), "truncated") {
				t.Fatalf("error = %v, want it to mention truncation", event.Error)
			}
		case provider.EventDone:
			sawDone = true
		}
	}

	if !sawError {
		t.Fatal("truncated stream produced no error event")
	}
	if sawDone {
		t.Fatal("truncated stream must not report a successful done event")
	}
}

// OpenRouter reports each call's cost only when asked (usage.include), as
// usage.cost; without it the daily budget would count OpenRouter as free.
func TestOpenRouterUsageCost(t *testing.T) {
	or := NewClientWithAdvancedOptions("test-key", "deepseek/deepseek-v4-flash", ClientOptions{Name: "openrouter"})
	body, err := or.buildRequestBody(&provider.Request{Messages: []internal.Message{{ID: "m1", Role: "user", Content: "hi"}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"usage":{"include":true}`) {
		t.Fatalf("openrouter request does not ask for usage accounting: %s", body)
	}
	other := NewClientWithAdvancedOptions("test-key", "glm-5.3-flash", ClientOptions{Name: "z-ai"})
	if body, _ := other.buildRequestBody(&provider.Request{Messages: []internal.Message{{ID: "m1", Role: "user", Content: "hi"}}}); strings.Contains(string(body), `"usage"`) {
		t.Fatalf("usage accounting sent to a non-OpenRouter provider: %s", body)
	}

	sse := "data: {\"id\":\"gen-1\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":1000,\"completion_tokens\":100,\"cost\":0.00042}}\n\n"
	ch := make(chan provider.StreamEvent, 8)
	go or.parseSSE(context.Background(), &http.Response{Body: io.NopCloser(strings.NewReader(sse))}, ch)
	var done *provider.Usage
	for event := range ch {
		if event.Type == provider.EventDone {
			done = event.Usage
		}
	}
	if done == nil || done.Cost == nil || done.Cost.BilledTotalUSD != 0.00042 {
		t.Fatalf("cost not read: %+v", done)
	}
}
