package openai

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Problem99-io/kodeblue/internal/provider"
)

func TestParseSSEPreservesUpstreamError(t *testing.T) {
	for _, tc := range []struct{ name, data, want string }{
		{"error envelope", `{"error":{"message":"Invalid tool arguments","code":"invalid_request_error","metadata":{"raw":"private diagnostic"}}}`, "Invalid tool arguments"},
		{"string error", `{"error":"upstream unavailable"}`, "upstream unavailable"},
		{"terminal error", `{"choices":[{"delta":{},"finish_reason":"error"}]}`, "finish_reason=error"},
		{"filtered", `{"choices":[{"delta":{},"finish_reason":"content_filter"}]}`, "finish_reason=content_filter"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := NewClient("unused", "fixture")
			response := &http.Response{Body: io.NopCloser(strings.NewReader("data: " + tc.data + "\n\n"))}
			events := make(chan provider.StreamEvent, 8)
			go c.parseSSE(context.Background(), response, events)
			var errors, done int
			for event := range events {
				if event.Type == provider.EventDone {
					done++
				}
				if event.Type == provider.EventError {
					errors++
					if !strings.Contains(event.Error.Error(), tc.want) {
						t.Errorf("lost upstream cause: %v", event.Error)
					}
					if strings.Contains(event.Error.Error(), "private diagnostic") {
						t.Error("exposed upstream metadata")
					}
				}
			}
			if errors != 1 || done != 0 {
				t.Fatalf("errors=%d done=%d", errors, done)
			}
		})
	}
}

func TestParseSSEHealthyRelayFinishWithTrailingUsage(t *testing.T) {
	c := NewClient("unused", "fixture")
	data := "data: {\"choices\":[{\"delta\":{\"content\":\"OK\"},\"finish_reason\":null}]}\n\n" +
		"data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n" +
		"data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":5}}\n\n" +
		"data: [DONE]\n\n"
	events := make(chan provider.StreamEvent, 8)
	go c.parseSSE(context.Background(), &http.Response{Body: io.NopCloser(strings.NewReader(data))}, events)
	var text string
	var done int
	for event := range events {
		switch event.Type {
		case provider.EventToken:
			text += event.Content
		case provider.EventError:
			t.Fatal(event.Error)
		case provider.EventDone:
			done++
			if event.Usage == nil || event.Usage.OutputTokens != 5 {
				t.Fatalf("lost usage: %+v", event.Usage)
			}
		}
	}
	if text != "OK" || done != 1 {
		t.Fatalf("text=%q done=%d", text, done)
	}
}

func TestParseSSEPreservesRateLimitCode(t *testing.T) {
	for _, code := range []string{`429`, `"429"`, `"rate_limit_exceeded"`} {
		data := `data: {"error":{"code":` + code + `,"message":"temporarily rate-limited upstream","metadata":{"raw":"private request"}}}` + "\n\n"
		events := make(chan provider.StreamEvent, 8)
		go NewClient("unused", "fixture").parseSSE(context.Background(), &http.Response{Body: io.NopCloser(strings.NewReader(data))}, events)
		count := 0
		for event := range events {
			var streamErr *provider.StreamError
			if event.Type != provider.EventError || !errors.As(event.Error, &streamErr) {
				t.Fatalf("expected structured stream error: %+v", event)
			}
			if streamErr.Code != strings.Trim(code, "\"") || streamErr.Message != "temporarily rate-limited upstream" {
				t.Fatalf("lost details: %+v", streamErr)
			}
			if strings.Contains(streamErr.Error(), "private request") {
				t.Fatal("leaked metadata")
			}
			count++
		}
		if count != 1 {
			t.Fatalf("events=%d", count)
		}
	}
}

func TestStreamDiagnosticsRetainResponseIdentifiers(t *testing.T) {
	for _, tc := range []struct{ name, body, class, code string }{
		{"upstream error", "data: {\"error\":{\"code\":429,\"message\":\"PRIVATE PROMPT token=secret\",\"metadata\":{\"raw\":\"PRIVATE BODY\"}}}\n\n", "rate_limit", "429"},
		{"truncated stream", "", "stream_truncated", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest("POST", "https://user:password@gateway.example/private?token=secret", nil)
			response := &http.Response{Request: req, StatusCode: 200, Header: http.Header{"X-Request-Id": []string{"req-stream"}}, Body: io.NopCloser(strings.NewReader(tc.body))}
			events := make(chan provider.StreamEvent, 8)
			go NewClient("unused", "fixture").parseSSE(context.Background(), response, events)
			count := 0
			for event := range events {
				if event.Type != provider.EventError {
					continue
				}
				count++
				d := provider.DiagnoseFailure(event.Error)
				if d.Class != tc.class || d.UpstreamCode != tc.code || d.EndpointHost != "gateway.example" || d.RequestID != "req-stream" || d.HTTPStatus != 200 {
					t.Fatalf("diagnostics=%+v", d)
				}
				if strings.Contains(provider.FailureReason(event.Error), "PRIVATE") {
					t.Fatal("leaked provider body")
				}
			}
			if count != 1 {
				t.Fatalf("errors=%d", count)
			}
		})
	}
}
