package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFailureDiagnosticsClassifyWithoutEchoingProviderData(t *testing.T) {
	for _, tc := range []struct {
		name        string
		err         error
		class, code string
		status      int
	}{
		{"stream rate limit", &StreamError{Code: "rate_limit_exceeded", Message: "temporarily rate-limited upstream PRIVATE PROMPT token=private"}, "rate_limit", "rate_limit_exceeded", 0},
		{"numeric stream status", &StreamError{Code: "429", Message: "PRIVATE PROMPT"}, "rate_limit", "429", 0},
		{"nested relay status", &APIStatusError{StatusCode: 503, Body: openRouterRateLimitBody}, "rate_limit", "429", 503},
		{"overload", &StreamError{Code: "overloaded_error", Message: "PRIVATE PROMPT"}, "overloaded", "overloaded_error", 0},
		{"bad credentials", &APIStatusError{StatusCode: 401, Body: `{"error":{"type":"authentication_error","message":"PRIVATE PROMPT sk-private-key"}}`}, "authentication", "authentication_error", 401},
		{"quota", &APIStatusError{StatusCode: 429, Body: `{"error":"quota exceeded","private":"PRIVATE PROMPT"}`}, "quota_exceeded", "", 429},
		{"timeout", fmt.Errorf("send failed: %w", context.DeadlineExceeded), "timeout", "", 0},
		{"reset", errors.New("connection reset by peer PRIVATE PROMPT"), "connection_reset", "", 0},
		{"EOF", fmt.Errorf("stream read: %w", io.ErrUnexpectedEOF), "stream_truncated", "", 0},
		{"unknown code", &StreamError{Code: "PRIVATE PROMPT sk-private-key", Message: "PRIVATE PROMPT"}, "upstream_stream_error", "", 0},
		{"unknown failure", errors.New("PRIVATE PROMPT {raw provider body} password=private"), "provider_error", "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := DiagnoseFailure(tc.err)
			if d.Class != tc.class || d.UpstreamCode != tc.code || d.HTTPStatus != tc.status {
				t.Fatalf("diagnostic=%+v", d)
			}
			raw, _ := json.Marshal(FailureFields(tc.err))
			for _, forbidden := range []string{"PRIVATE PROMPT", "sk-private-key", "password=private", "raw provider body", "metadata", "details"} {
				if strings.Contains(string(raw), forbidden) {
					t.Fatalf("diagnostics leaked %q: %s", forbidden, raw)
				}
			}
		})
	}
}

func TestSendPreservesResponseIdentifiersAndRetryBudget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Request-ID", "req-last-429")
		w.WriteHeader(429)
		_, _ = w.Write([]byte(`{"error":{"code":"rate_limit_exceeded","message":"PRIVATE PROMPT token=secret"},"metadata":{"raw":"PRIVATE BODY"}}`))
	}))
	defer srv.Close()
	_, err := Send(context.Background(), RetryOptions{Provider: "test", Client: srv.Client(), Attempts: 2, BaseDelay: time.Millisecond, NewRequest: func(ctx context.Context) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, "POST", srv.URL+"/private-path?token=secret", strings.NewReader("PRIVATE REQUEST"))
	}})
	d := DiagnoseFailure(err)
	if d.RequestID != "req-last-429" || d.EndpointHost != "127.0.0.1" || d.HTTPStatus != 429 || d.UpstreamCode != "rate_limit_exceeded" || d.Attempt != 2 || d.MaxAttempts != 2 || d.RetryElapsedMS < 1 {
		t.Fatalf("diagnostic=%+v", d)
	}
	raw, _ := json.Marshal(d)
	for _, private := range []string{"PRIVATE", "secret", "private-path", "token", srv.URL} {
		if strings.Contains(string(raw), private) {
			t.Fatalf("leaked %q: %s", private, raw)
		}
	}
}

func TestResponseDiagnosticsPreserveHandshakeStatusAndUnderlyingError(t *testing.T) {
	req, _ := http.NewRequest("POST", "https://user:password@gateway.example/private?token=secret", nil)
	resp := &http.Response{StatusCode: 200, Request: req, Header: http.Header{"Request-Id": []string{"req-stream"}}}
	cause := &StreamError{Code: "429", Message: "PRIVATE PROMPT"}
	wrapped := WrapResponseError(resp, cause)
	if !errors.Is(wrapped, cause) {
		t.Fatal("response wrapper lost cause")
	}
	d := DiagnoseFailure(wrapped)
	if d.CauseType != "*provider.StreamError" {
		t.Fatalf("lost cause type: %+v", d)
	}
	if d.EndpointHost != "gateway.example" || d.RequestID != "req-stream" || d.HTTPStatus != 200 || d.UpstreamCode != "429" || d.Class != "rate_limit" {
		t.Fatalf("diagnostic=%+v", d)
	}
	resp.Header.Set("Request-ID", "Bearer sk-private-key PRIVATE PROMPT")
	if DiagnoseFailure(WrapResponseError(resp, cause)).RequestID != "" {
		t.Fatal("unsafe request ID retained")
	}
}
