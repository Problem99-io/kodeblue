package agent

import (
	"context"
	"encoding/json"
	"errors"
	internal "github.com/Problem99-io/kodeblue/internal"
	"github.com/Problem99-io/kodeblue/internal/provider"
	"github.com/Problem99-io/kodeblue/internal/tools"
	"strings"
	"testing"
)

func TestLoopConnectionRecoveryStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := newMockProvider([][]provider.StreamEvent{{{Type: provider.EventError, Error: errors.New("stream truncated by stream EOF after 0 bytes")}}})
	reg := tools.NewRegistry()
	var events []string
	loop := NewLoop(reg, newAllowAllToolGuard(), nil, func(e internal.Event) {
		events = append(events, e.Type)
		if e.Type == "provider.connection" {
			cancel()
		}
	})
	_, err := loop.Run(ctx, buildRunConfig(p, nil), "synthetic recovery test", nil)
	if !errors.Is(err, ErrAborted) {
		t.Fatalf("wanted aborted, got %v", err)
	}
	if p.callCount() != 1 {
		t.Fatalf("unexpected replay: %d", p.callCount())
	}
	found := false
	for _, event := range events {
		if event == "provider.connection" {
			found = true
		}
		if event == internal.EventRunFailed {
			t.Fatal("transient failure surfaced before retries")
		}
	}
	if !found {
		t.Fatal("missing connection widget event")
	}
}

func TestLoopTerminalProviderEventRetainsSafeDiagnostics(t *testing.T) {
	cause := &provider.StreamError{Provider: "openai", Code: "401", Message: "PRIVATE PROMPT sk-private-credential"}
	wrapped := &provider.ResponseError{Cause: cause, HTTPStatus: 200, EndpointHost: "gateway.example", RequestID: "req-denied"}
	p := newMockProvider([][]provider.StreamEvent{{{Type: provider.EventError, Error: wrapped}}})
	var failed map[string]any
	loop := NewLoop(tools.NewRegistry(), newAllowAllToolGuard(), nil, func(e internal.Event) {
		if e.Type == internal.EventRunFailed {
			if err := json.Unmarshal(e.Payload, &failed); err != nil {
				t.Error(err)
			}
		}
	})
	cfg := buildRunConfig(p, nil)
	cfg.ModelName = "fixture-model"
	_, err := loop.Run(context.Background(), cfg, "PRIVATE USER PROMPT", nil)
	if !errors.Is(err, cause) {
		t.Fatalf("lost underlying cause: %v", err)
	}
	for key, want := range map[string]any{"failure_class": "authentication", "http_status": float64(200), "upstream_code": "401", "endpoint_host": "gateway.example", "request_id": "req-denied", "attempt": float64(0), "max_attempts": float64(10), "recovery_outcome": "stopped"} {
		if failed[key] != want {
			t.Errorf("%s=%v want=%v", key, failed[key], want)
		}
	}
	if failed["provider_cause"] == "" || failed["model"] == "" || failed["provider"] == "" {
		t.Fatalf("missing identifiers/cause: %+v", failed)
	}
	raw, _ := json.Marshal(failed)
	if strings.Contains(string(raw), "PRIVATE") || strings.Contains(string(raw), "sk-private") {
		t.Fatalf("terminal leaked provider data: %s", raw)
	}
	if p.callCount() != 1 {
		t.Fatalf("permanent error replayed %d times", p.callCount())
	}
}
