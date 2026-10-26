package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	internal "github.com/Problem99-io/kodeblue/internal"
	"github.com/Problem99-io/kodeblue/internal/provider"
	"github.com/Problem99-io/kodeblue/internal/tools"
	"strings"
	"testing"
	"time"
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

// A connection that drops after the model started answering asks for the
// same turn again instead of failing the run (a learning run on a flaky
// network lost minutes of work to one reset). Nothing of the broken turn is
// kept: the run's answer is the second response alone.
func TestLoopRestartsATurnThatDroppedMidAnswer(t *testing.T) {
	old := turnRestartDelay
	turnRestartDelay = func(int) time.Duration { return time.Millisecond }
	t.Cleanup(func() { turnRestartDelay = old })
	reset := errors.New("read tcp 10.0.0.1:443: connection reset by peer")
	p := newMockProvider([][]provider.StreamEvent{
		{{Type: provider.EventToken, Content: "half an ans"}, {Type: provider.EventError, Error: reset}},
		{{Type: provider.EventToken, Content: "the whole answer"}, {Type: provider.EventDone}},
	})
	var states []string
	loop := NewLoop(tools.NewRegistry(), newAllowAllToolGuard(), nil, func(e internal.Event) {
		if e.Type == "provider.connection" {
			var f map[string]any
			_ = json.Unmarshal(e.Payload, &f)
			states = append(states, fmt.Sprint(f["state"]))
		}
		if e.Type == internal.EventRunFailed {
			t.Error("run failed on a restartable reset")
		}
	})
	res, err := loop.Run(context.Background(), buildRunConfig(p, nil), "learn the server", nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.callCount() != 2 || strings.Join(states, ",") != "stopped,restarting_turn" {
		t.Fatalf("calls %d, states %v", p.callCount(), states)
	}
	last := res.Messages[len(res.Messages)-1]
	if last.Content != "the whole answer" {
		t.Fatalf("answer %q", last.Content)
	}
}

// Past turnRestarts, or for a failure that is not the connection, the run
// fails as before.
func TestLoopGivesUpOnRepeatedOrPermanentFailures(t *testing.T) {
	old := turnRestartDelay
	turnRestartDelay = func(int) time.Duration { return time.Millisecond }
	t.Cleanup(func() { turnRestartDelay = old })
	reset := errors.New("connection reset by peer")
	var script [][]provider.StreamEvent
	for i := 0; i <= turnRestarts; i++ {
		script = append(script, []provider.StreamEvent{{Type: provider.EventToken, Content: "x"}, {Type: provider.EventError, Error: reset}})
	}
	p := newMockProvider(script)
	if _, err := NewLoop(tools.NewRegistry(), newAllowAllToolGuard(), nil, nil).Run(context.Background(), buildRunConfig(p, nil), "go", nil); err == nil || p.callCount() != turnRestarts+1 {
		t.Fatalf("err %v after %d calls", err, p.callCount())
	}
	denied := &provider.APIStatusError{Provider: "openai", StatusCode: 403, Body: `{"error":{"message":"Key limit exceeded (daily limit). $2.01 of $2.00 used; resets 2026-10-27T00:00:00.000Z."}}`}
	p = newMockProvider([][]provider.StreamEvent{{{Type: provider.EventToken, Content: "x"}, {Type: provider.EventError, Error: denied}}})
	if _, err := NewLoop(tools.NewRegistry(), newAllowAllToolGuard(), nil, nil).Run(context.Background(), buildRunConfig(p, nil), "go", nil); err == nil || p.callCount() != 1 {
		t.Fatalf("a spending limit was retried: %v, %d calls", err, p.callCount())
	}
}
