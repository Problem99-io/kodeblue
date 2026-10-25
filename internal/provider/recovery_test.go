package provider

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

type recoveryProvider struct {
	calls  int
	stream func(int) ([]StreamEvent, error)
}

func (p *recoveryProvider) Name() string                                          { return "test" }
func (p *recoveryProvider) CountTokens(context.Context, *Request) (*Usage, error) { return nil, nil }
func (p *recoveryProvider) Stream(ctx context.Context, _ *Request) (<-chan StreamEvent, error) {
	if managed, _ := ctx.Value(recoveryContextKey{}).(bool); !managed {
		panic("nested HTTP retries not disabled")
	}
	p.calls++
	events, err := p.stream(p.calls)
	ch := make(chan StreamEvent, len(events))
	for _, e := range events {
		ch <- e
	}
	close(ch)
	return ch, err
}
func TestRecoveryScheduleAndExhaustion(t *testing.T) {
	p := &recoveryProvider{stream: func(int) ([]StreamEvent, error) { return nil, io.ErrUnexpectedEOF }}
	var delays []time.Duration
	var states []ConnectionRecovery
	var last error
	ch := streamWithRecovery(context.Background(), p, &Request{}, func(s ConnectionRecovery) { states = append(states, s) }, func(_ context.Context, d time.Duration) error { delays = append(delays, d); return nil })
	for e := range ch {
		last = e.Error
	}
	if p.calls != 11 || len(delays) != 10 {
		t.Fatalf("calls=%d delays=%v", p.calls, delays)
	}
	for i, d := range delays {
		want := time.Minute
		if i < 6 {
			want = 30 * time.Second
		}
		if i < 3 {
			want = 10 * time.Second
		}
		if d != want {
			t.Fatalf("retry %d delay %v", i+1, d)
		}
	}
	var exhausted *RecoveryExhaustedError
	if !errors.As(last, &exhausted) {
		t.Fatalf("error=%v", last)
	}
	if states[len(states)-1].State != "exhausted" || states[len(states)-1].Attempt != 10 {
		t.Fatal(states)
	}
	if FailureReason(last) != "We could not reconnect after 10 retries. The model provider's response ended before it completed. Please try again later or choose another model." {
		t.Fatal(FailureReason(last))
	}
}
func TestRecoverySuccessAndPermanentFailures(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want int
	}{
		{"empty stream", io.ErrUnexpectedEOF, 2},
		{"catalog unavailable", &APIStatusError{StatusCode: 400, Body: `{"code":"unknown_model"}`}, 2},
		{"unauthorized", &APIStatusError{StatusCode: 401, Body: "invalid key"}, 1},
		{"bad request", &APIStatusError{StatusCode: 400, Body: "invalid arguments"}, 1},
		{"credit", &APIStatusError{StatusCode: 429, Body: "insufficient credit"}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &recoveryProvider{stream: func(n int) ([]StreamEvent, error) {
				if n == 1 {
					return nil, tc.err
				}
				return []StreamEvent{{Type: EventToken, Content: "OK"}, {Type: EventDone}}, nil
			}}
			var text string
			var done bool
			for e := range streamWithRecovery(context.Background(), p, &Request{}, nil, func(context.Context, time.Duration) error { return nil }) {
				text += e.Content
				done = done || e.Type == EventDone
			}
			if p.calls != tc.want {
				t.Fatalf("calls=%d", p.calls)
			}
			if tc.want == 2 && (!done || text != "OK") {
				t.Fatalf("done=%t text=%s", done, text)
			}
		})
	}
}
func TestRecoveryStreamErrorBeforeOutput(t *testing.T) {
	p := &recoveryProvider{stream: func(n int) ([]StreamEvent, error) {
		if n == 1 {
			return []StreamEvent{{Type: EventError, Error: errors.New("stream truncated by stream EOF")}}, nil
		}
		return []StreamEvent{{Type: EventDone}}, nil
	}}
	for e := range streamWithRecovery(context.Background(), p, &Request{}, nil, func(context.Context, time.Duration) error { return nil }) {
		if e.Type == EventError {
			t.Fatal(e.Error)
		}
	}
	if p.calls != 2 {
		t.Fatal(p.calls)
	}
}
func TestRecoveryNeverReplaysPartialOutputOrTools(t *testing.T) {
	for _, kind := range []StreamEventType{EventToken, EventToolUseDelta, EventToolUse} {
		p := &recoveryProvider{stream: func(int) ([]StreamEvent, error) {
			return []StreamEvent{{Type: kind, Content: "partial"}, {Type: EventError, Error: io.ErrUnexpectedEOF}}, nil
		}}
		for range streamWithRecovery(context.Background(), p, &Request{}, nil, func(context.Context, time.Duration) error { t.Error("must not wait"); return nil }) {
		}
		if p.calls != 1 {
			t.Fatal(p.calls)
		}
	}
}
func TestRecoveryStopCancelsWait(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &recoveryProvider{stream: func(int) ([]StreamEvent, error) { return nil, io.ErrUnexpectedEOF }}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range streamWithRecovery(ctx, p, &Request{}, func(s ConnectionRecovery) {
			if s.State == "waiting" {
				cancel()
			}
		}, sleepCtx) {
		}
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stop did not cancel delay")
	}
	if p.calls != 1 {
		t.Fatal(p.calls)
	}
}

func TestRecoveryStreamedRateLimit(t *testing.T) {
	for _, tc := range []struct {
		name    string
		err     error
		retries bool
	}{
		{"observed upstream message", &StreamError{Provider: "openai", Message: "openai/gpt-6-luna is temporarily rate-limited upstream. Please retry shortly, or add your own key to accumulate your rate limits"}, true},
		{"numeric code", &StreamError{Code: "429", Message: "capacity reached"}, true},
		{"overloaded", &StreamError{Code: "503", Message: "overloaded"}, true},
		{"symbolic code", &StreamError{Code: "rate_limit_exceeded", Message: "rate limit exceeded"}, true},
		{"credits", &StreamError{Code: "429", Message: "insufficient credit"}, false},
		{"quota", &StreamError{Code: "429", Message: "quota exceeded"}, false},
		{"invalid key", &StreamError{Code: "401", Message: "unauthorized"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &recoveryProvider{stream: func(n int) ([]StreamEvent, error) {
				if n == 1 {
					return []StreamEvent{{Type: EventError, Error: tc.err}}, nil
				}
				return []StreamEvent{{Type: EventToken, Content: "Recovered"}, {Type: EventDone}}, nil
			}}
			var states []string
			var delays []time.Duration
			var done bool
			for e := range streamWithRecovery(context.Background(), p, &Request{}, func(s ConnectionRecovery) { states = append(states, s.State) }, func(_ context.Context, d time.Duration) error { delays = append(delays, d); return nil }) {
				if e.Type == EventError && tc.retries {
					t.Fatal(e.Error)
				}
				done = done || e.Type == EventDone
			}
			if tc.retries {
				if p.calls != 2 || !done || len(delays) != 1 || delays[0] != 10*time.Second || len(states) != 3 || states[0] != "waiting" || states[1] != "retrying" || states[2] != "recovered" {
					t.Fatalf("calls=%d done=%t delays=%v states=%v", p.calls, done, delays, states)
				}
			} else if p.calls != 1 || len(delays) != 0 || done {
				t.Fatalf("permanent error retried: calls=%d", p.calls)
			}
		})
	}
}

func TestRecoveryDiagnosticsKeepLatestCauseThroughExhaustion(t *testing.T) {
	var cause *APIStatusError
	p := &recoveryProvider{stream: func(n int) ([]StreamEvent, error) {
		cause = &APIStatusError{Provider: "openai", StatusCode: 429, Body: `{"error":{"code":"rate_limit_exceeded","message":"PRIVATE PROMPT"}}`, EndpointHost: "gateway.example", RequestID: fmt.Sprintf("req-%d", n)}
		return nil, fmt.Errorf("wrapped provider: %w", cause)
	}}
	var states []ConnectionRecovery
	var terminal error
	for e := range streamWithRecovery(context.Background(), p, &Request{}, func(s ConnectionRecovery) { states = append(states, s) }, func(context.Context, time.Duration) error { time.Sleep(time.Millisecond); return nil }) {
		terminal = e.Error
	}
	if !errors.Is(terminal, cause) {
		t.Fatal("exhaustion lost the last underlying cause")
	}
	d := DiagnoseFailure(terminal)
	if d.Cause == "" || d.Class != "rate_limit" || d.EndpointHost != "gateway.example" || d.RequestID != "req-11" || d.Attempt != 10 || d.MaxAttempts != 10 || d.RetryElapsedMS < 10 || d.RecoveryOutcome != "exhausted" {
		t.Fatalf("terminal=%+v", d)
	}
	for _, s := range states {
		if s.Class != "rate_limit" || s.Cause == "" || s.MaxAttempts != 10 || s.RecoveryOutcome != s.State || s.HTTPStatus != 429 || s.RequestID == "" {
			t.Fatalf("state=%+v", s)
		}
	}
	if !strings.Contains(FailureReason(terminal), "rate limiting") || strings.Contains(FailureReason(terminal), "PRIVATE") {
		t.Fatalf("reason=%s", FailureReason(terminal))
	}
}

func TestRecoveredDiagnosticsKeepPriorCauseAndElapsedTime(t *testing.T) {
	cause := &StreamError{Code: "rate_limit_exceeded", Message: "temporarily rate-limited upstream PRIVATE"}
	p := &recoveryProvider{stream: func(n int) ([]StreamEvent, error) {
		if n == 1 {
			return nil, cause
		}
		return []StreamEvent{{Type: EventDone}}, nil
	}}
	var states []ConnectionRecovery
	for range streamWithRecovery(context.Background(), p, &Request{}, func(s ConnectionRecovery) { states = append(states, s) }, func(context.Context, time.Duration) error { time.Sleep(time.Millisecond); return nil }) {
	}
	recovered := states[len(states)-1]
	if recovered.State != "recovered" || recovered.RecoveryOutcome != "recovered" || recovered.Class != "rate_limit" || recovered.Attempt != 1 || recovered.RetryElapsedMS < 1 {
		t.Fatalf("recovered=%+v", recovered)
	}
}

func TestStoppedRecoveryPreservesChangedCause(t *testing.T) {
	final := &APIStatusError{StatusCode: 401, Body: "PRIVATE CREDENTIAL", RequestID: "req-denied", EndpointHost: "gateway.example"}
	p := &recoveryProvider{stream: func(n int) ([]StreamEvent, error) {
		if n == 1 {
			return nil, io.ErrUnexpectedEOF
		}
		return nil, final
	}}
	var terminal error
	for e := range streamWithRecovery(context.Background(), p, &Request{}, nil, func(context.Context, time.Duration) error { return nil }) {
		terminal = e.Error
	}
	d := DiagnoseFailure(terminal)
	if !errors.Is(terminal, final) || d.RecoveryOutcome != "stopped" || d.Attempt != 1 || d.Class != "authentication" || d.RequestID != "req-denied" {
		t.Fatalf("diagnostic=%+v err=%v", d, terminal)
	}
}

func TestCancelledRetryRequestPublishesOutcome(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &recoveryProvider{stream: func(n int) ([]StreamEvent, error) {
		if n == 1 {
			return nil, io.ErrUnexpectedEOF
		}
		cancel()
		return nil, context.Canceled
	}}
	var states []ConnectionRecovery
	for e := range streamWithRecovery(ctx, p, &Request{}, func(s ConnectionRecovery) { states = append(states, s) }, func(context.Context, time.Duration) error { return nil }) {
		if e.Type == EventError {
			t.Fatal("cancellation became a terminal failure")
		}
	}
	last := states[len(states)-1]
	if last.State != "cancelled" || last.RecoveryOutcome != "cancelled" || last.Class != "stream_truncated" || last.Attempt != 1 || p.calls != 2 {
		t.Fatalf("cancelled=%+v calls=%d", last, p.calls)
	}
}
