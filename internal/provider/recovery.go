package provider

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

const RecoveryRetries = 10

// ConnectionRecovery includes presentation state and a privacy-safe failure summary.
type ConnectionRecovery struct {
	FailureDiagnostic
	State       string     `json:"state"`
	Attempt     int        `json:"attempt"`
	MaxAttempts int        `json:"max_attempts"`
	RetryAt     *time.Time `json:"retry_at,omitempty"`
}

func RecoveryDelay(attempt int) time.Duration {
	if attempt <= 3 {
		return 10 * time.Second
	}
	if attempt <= 6 {
		return 30 * time.Second
	}
	return time.Minute
}

type RecoveryExhaustedError struct {
	Cause                error
	Attempt, MaxAttempts int
	Elapsed              time.Duration
}

func (e *RecoveryExhaustedError) Error() string {
	return fmt.Sprintf("connection recovery exhausted: %v", e.Cause)
}
func (e *RecoveryExhaustedError) Unwrap() error { return e.Cause }

// StreamError preserves a gateway's error code even when HTTP succeeded.
// Metadata is deliberately excluded because it can contain private requests.
type StreamError struct {
	Provider string
	Code     string
	Message  string
}

func (e *StreamError) Error() string {
	return fmt.Sprintf("%s: upstream stream error: %s", e.Provider, e.Message)
}

func recoverableConnectionError(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	var apiErr *APIStatusError
	if errors.As(err, &apiErr) {
		// The relay temporarily reports unknown_model when discovery is unavailable.
		return apiErr.Transient() || (apiErr.StatusCode == 400 && strings.Contains(apiErr.Body, "unknown_model"))
	}
	var streamErr *StreamError
	if errors.As(err, &streamErr) {
		if status, parseErr := strconv.Atoi(streamErr.Code); parseErr == nil && status >= 400 && status <= 599 {
			return TransientFailure(status, []byte(streamErr.Message))
		}
	}
	if permanentBlockPattern.MatchString(err.Error()) {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	text := strings.ToLower(err.Error())
	for _, fragment := range []string{"stream truncated", "stream eof", "connection reset", "connection refused", "broken pipe", "stream idle timeout", "upstream unavailable", "service unavailable", "temporarily unavailable", "finish_reason=error", "rate-limited", "rate limited", "rate limit exceeded", "too many requests"} {
		if strings.Contains(text, fragment) {
			return true
		}
	}
	return false
}

// RestartableTurn reports whether a model turn that failed after the model
// had started answering may be requested again: the connection dropped or
// stalled, as recovery would have retried before any output, and recovery's
// own retries were not already spent. Nothing of a turn takes effect before
// it completes (its tool calls run afterwards), so asking again only repeats
// output tokens.
func RestartableTurn(err error) bool {
	var exhausted *RecoveryExhaustedError
	if errors.As(err, &exhausted) {
		return false
	}
	return recoverableConnectionError(err)
}

type recoveryContextKey struct{}

// StreamWithRecovery retries only before the request has exposed any output.
// It never restarts the run or re-executes a tool. Cancellation interrupts both
// the wait and the active request. Each attempt owns and closes its stream.
func StreamWithRecovery(ctx context.Context, p Provider, req *Request, notify func(ConnectionRecovery)) (<-chan StreamEvent, error) {
	return streamWithRecovery(ctx, p, req, notify, sleepCtx), nil
}

func streamWithRecovery(ctx context.Context, p Provider, req *Request, notify func(ConnectionRecovery), wait func(context.Context, time.Duration) error) <-chan StreamEvent {
	out := make(chan StreamEvent)
	go func() {
		defer close(out)
		send := func(e StreamEvent) bool {
			select {
			case out <- e:
				return true
			case <-ctx.Done():
				return false
			}
		}
		var lastCause error
		var retryStart time.Time
		retryElapsed := func() time.Duration {
			if retryStart.IsZero() {
				return 0
			}
			return time.Since(retryStart)
		}
		var lastState string
		var lastAttempt int
		publish := func(state string, attempt int, at *time.Time) {
			lastState, lastAttempt = state, attempt
			if notify != nil {
				diagnostic := DiagnoseFailure(lastCause)
				diagnostic.Attempt, diagnostic.MaxAttempts = attempt, RecoveryRetries
				diagnostic.RetryElapsedMS, diagnostic.RecoveryOutcome = retryElapsed().Milliseconds(), state
				notify(ConnectionRecovery{FailureDiagnostic: diagnostic, State: state, Attempt: attempt, MaxAttempts: RecoveryRetries, RetryAt: at})
			}
		}
		defer func() {
			if ctx.Err() != nil && (lastState == "waiting" || lastState == "retrying") {
				publish("cancelled", lastAttempt, nil)
			}
		}()
		for attempt := 0; ; attempt++ {
			if ctx.Err() != nil {
				return
			}
			// Disable the provider HTTP helper's hidden retries: this is the single budget.
			attemptCtx, cancel := context.WithCancel(context.WithValue(ctx, recoveryContextKey{}, true))
			ch, err := p.Stream(attemptCtx, req)
			progress := false
			if err == nil {
			read:
				for {
					select {
					case <-ctx.Done():
						cancel()
						return
					case event, ok := <-ch:
						if !ok {
							err = io.ErrUnexpectedEOF
							break read
						}
						if event.Type == EventError {
							err = event.Error
							if err == nil {
								err = io.ErrUnexpectedEOF
							}
							break read
						}
						if !progress {
							progress = true
							if attempt > 0 {
								publish("recovered", attempt, nil)
							}
						}
						if !send(event) {
							cancel()
							return
						}
						if event.Type == EventDone {
							cancel()
							return
						}
					}
				}
			}
			cancel()
			if ctx.Err() != nil {
				return
			}
			lastCause = err
			if retryStart.IsZero() {
				retryStart = time.Now()
			}
			if progress || !recoverableConnectionError(err) {
				publish("stopped", attempt, nil)
				send(StreamEvent{Type: EventError, Error: &RecoveryStoppedError{Cause: err, Attempt: attempt, MaxAttempts: RecoveryRetries, Elapsed: retryElapsed()}})
				return
			}
			if attempt == RecoveryRetries {
				publish("exhausted", attempt, nil)
				send(StreamEvent{Type: EventError, Error: &RecoveryExhaustedError{Cause: err, Attempt: attempt, MaxAttempts: RecoveryRetries, Elapsed: retryElapsed()}})
				return
			}
			delay := RecoveryDelay(attempt + 1)
			at := time.Now().Add(delay)
			publish("waiting", attempt+1, &at)
			if wait(ctx, delay) != nil {
				publish("cancelled", attempt+1, nil)
				return
			}
			if ctx.Err() != nil {
				return
			}
			publish("retrying", attempt+1, nil)
		}
	}()
	return out
}
