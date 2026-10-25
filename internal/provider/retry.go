package provider

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Transient upstream failures are the most common way a long agent run dies for
// no good reason: a shared rate-limit pool that is momentarily full, a vendor
// 5xx, an overloaded relay. They clear on their own within a second or two, and
// the request has produced nothing yet — no tokens have reached the agent loop —
// so re-sending it is invisible to the run. Retrying here turns what used to be
// a hard "FAILURE REASON: provider error: openai: API error 429 {...}" banner
// into a slightly slower turn.
//
// Only a failure the vendor reported as a status code is retried, and only
// during the request/response handshake. Once the stream has begun the model is
// already writing, so a mid-stream failure is reported as-is rather than
// silently restarting a partially delivered turn — and a transport error is
// left alone for the same reason, since it can surface long after the vendor
// accepted the request and started billing for it.
const (
	// streamRetryAttempts counts the first attempt plus its retries.
	streamRetryAttempts  = 3
	streamRetryBaseDelay = 2 * time.Second
	streamRetryMaxDelay  = 8 * time.Second

	// defaultErrorBodyLimit caps how much of a failure body is read for the
	// error message and the retry hint.
	defaultErrorBodyLimit = 4 * 1024
)

// APIStatusError is a non-2xx response from a provider endpoint. It carries the
// status and the raw body for logs, plus how hard the client already tried, so
// the user-facing message can say "we retried" instead of dumping a relay's
// nested JSON on someone who just wanted their task to run.
type APIStatusError struct {
	Provider     string
	StatusCode   int
	Body         string
	EndpointHost string
	RequestID    string
	MaxAttempts  int
	// Attempts is the number of requests actually sent (1 when the first
	// response was already final).
	Attempts int
	Elapsed  time.Duration
}

func (e *APIStatusError) Error() string {
	if e.Attempts > 1 {
		return fmt.Sprintf(
			"%s: API error %d after %d attempts over %s: %s",
			e.Provider, e.StatusCode, e.Attempts, e.Elapsed.Round(100*time.Millisecond), e.Body,
		)
	}
	return fmt.Sprintf("%s: API error %d: %s", e.Provider, e.StatusCode, e.Body)
}

// Transient reports whether this failure is the kind that clears on its own.
func (e *APIStatusError) Transient() bool {
	return TransientFailure(e.StatusCode, []byte(e.Body))
}

// TransientFailure reports whether a provider response is worth re-sending the
// same request for. The status alone is not enough: our own relay answers a
// spent quota or a credit block with 429, and a provider it has no key for with
// 503. Those never clear by waiting, so re-sending only burns time and hides
// the one sentence that would tell the user what to fix.
func TransientFailure(status int, body []byte) bool {
	switch status {
	case http.StatusRequestTimeout, // 408
		http.StatusTooEarly,            // 425
		http.StatusTooManyRequests,     // 429
		http.StatusInternalServerError, // 500
		http.StatusBadGateway,          // 502
		http.StatusServiceUnavailable,  // 503
		http.StatusGatewayTimeout,      // 504
		529:                            // Anthropic / OpenRouter "overloaded"
		return !permanentBlockPattern.Match(body)
	}
	return false
}

// permanentBlockPattern recognizes the refusals our relay dresses up in an
// otherwise transient status: an exhausted quota or credit balance, a model or
// provider that is not available to this caller.
var permanentBlockPattern = regexp.MustCompile(`(?i)quota exceeded|insufficient (?:credit|balance|funds)|out of credit|provider not available|not authorized|is disabled`)

// FailureReason renders a provider error for a human. Transient failures that
// survived every retry get a plain-language explanation and a next step.
// Other failures retain a safe cause classification rather than raw bodies.
func FailureReason(err error) string {
	if err == nil {
		return ""
	}
	var exhausted *RecoveryExhaustedError
	if errors.As(err, &exhausted) {
		attempts := exhausted.MaxAttempts
		if attempts == 0 {
			attempts = RecoveryRetries
		}
		return fmt.Sprintf("We could not reconnect after %d retries. %s Please try again later or choose another model.", attempts, DiagnoseFailure(err).Cause)
	}
	var apiErr *APIStatusError
	if errors.As(err, &apiErr) {
		if msg := apiErr.userMessage(); msg != "" {
			return msg
		}
	}
	return DiagnoseFailure(err).Cause
}

// userMessage returns advice for a transient failure, or "" to use the safe
// classification of a permanent rejection.
func (e *APIStatusError) userMessage() string {
	if !e.Transient() {
		return ""
	}
	tried := ""
	if e.Attempts > 1 {
		tried = fmt.Sprintf(" We retried %d times over %s.", e.Attempts-1, e.Elapsed.Round(time.Second))
	}
	if e.StatusCode == http.StatusTooManyRequests {
		return "The model provider is rate limiting requests for this model right now." + tried +
			" Wait a moment and try again, or switch to another model."
	}
	return fmt.Sprintf("The model provider is temporarily unavailable (HTTP %d).", e.StatusCode) + tried +
		" Try again in a moment, or switch to another model."
}

// RetryOptions describes one retryable provider call.
type RetryOptions struct {
	// Provider names the client for error messages ("openai", "anthropic").
	Provider string
	Client   *http.Client
	// NewRequest builds a fresh request for each attempt. It must produce a
	// rereadable body (build it from a []byte), since a retry re-sends it.
	NewRequest func(ctx context.Context) (*http.Request, error)
	// Attempts overrides the default attempt count (first try + retries).
	Attempts int
	// BaseDelay overrides the first backoff step; each further retry doubles it.
	BaseDelay time.Duration
	// ErrorBodyLimit overrides how much of a failure body is read.
	ErrorBodyLimit int64
	// OnFailureResponse, when set, sees every non-2xx response together with
	// its already-read body. Clients use it for their diagnostic logging.
	OnFailureResponse func(resp *http.Response, body []byte, willRetry bool)
	// OnRetry, when set, is called before each backoff sleep. cause is reserved
	// for a failure that is not a response status; it is nil today.
	OnRetry func(attempt int, status int, delay time.Duration, cause error)
}

// Send performs an HTTP request, retrying transient response statuses with
// backoff. Transport failures are not retried — see the loop for why.
//
// On success the response is returned with its body unread and open — the
// caller owns it. Any non-2xx response is drained, closed, and returned as an
// *APIStatusError; a transport failure is returned wrapped, matching the
// clients' existing "<provider>: send request" phrasing. A run cancelled during
// a backoff returns the context error, never the upstream status.
func Send(ctx context.Context, opts RetryOptions) (*http.Response, error) {
	attempts := opts.Attempts
	if managed, _ := ctx.Value(recoveryContextKey{}).(bool); managed {
		attempts = 1
	}
	if attempts <= 0 {
		attempts = streamRetryAttempts
	}
	bodyLimit := opts.ErrorBodyLimit
	if bodyLimit <= 0 {
		bodyLimit = defaultErrorBodyLimit
	}
	baseDelay := opts.BaseDelay
	if baseDelay <= 0 {
		baseDelay = streamRetryBaseDelay
	}

	start := time.Now()
	statusError := func(attempt int, resp *http.Response, errBody []byte) error {
		host, requestID := responseIdentifiers(resp)
		return &APIStatusError{
			EndpointHost: host, RequestID: requestID, MaxAttempts: attempts,
			Provider:   opts.Provider,
			StatusCode: resp.StatusCode,
			Body:       string(errBody),
			Attempts:   attempt,
			Elapsed:    time.Since(start),
		}
	}

	for attempt := 1; ; attempt++ {
		req, err := opts.NewRequest(ctx)
		if err != nil {
			return nil, err
		}

		resp, err := opts.Client.Do(req)
		if err != nil {
			// Transport failures are deliberately not retried. By the time one
			// surfaces the request has been fully sent and accepted — a
			// ResponseHeaderTimeout in particular fires while the model is
			// already generating — so re-sending would duplicate billable work
			// that may well have completed.
			return nil, &ResponseError{Cause: fmt.Errorf("%s: send request: %w", opts.Provider, err), EndpointHost: endpointHost(req.URL)}
		}

		if resp.Request == nil {
			resp.Request = req
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return resp, nil
		}

		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, bodyLimit))
		resp.Body.Close()

		delay, retryWorthwhile := retryDelay(attempt, baseDelay, resp.Header, errBody)
		willRetry := retryWorthwhile &&
			TransientFailure(resp.StatusCode, errBody) &&
			attempt < attempts &&
			ctx.Err() == nil
		if opts.OnFailureResponse != nil {
			opts.OnFailureResponse(resp, errBody, willRetry)
		}
		if !willRetry {
			return nil, statusError(attempt, resp, errBody)
		}

		if opts.OnRetry != nil {
			opts.OnRetry(attempt, resp.StatusCode, delay, nil)
		}
		if waitErr := sleepCtx(ctx, delay); waitErr != nil {
			// The run was stopped mid-backoff. Reporting the upstream status
			// here would tell the user their provider is rate limiting them
			// when in fact they pressed Stop.
			return nil, waitErr
		}
	}
}

// retryDelay picks how long to wait before attempt+1, and reports whether
// retrying is worth it at all. A hint asking for less than our backoff is
// rounded up — a pool that just rejected us is rarely free again in a few
// hundred milliseconds. A hint asking for more than we are willing to wait
// means the wait would not clear the limit either, so the caller gives up now
// with the vendor's own explanation rather than hammering a closed door.
func retryDelay(attempt int, base time.Duration, headers http.Header, body []byte) (time.Duration, bool) {
	if base <= 0 {
		base = streamRetryBaseDelay
	}
	maxDelay := max(streamRetryMaxDelay, base)
	backoff := min(base<<(attempt-1), maxDelay)
	if hint, ok := retryAfterHint(headers, body); ok {
		if hint > maxDelay {
			return 0, false
		}
		backoff = max(backoff, hint)
	}
	if backoff <= 0 {
		backoff = base
	}
	// Jitter keeps concurrent runs from re-hitting a shared pool in lockstep.
	return backoff + time.Duration(rand.Int63n(int64(backoff/4)+1)), true
}

// retryAfterHintPattern finds a retry hint anywhere in a response body. Relays
// bury theirs in escaped JSON — OpenRouter reports
// `{"details":"{\"error\":{...\"retry_after_seconds\":1...}}"}` — so matching
// the field textually is what actually reads these, rather than modelling one
// vendor's error envelope.
var retryAfterHintPattern = regexp.MustCompile(`(?i)(?:retry_after_seconds|retry-after)\\*"?\s*:\s*\\*"?(\d+(?:\.\d+)?)`)

// retryAfterHint reads an upstream's requested wait from the Retry-After header
// or, failing that, from the response body.
func retryAfterHint(headers http.Header, body []byte) (time.Duration, bool) {
	if headers != nil {
		if raw := strings.TrimSpace(headers.Get("Retry-After")); raw != "" {
			if secs, err := strconv.ParseFloat(raw, 64); err == nil && secs >= 0 {
				return time.Duration(secs * float64(time.Second)), true
			}
			if when, err := http.ParseTime(raw); err == nil {
				if d := time.Until(when); d > 0 {
					return d, true
				}
				return 0, true
			}
		}
	}
	if match := retryAfterHintPattern.FindSubmatch(body); match != nil {
		if secs, err := strconv.ParseFloat(string(match[1]), 64); err == nil && secs >= 0 {
			return time.Duration(secs * float64(time.Second)), true
		}
	}
	return 0, false
}

// sleepCtx waits for d, or returns early if the run is cancelled.
func sleepCtx(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
