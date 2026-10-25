package provider

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// openRouterRateLimitBody is a verbatim OpenRouter 429 as relayed by an
// upstream gateway: the useful retry hint is buried two levels deep in escaped
// JSON, which is why the hint is matched textually.
const openRouterRateLimitBody = `{"details":"{\"error\":{\"message\":\"Provider returned error\",\"code\":429,\"metadata\":{\"raw\":\"moonshotai/kimi-k3 is temporarily rate-limited upstream.\",\"provider_name\":\"Together\",\"is_byok\":false,\"retry_after_seconds\":1,\"headers\":{\"Retry-After\":\"1\"}}}}","error":"upstream provider error","provider":"openrouter","upstream_status":429}`

func TestSendRetriesRateLimitThenSucceeds(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(openRouterRateLimitBody))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	var retries atomic.Int32
	resp, err := Send(context.Background(), RetryOptions{
		Provider:  "openai",
		Client:    srv.Client(),
		BaseDelay: time.Millisecond,
		NewRequest: func(ctx context.Context) (*http.Request, error) {
			return http.NewRequestWithContext(ctx, http.MethodPost, srv.URL, strings.NewReader(`{}`))
		},
		OnRetry: func(attempt, status int, delay time.Duration, cause error) {
			retries.Add(1)
			if status != http.StatusTooManyRequests {
				t.Errorf("retried on status %d, want 429", status)
			}
		},
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	defer resp.Body.Close()

	if got := calls.Load(); got != 2 {
		t.Errorf("requests sent = %d, want 2", got)
	}
	if got := retries.Load(); got != 1 {
		t.Errorf("retry callbacks = %d, want 1", got)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestSendGivesUpAfterAttemptsAndReportsRetries(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(openRouterRateLimitBody))
	}))
	defer srv.Close()

	_, err := Send(context.Background(), RetryOptions{
		Provider:  "openai",
		Client:    srv.Client(),
		BaseDelay: time.Millisecond,
		NewRequest: func(ctx context.Context) (*http.Request, error) {
			return http.NewRequestWithContext(ctx, http.MethodPost, srv.URL, strings.NewReader(`{}`))
		},
	})
	if err == nil {
		t.Fatal("Send succeeded, want rate-limit error")
	}
	if got := calls.Load(); got != streamRetryAttempts {
		t.Errorf("requests sent = %d, want %d", got, streamRetryAttempts)
	}

	var apiErr *APIStatusError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error %T, want *APIStatusError", err)
	}
	if apiErr.StatusCode != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429", apiErr.StatusCode)
	}
	if apiErr.Attempts != streamRetryAttempts {
		t.Errorf("attempts = %d, want %d", apiErr.Attempts, streamRetryAttempts)
	}
	if !strings.Contains(apiErr.Error(), "upstream provider error") {
		t.Errorf("error lost the vendor body: %s", apiErr.Error())
	}

	// What the user reads must not be the relay's nested JSON.
	reason := FailureReason(err)
	if strings.Contains(reason, "{") {
		t.Errorf("user-facing reason leaks raw JSON: %s", reason)
	}
	if !strings.Contains(reason, "rate limiting") {
		t.Errorf("user-facing reason = %q, want a rate-limit explanation", reason)
	}
	if !strings.Contains(reason, "We retried 2 times") {
		t.Errorf("user-facing reason = %q, want the retry count", reason)
	}
}

func TestSendDoesNotRetryClientErrors(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"unknown model"}`))
	}))
	defer srv.Close()

	_, err := Send(context.Background(), RetryOptions{
		Provider:  "openai",
		Client:    srv.Client(),
		BaseDelay: time.Millisecond,
		NewRequest: func(ctx context.Context) (*http.Request, error) {
			return http.NewRequestWithContext(ctx, http.MethodPost, srv.URL, strings.NewReader(`{}`))
		},
	})
	if err == nil {
		t.Fatal("Send succeeded, want 400")
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("requests sent = %d, want 1 (400 is not transient)", got)
	}
	// A configuration error keeps its detail — that is what makes it fixable.
	if reason := FailureReason(err); !strings.Contains(reason, "unknown model") {
		t.Errorf("reason = %q, want the vendor detail preserved", reason)
	}
}

func TestSendStopsRetryingWhenRunIsCancelled(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel while the retry is sleeping, the way pressing Stop does.
	_, err := Send(ctx, RetryOptions{
		Provider:  "openai",
		Client:    srv.Client(),
		BaseDelay: 50 * time.Millisecond,
		NewRequest: func(reqCtx context.Context) (*http.Request, error) {
			return http.NewRequestWithContext(reqCtx, http.MethodPost, srv.URL, strings.NewReader(`{}`))
		},
		OnRetry: func(attempt, status int, delay time.Duration, cause error) {
			go cancel()
		},
	})
	cancel()
	if err == nil {
		t.Fatal("Send succeeded, want failure")
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("requests sent = %d, want 1 (cancelled run must not retry)", got)
	}
	// A stop must not be reported as a provider problem.
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want context.Canceled", err)
	}
	var apiErr *APIStatusError
	if errors.As(err, &apiErr) {
		t.Errorf("a stopped run reported an upstream status: %v", err)
	}
}

func TestSendDoesNotRetryQuotaBlocksDressedAsRateLimits(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		// This is what our own relay answers when a user is out of credits.
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":"quota exceeded","reason":"monthly spend limit reached"}`))
	}))
	defer srv.Close()

	_, err := Send(context.Background(), RetryOptions{
		Provider:  "openai",
		Client:    srv.Client(),
		BaseDelay: time.Millisecond,
		NewRequest: func(ctx context.Context) (*http.Request, error) {
			return http.NewRequestWithContext(ctx, http.MethodPost, srv.URL, strings.NewReader(`{}`))
		},
	})
	if err == nil {
		t.Fatal("Send succeeded, want the quota error")
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("requests sent = %d, want 1 (waiting never clears a spent quota)", got)
	}
	// Telling this user to "wait a moment and try again" would be a lie; they
	// need the reason.
	reason := FailureReason(err)
	if !strings.Contains(reason, "monthly spend limit reached") {
		t.Errorf("reason = %q, want the quota explanation preserved", reason)
	}
	if strings.Contains(reason, "rate limiting") {
		t.Errorf("reason = %q, want it not to claim a transient rate limit", reason)
	}
}

func TestSendDoesNotRetryTransportFailures(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		// Kill the connection after the request was accepted — by this point a
		// real vendor may already be generating (and billing for) a response.
		panic(http.ErrAbortHandler)
	}))
	defer srv.Close()

	_, err := Send(context.Background(), RetryOptions{
		Provider:  "openai",
		Client:    srv.Client(),
		BaseDelay: time.Millisecond,
		NewRequest: func(ctx context.Context) (*http.Request, error) {
			return http.NewRequestWithContext(ctx, http.MethodPost, srv.URL, strings.NewReader(`{}`))
		},
	})
	if err == nil {
		t.Fatal("Send succeeded, want a transport error")
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("requests sent = %d, want 1 (a half-served request must not be duplicated)", got)
	}
	if !strings.Contains(err.Error(), "openai: send request") {
		t.Errorf("error = %v, want the client's send-request wording", err)
	}
}

func TestRetryAfterHint(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		body    string
		want    time.Duration
		wantOK  bool
	}{
		{
			name:    "seconds header",
			headers: http.Header{"Retry-After": []string{"3"}},
			want:    3 * time.Second,
			wantOK:  true,
		},
		{
			name:   "escaped body field",
			body:   openRouterRateLimitBody,
			want:   time.Second,
			wantOK: true,
		},
		{
			name:   "plain body field",
			body:   `{"retry_after_seconds": 5}`,
			want:   5 * time.Second,
			wantOK: true,
		},
		{
			name:   "no hint",
			body:   `{"error":"boom"}`,
			wantOK: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := retryAfterHint(tc.headers, []byte(tc.body))
			if ok != tc.wantOK {
				t.Fatalf("ok = %t, want %t", ok, tc.wantOK)
			}
			if ok && got != tc.want {
				t.Errorf("hint = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestRetryDelayUsesHintWhenItIsLongerThanTheBackoff(t *testing.T) {
	// 5s sits above the 2s first backoff step but inside the 8s ceiling.
	headers := http.Header{"Retry-After": []string{"5"}}
	got, worthwhile := retryDelay(1, streamRetryBaseDelay, headers, nil)
	if !worthwhile {
		t.Fatal("retry judged pointless for a hint we are willing to wait out")
	}
	if got < 5*time.Second || got > 5*time.Second+5*time.Second/4 {
		t.Errorf("delay = %s, want about the 5s the vendor asked for", got)
	}
}

func TestRetryDelayGivesUpWhenTheHintExceedsOurCeiling(t *testing.T) {
	headers := http.Header{"Retry-After": []string{"600"}}
	if _, worthwhile := retryDelay(1, streamRetryBaseDelay, headers, nil); worthwhile {
		t.Error("retried against a 10-minute hint; waiting 8s would not have cleared it")
	}
}

func TestRetryDelayRoundsShortHintsUpToTheBackoff(t *testing.T) {
	// The body asks for 1s; re-hitting a pool that fast rarely helps.
	got, worthwhile := retryDelay(1, streamRetryBaseDelay, nil, []byte(openRouterRateLimitBody))
	if !worthwhile {
		t.Fatal("retry judged pointless for a 1s hint")
	}
	if got < streamRetryBaseDelay {
		t.Errorf("delay = %s, want at least the %s backoff", got, streamRetryBaseDelay)
	}
}
