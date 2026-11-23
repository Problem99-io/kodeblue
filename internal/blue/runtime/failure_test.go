package runtime

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// WaitSession keeps why a run failed, so an investigation that ends "failed"
// can say it was the provider's spending limit and not just "failed".
func TestWaitSessionKeepsFailureReason(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/sessions/s1/status":
			w.Write([]byte(`{"is_running":false,"pending_messages":0,"latest_run":{"id":"r1"}}`))
		case "/v1/sessions/s1/runs/r1/outcome":
			w.Write([]byte(`{"status":"failed","error":"key budget exhausted","error_class":"spend_limit","resets_at":"2026-11-24T00:00:00Z"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	k := &Engine{baseURL: srv.URL, http: srv.Client()}
	out := k.WaitSession(context.Background(), &Session{ID: "s1", RunID: "r1"}, 30*time.Second)
	if out.Status != "failed" || out.Error != "key budget exhausted" || out.ErrorClass != "spend_limit" {
		t.Fatalf("got %+v", out)
	}
	if want := time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC); !out.ResetsAt.Equal(want) {
		t.Fatalf("resets_at %v, want %v", out.ResetsAt, want)
	}
}

func TestFailureReason(t *testing.T) {
	resets := time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		out  Outcome
		want string
	}{
		{"completed", Outcome{Status: "completed", Error: "ignored"}, ""},
		{"no reason", Outcome{Status: "failed"}, ""},
		{"spend limit", Outcome{Status: "failed", Error: "key budget exhausted", ErrorClass: "spend_limit", ResetsAt: resets},
			"Model provider spending limit reached, resets at 2026-11-24T00:00:00Z: key budget exhausted"},
		{"quota", Outcome{Status: "failed", ErrorClass: "quota_exceeded"}, "Model provider spending limit reached."},
		{"rate limit", Outcome{Status: "failed", Error: "429 too many requests", ErrorClass: "rate_limit"},
			"Model provider rate limit hit: 429 too many requests"},
		{"other class", Outcome{Status: "failed", Error: "reset by peer", ErrorClass: "connection_reset"},
			"Model provider error (connection_reset): reset by peer"},
		{"message only", Outcome{Status: "failed", Error: "  context too long  "}, "context too long"},
	}
	for _, c := range cases {
		if got := c.out.FailureReason(); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
	long := Outcome{Status: "failed", Error: strings.Repeat("x", 500)}
	if got := long.FailureReason(); len(got) != 400+len("…") {
		t.Errorf("long error not clipped: %d bytes", len(got))
	}
}
