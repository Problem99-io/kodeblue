package runtime

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func fastDispatch(t *testing.T) {
	t.Helper()
	w, b, p := dispatchWait, dispatchWaitBusy, dispatchPoll
	dispatchWait, dispatchWaitBusy, dispatchPoll = time.Second, 2*time.Second, 10*time.Millisecond
	t.Cleanup(func() { dispatchWait, dispatchWaitBusy, dispatchPoll = w, b, p })
}

// The engine keeps a message it could not dispatch at once (provider still
// registering) in the inbox and starts it on retry. That is a started
// session, not "no run started".
func TestStartSessionWaitsForQueuedDispatch(t *testing.T) {
	fastDispatch(t)
	var polls atomic.Int32
	var resumed atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "POST /v1/sessions":
			w.Write([]byte(`{"id":"s1"}`))
		case "POST /v1/sessions/s1/messages":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			resumed.Store(body["resume"] == true)
			w.Write([]byte(`{"run_id":"","status":"queued","queue_item":{"id":"q1"}}`))
		case "GET /v1/sessions/s1/queue":
			if polls.Add(1) < 3 {
				w.Write([]byte(`{"items":[{"id":"q1"}],"paused":false}`))
				return
			}
			w.Write([]byte(`{"items":[],"paused":false}`))
		case "GET /v1/sessions/s1/status":
			if polls.Load() < 3 {
				w.Write([]byte(`{"is_running":false}`))
				return
			}
			w.Write([]byte(`{"is_running":true,"active_run_id":"r1"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	k := &Engine{baseURL: srv.URL, http: srv.Client(), agents: map[string]string{"blue-operator": "a1"}}
	s, err := k.StartSession(context.Background(), "blue-operator", "", "", "hello")
	if err != nil || s.RunID != "r1" || !resumed.Load() {
		t.Fatalf("got %+v, %v (resume sent: %v)", s, err, resumed.Load())
	}
}

// When the engine pauses delivery, the caller gets the engine's reason, and
// the message is withdrawn so it does not run after being reported failed.
func TestStartSessionReportsPauseReasonAndWithdraws(t *testing.T) {
	fastDispatch(t)
	var deleted atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "POST /v1/sessions":
			w.Write([]byte(`{"id":"s1"}`))
		case "POST /v1/sessions/s1/messages":
			w.Write([]byte(`{"run_id":"","status":"queued","queue_item":{"id":"q1"}}`))
		case "GET /v1/sessions/s1/queue":
			w.Write([]byte(`{"items":[{"id":"q1"}],"paused":true,"failure_reason":"provider not available: dedi:openai"}`))
		case "GET /v1/sessions/s1/status":
			w.Write([]byte(`{"is_running":false}`))
		case "DELETE /v1/sessions/s1/queue/q1":
			deleted.Store(true)
			w.Write([]byte(`{}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	k := &Engine{baseURL: srv.URL, http: srv.Client(), agents: map[string]string{"blue-operator": "a1"}}
	_, err := k.StartSession(context.Background(), "blue-operator", "", "", "hello")
	if err == nil || !strings.Contains(err.Error(), "provider not available: dedi:openai") || !deleted.Load() {
		t.Fatalf("err=%v deleted=%v", err, deleted.Load())
	}
}

// A message that never leaves the inbox of an idle session times out with a
// reason instead of an empty one.
func TestFollowUpTimesOutWithReason(t *testing.T) {
	fastDispatch(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "POST /v1/sessions/s1/messages":
			w.Write([]byte(`{"status":"queued","queue_item":{"id":"q1"}}`))
		case "GET /v1/sessions/s1/queue":
			w.Write([]byte(`{"items":[{"id":"q1"}]}`))
		case "GET /v1/sessions/s1/status":
			w.Write([]byte(`{"is_running":false}`))
		default:
			w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()
	k := &Engine{baseURL: srv.URL, http: srv.Client()}
	_, err := k.FollowUp(context.Background(), &Session{ID: "s1"}, "continue")
	if err == nil || !strings.Contains(err.Error(), "did not start a run") {
		t.Fatalf("err=%v", err)
	}
}
