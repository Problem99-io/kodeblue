package runtime

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// A steer replaces the run being waited on; WaitSession follows the session
// to the outcome of the last run, not the first.
func TestWaitSessionFollowsSteeredRun(t *testing.T) {
	var polls atomic.Int32
	var steered atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/sessions/s1/messages":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			steered.Store(body["steer"] == true)
			w.Write([]byte(`{}`))
		case "/v1/sessions/s1/status":
			if polls.Add(1) == 1 {
				w.Write([]byte(`{"is_running":true,"active_run_id":"r2","pending_messages":0}`))
				return
			}
			w.Write([]byte(`{"is_running":false,"pending_messages":0,"latest_run":{"id":"r2"}}`))
		case "/v1/sessions/s1/runs/r2/outcome":
			w.Write([]byte(`{"status":"completed","text":"contained"}`))
		case "/v1/sessions/s1/runs/r1/outcome":
			w.Write([]byte(`{"status":"aborted"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	k := &Engine{baseURL: srv.URL, http: srv.Client()}
	s := &Session{ID: "s1", RunID: "r1"}
	if err := k.Steer(context.Background(), s, "new findings"); err != nil || !steered.Load() {
		t.Fatalf("steer: err=%v steered=%v", err, steered.Load())
	}
	out := k.WaitSession(context.Background(), s, 30*time.Second)
	if out.Status != "completed" || out.Text != "contained" || s.RunID != "r2" {
		t.Fatalf("got %+v run %s", out, s.RunID)
	}
}
