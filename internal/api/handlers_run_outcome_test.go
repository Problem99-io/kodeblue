package api

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	internal "github.com/Problem99-io/kodeblue/internal"
)

func TestRunOutcomeBindsSessionAndExcludesOtherRuns(t *testing.T) {
	deps, _ := setupTestDeps(t)
	now := time.Now()
	session := &internal.Session{ID: internal.NewSessionID(), Status: internal.SessionActive, CreatedAt: now, UpdatedAt: now}
	if err := deps.Sessions.Create(session); err != nil {
		t.Fatal(err)
	}
	run := &internal.Run{ID: internal.NewRunID(), SessionID: session.ID, Status: internal.RunRunning, CreatedAt: now}
	if err := deps.Runs.Create(run); err != nil {
		t.Fatal(err)
	}
	router := NewRouter(deps)
	get := func(s string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("GET", "/v1/sessions/"+s+"/runs/"+string(run.ID)+"/outcome", nil))
		return w
	}
	if w := get("other-session"); w.Code != 404 {
		t.Fatalf("wrong session: %d", w.Code)
	}
	if w := get(string(session.ID)); w.Code != 200 || !strings.Contains(w.Body.String(), `"running"`) {
		t.Fatal(w.Body.String())
	}
	for _, item := range []struct {
		id         internal.RunID
		kind, text string
	}{
		{internal.NewRunID(), internal.EventRunCompleted, "OTHER-RUN-SECRET"},
		{run.ID, internal.EventToolOutput, "TOOL-SECRET"},
		{run.ID, internal.EventRunCompleted, strings.Repeat("界", 12001)},
	} {
		payload, _ := json.Marshal(map[string]any{"final_content": item.text, "reasoning": "HIDDEN"})
		if err := deps.Events.Append(&internal.Event{SessionID: session.ID, RunID: item.id, Type: item.kind, Payload: payload, Timestamp: now}); err != nil {
			t.Fatal(err)
		}
	}
	w := get(string(session.ID))
	var result struct {
		Text, Status string
		Truncated    bool
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Status != "completed" || len([]rune(result.Text)) != 12000 || !result.Truncated {
		t.Fatalf("bad outcome: %s, length %d", result.Status, len([]rune(result.Text)))
	}
	if strings.Contains(w.Body.String(), "SECRET") || strings.Contains(w.Body.String(), "HIDDEN") {
		t.Fatal("exposed unrelated data")
	}
}

// A failed run says why, as the agent loop wrote it for people: the daemon
// shows it on the case (a provider's rate limit, a spend cap).
func TestRunOutcomeSaysWhyARunFailed(t *testing.T) {
	deps, _ := setupTestDeps(t)
	now := time.Now()
	session := &internal.Session{ID: internal.NewSessionID(), Status: internal.SessionActive, CreatedAt: now, UpdatedAt: now}
	run := &internal.Run{ID: internal.NewRunID(), SessionID: session.ID, Status: internal.RunFailed, CreatedAt: now}
	if deps.Sessions.Create(session) != nil || deps.Runs.Create(run) != nil {
		t.Fatal("setup")
	}
	payload, _ := json.Marshal(map[string]any{"reason": "Rate limit exceeded: free-models-per-day.", "http_status": 429, "failure_class": "rate_limited"})
	if err := deps.Events.Append(&internal.Event{SessionID: session.ID, RunID: run.ID, Type: internal.EventRunFailed, Payload: payload, Timestamp: now}); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	NewRouter(deps).ServeHTTP(w, httptest.NewRequest("GET", "/v1/sessions/"+string(session.ID)+"/runs/"+string(run.ID)+"/outcome", nil))
	var out struct{ Status, Error string }
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if out.Status != "failed" || out.Error != "Rate limit exceeded: free-models-per-day. (HTTP 429)" {
		t.Fatalf("outcome: %s", w.Body.String())
	}
}
