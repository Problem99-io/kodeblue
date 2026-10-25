package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	internal "github.com/Problem99-io/kodeblue/internal"
	"github.com/Problem99-io/kodeblue/internal/state"
)

func TestLifecycleReconciliationUnsticksCompletedSessionAndRejectsLateAnswers(t *testing.T) {
	deps, loop := setupTestDeps(t)
	now := time.Now()
	sessionID := internal.SessionID("session-repair")
	if err := deps.Sessions.Create(&internal.Session{ID: sessionID, Status: internal.SessionActive, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	for _, run := range []*internal.Run{
		{ID: "old", SessionID: sessionID, Status: internal.RunAborted, CreatedAt: now.Add(-24 * time.Hour)},
		{ID: "latest", SessionID: sessionID, Status: internal.RunCompleted, CreatedAt: now},
	} {
		if err := deps.Runs.Create(run); err != nil {
			t.Fatal(err)
		}
	}
	q := internal.PendingQuestion{QuestionID: "question", RunID: "old", SessionID: sessionID, Mode: "single_select", CreatedAt: now}
	if err := deps.Questions.Create(q); err != nil {
		t.Fatal(err)
	}
	questionWait := deps.EventHub.RegisterQuestionWait(q)
	router := NewRouter(deps)
	for i := 0; i < 2; i++ {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/sessions/"+string(sessionID)+"/status", nil))
		if response.Code != 200 {
			t.Fatalf("status %d: %s", response.Code, response.Body.String())
		}
		var got sessionRuntimeStatusResponse
		if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got.Status != "idle" || got.PendingQuestions != 0 || len(got.LifecycleRepairs) != 1 || got.LatestRun.ID != "latest" {
			t.Fatalf("status %+v", got)
		}
	}
	select {
	case _, ok := <-questionWait:
		if ok {
			t.Fatal("sent fabricated answer")
		}
	default:
		t.Fatal("obsolete question waiter left open")
	}
	for _, input := range []struct{ path, body string }{
		{"/v1/questions/question/answer", `{"mode":"single_select","text":"yes"}`},
	} {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, input.path, strings.NewReader(input.body)))
		if response.Code != http.StatusConflict {
			t.Fatalf("late response %s: %d %s", input.path, response.Code, response.Body.String())
		}
	}
	if loop.runAsyncCalled {
		t.Fatal("resurrected terminal run")
	}
}

func TestLifecyclePreservesOldInterruptedInputAndQueueClaims(t *testing.T) {
	deps, _ := setupTestDeps(t)
	now := time.Now()
	id := internal.SessionID("interrupted")
	if err := deps.Sessions.Create(&internal.Session{ID: id, Status: internal.SessionActive, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := deps.Runs.Create(&internal.Run{ID: "run", SessionID: id, Status: internal.RunInterrupted, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := deps.Questions.Create(internal.PendingQuestion{QuestionID: "old-q", RunID: "run", SessionID: id, CreatedAt: now.Add(-60 * 24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	router := NewRouter(deps)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/sessions/interrupted/pending", nil))
	if response.Code != 200 || !strings.Contains(response.Body.String(), "old-q") {
		t.Fatalf("lost old question: %d %s", response.Code, response.Body.String())
	}
	status, err := buildSessionRuntimeStatus(deps, id)
	if err != nil || status.Status != "awaiting_user" {
		t.Fatalf("status %+v %v", status, err)
	}
	if err := deps.Questions.Resolve("old-q", state.PendingQuestionStatusAnswered, internal.QuestionAnswer{QuestionID: "old-q"}); err != nil {
		t.Fatal(err)
	}
	if _, err := deps.Queue.Enqueue(&internal.QueueItem{SessionID: id, Source: internal.QueueItemSourceUser, Content: "queued work"}); err != nil {
		t.Fatal(err)
	}
	if _, err := deps.Queue.ClaimPending(id, "run"); err != nil {
		t.Fatal(err)
	}
	status, err = buildSessionRuntimeStatus(deps, id)
	if err != nil || status.PendingMessages != 1 || status.Status != "queued" {
		t.Fatalf("lost claimed input: %+v %v", status, err)
	}
}
