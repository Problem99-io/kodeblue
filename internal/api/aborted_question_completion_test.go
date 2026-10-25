package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	internal "github.com/Problem99-io/kodeblue/internal"
)

func TestAbortedRunQuestionDoesNotBlockLaterCompletion(t *testing.T) {
	for _, questionStatus := range []string{"pending", "resuming"} {
		t.Run(questionStatus, func(t *testing.T) {
			deps, mock := setupTestDeps(t)
			router := NewRouter(deps)
			session, oldRun := seedSessionAndRun(t, deps, router)
			oldRun.Status = internal.RunAborted
			if err := deps.Runs.Update(oldRun); err != nil {
				t.Fatal(err)
			}
			latest := &internal.Run{ID: internal.NewRunID(), SessionID: session.ID, Status: internal.RunCompleted, CreatedAt: time.Now().Add(time.Second)}
			if err := deps.Runs.Create(latest); err != nil {
				t.Fatal(err)
			}
			q := internal.PendingQuestion{QuestionID: "obsolete", SessionID: session.ID, RunID: oldRun.ID, Question: "Old setup question", CreatedAt: time.Now().Add(-29 * 24 * time.Hour)}
			if err := deps.Questions.Create(q); err != nil {
				t.Fatal(err)
			}
			if questionStatus == "resuming" {
				if err := deps.Questions.Resolve(q.QuestionID, questionStatus, internal.QuestionAnswer{}); err != nil {
					t.Fatal(err)
				}
			}
			w := httptest.NewRecorder()
			router.ServeHTTP(w, httptest.NewRequest("GET", "/v1/sessions/"+string(session.ID)+"/status", nil))
			var status sessionRuntimeStatusResponse
			if w.Code != http.StatusOK {
				t.Fatalf("status HTTP %d: %s", w.Code, w.Body.String())
			}
			if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
				t.Fatal(err)
			}
			if status.Status != "idle" || status.IsRunning || status.PendingQuestions != 0 || status.LatestRun.ID != latest.ID {
				t.Fatalf("obsolete question blocks completed session: %+v", status)
			}
			w = httptest.NewRecorder()
			router.ServeHTTP(w, httptest.NewRequest("GET", "/v1/sessions/"+string(session.ID)+"/pending", nil))
			var pending sessionPendingResponse
			if err := json.Unmarshal(w.Body.Bytes(), &pending); err != nil {
				t.Fatal(err)
			}
			if w.Code != http.StatusOK || pending.TotalPending != 0 {
				t.Fatalf("obsolete question exposed: %s", w.Body.String())
			}
			w = httptest.NewRecorder()
			router.ServeHTTP(w, httptest.NewRequest("POST", "/v1/questions/obsolete/answer", bytes.NewBufferString(`{"mode":"single_select","text":"yes"}`)))
			if w.Code != http.StatusConflict || mock.runAsyncCount != 0 {
				t.Fatalf("aborted question resumed: HTTP %d, dispatches=%d", w.Code, mock.runAsyncCount)
			}
		})
	}
}

func TestRecoverableQuestionsStillBlockCompletion(t *testing.T) {
	for _, owner := range []string{"running", "interrupted", "subagent"} {
		t.Run(owner, func(t *testing.T) {
			deps, _ := setupTestDeps(t)
			router := NewRouter(deps)
			session, run := seedSessionAndRun(t, deps, router)
			if owner == "interrupted" {
				run.Status = internal.RunInterrupted
				if err := deps.Runs.Update(run); err != nil {
					t.Fatal(err)
				}
			}
			runID := run.ID
			if owner == "subagent" {
				runID = internal.NewRunID()
			}
			if err := deps.Questions.Create(internal.PendingQuestion{QuestionID: "recoverable", SessionID: session.ID, RunID: runID, Question: "Still needs an answer", CreatedAt: time.Now()}); err != nil {
				t.Fatal(err)
			}
			status, err := buildSessionRuntimeStatus(deps, session.ID)
			if err != nil {
				t.Fatal(err)
			}
			if status.Status != "awaiting_user" || status.PendingQuestions != 1 {
				t.Fatalf("recoverable question lost: %+v", status)
			}
		})
	}
}
