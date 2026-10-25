package api

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	internal "github.com/Problem99-io/kodeblue/internal"
	"github.com/Problem99-io/kodeblue/internal/state"
)

func TestContinuationResumeFailureRemainsRetryable(t *testing.T) {
	deps, mock := setupTestDeps(t)
	router := NewRouter(deps)
	session, run := seedSessionAndRun(t, deps, router)
	if err := deps.Questions.Create(internal.PendingQuestion{QuestionID: "resume-retry", SessionID: session.ID, RunID: run.ID, Kind: internal.QuestionKindContinuation, Question: "Keep going?", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	answer := func() int {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("POST", "/v1/questions/resume-retry/answer", bytes.NewBufferString(`{"mode":"single_select","choices":["Yes, keep going"]}`)))
		return w.Code
	}
	mock.runErr = errors.New("provider temporarily unavailable")
	if got := answer(); got != http.StatusInternalServerError {
		t.Fatalf("status=%d", got)
	}
	_, status, err := deps.Questions.Get("resume-retry")
	if err != nil || status != state.PendingQuestionStatusPending {
		t.Fatalf("status=%s err=%v", status, err)
	}
	runs, err := deps.Runs.GetBySession(session.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range runs {
		if r.ID != run.ID && r.Status != internal.RunFailed {
			t.Fatalf("failed dispatch left run %s in %s", r.ID, r.Status)
		}
	}
	mock.runErr = nil
	if got := answer(); got != http.StatusOK {
		t.Fatalf("retry status=%d", got)
	}
	if got := answer(); got != http.StatusConflict {
		t.Fatalf("duplicate status=%d", got)
	}
	if mock.runAsyncCount != 2 {
		t.Fatalf("dispatches=%d", mock.runAsyncCount)
	}
}

func TestContinuationInterruptedAnswerRemainsVisibleAndDoesNotDuplicateCompletedResume(t *testing.T) {
	deps, mock := setupTestDeps(t)
	router := NewRouter(deps)
	session, run := seedSessionAndRun(t, deps, router)
	question := internal.PendingQuestion{QuestionID: "crash-answer", SessionID: session.ID, RunID: run.ID, Kind: internal.QuestionKindContinuation, Question: "Keep going?", CreatedAt: time.Now()}
	if err := deps.Questions.Create(question); err != nil {
		t.Fatal(err)
	}
	if err := deps.Questions.Resolve(question.QuestionID, "resuming", internal.QuestionAnswer{Choices: []string{internal.ContinueYesOption}}); err != nil {
		t.Fatal(err)
	}
	pending, err := deps.Questions.ListPendingBySession(session.ID, time.Now().Add(-time.Hour))
	if err != nil || len(pending) != 1 {
		t.Fatalf("interrupted answer disappeared: %v %v", pending, err)
	}
	resume := &internal.Run{ID: internal.RunID("run_resume_" + string(run.ID)), SessionID: session.ID, Status: internal.RunCompleted, CreatedAt: time.Now()}
	if err := deps.Runs.Create(resume); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/v1/questions/crash-answer/answer", bytes.NewBufferString(`{"mode":"single_select","choices":["Yes, keep going"]}`)))
	if w.Code != http.StatusOK || mock.runAsyncCount != 0 {
		t.Fatalf("completed resume duplicated: status=%d calls=%d", w.Code, mock.runAsyncCount)
	}
}
