package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	internal "github.com/Problem99-io/kodeblue/internal"
)

func TestInitialContextDoesNotRunBeforeFirstQuestion(t *testing.T) {
	deps, loop := setupTestDeps(t)
	router := NewRouter(deps)
	context := "Task: Build a dashboard\nDescription: Implement charts\nBehavior guidelines: Ask before choosing a database."
	body, _ := json.Marshal(map[string]any{"initial_context": context})
	created := httptest.NewRecorder()
	router.ServeHTTP(created, httptest.NewRequest("POST", "/v1/sessions", bytes.NewReader(body)))
	if created.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", created.Code, created.Body.String())
	}
	var session internal.Session
	_ = json.Unmarshal(created.Body.Bytes(), &session)
	messages, err := deps.Messages.GetBySession(session.ID)
	if err != nil || len(messages) != 1 || messages[0].Content != context || messages[0].Role != "user" {
		t.Fatalf("context not saved separately: %+v, %v", messages, err)
	}
	runs, err := deps.Runs.GetBySession(session.ID)
	if err != nil || len(runs) != 0 || loop.runAsyncCalled {
		t.Fatalf("context started a run: %+v, %v", runs, err)
	}
	queue, err := deps.Queue.ListPending(session.ID)
	if err != nil || len(queue) != 0 {
		t.Fatalf("context queued a run: %+v, %v", queue, err)
	}
	question := "Is the database up?"
	body, _ = json.Marshal(map[string]any{"content": question})
	sent := httptest.NewRecorder()
	router.ServeHTTP(sent, httptest.NewRequest("POST", "/v1/sessions/"+string(session.ID)+"/messages", bytes.NewReader(body)))
	if sent.Code != http.StatusAccepted {
		t.Fatalf("send: %d %s", sent.Code, sent.Body.String())
	}
	if loop.runAsyncCount != 1 || loop.lastRunMessage != question {
		t.Fatalf("run trigger was not the question: %+v", loop)
	}
	messages, _ = deps.Messages.GetBySession(session.ID)
	if len(messages) != 1 || messages[0].Content != context {
		t.Fatalf("lost background: %+v", messages)
	}
}

func TestInitialContextFailureDoesNotLeaveUsableEmptySession(t *testing.T) {
	deps, loop := setupTestDeps(t)
	_, err := deps.DB.Exec(`CREATE TRIGGER reject_context BEFORE INSERT ON messages BEGIN SELECT RAISE(ABORT, 'context failed'); END`)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	NewRouter(deps).ServeHTTP(w, httptest.NewRequest("POST", "/v1/sessions", bytes.NewBufferString(`{"initial_context":"Task background"}`)))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected failure: %d %s", w.Code, w.Body.String())
	}
	sessions, err := deps.Sessions.List()
	if err != nil || len(sessions) != 0 || loop.runAsyncCalled {
		t.Fatalf("session survived failed context: %+v, %v", sessions, err)
	}
}
