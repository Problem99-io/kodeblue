package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	internal "github.com/Problem99-io/kodeblue/internal"
)

func TestSessionQueueEditValidatesAndRejectsConflicts(t *testing.T) {
	deps, _ := setupTestDeps(t)
	router := NewRouter(deps)
	session := &internal.Session{ID: internal.NewSessionID(), Status: internal.SessionActive, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := deps.Sessions.Create(session); err != nil {
		t.Fatal(err)
	}
	item, err := deps.Queue.Enqueue(&internal.QueueItem{SessionID: session.ID, Source: internal.QueueItemSourceUser, Content: "original"})
	if err != nil {
		t.Fatal(err)
	}
	patch := func(id internal.QueueItemID, body string, want int) {
		t.Helper()
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodPatch, "/v1/sessions/"+string(session.ID)+"/queue/"+string(id), strings.NewReader(body)))
		if w.Code != want {
			t.Fatalf("patch status = %d want %d: %s", w.Code, want, w.Body.String())
		}
	}
	patch(item.ID, `{"content":"  ","expected_content":"original"}`, http.StatusBadRequest)
	patch(item.ID, `{"content":"edited"}`, http.StatusBadRequest)
	patch(item.ID, `{"content":"edited","expected_content":"original"}`, http.StatusOK)
	patch(item.ID, `{"content":"stale","expected_content":"original"}`, http.StatusConflict)
	if _, err := deps.Queue.ClaimPending(session.ID, "run-edit"); err != nil {
		t.Fatal(err)
	}
	patch(item.ID, `{"content":"too late","expected_content":"edited"}`, http.StatusConflict)
}
