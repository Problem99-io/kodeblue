package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	internal "github.com/Problem99-io/kodeblue/internal"
	"github.com/Problem99-io/kodeblue/internal/agent"
)

func TestTaskieSessionIdentityPersistsIntoSystemPrompt(t *testing.T) {
	deps, _ := setupTestDeps(t)
	instruction := "Taskie identity:\nYou are Fidget, the Taskie assigned to this task."
	body, _ := json.Marshal(map[string]any{"instructions": []string{instruction}})
	w := httptest.NewRecorder()
	NewRouter(deps).ServeHTTP(w, httptest.NewRequest("POST", "/v1/sessions", bytes.NewReader(body)))
	if w.Code != http.StatusCreated {
		t.Fatalf("create session: %d: %s", w.Code, w.Body.String())
	}
	var created internal.Session
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	session, err := deps.Sessions.Get(created.ID)
	if err != nil || session == nil {
		t.Fatalf("load persisted session: %v", err)
	}
	if len(session.Instructions) != 1 || session.Instructions[0] != instruction {
		t.Fatalf("identity did not survive persistence: %v", session.Instructions)
	}
	prompt := agent.BuildSystemPrompt(agent.RunConfig{BaseDirectory: t.TempDir(), Instructions: session.Instructions})
	if !strings.Contains(prompt, instruction) {
		t.Errorf("system prompt missing %q", instruction)
	}
}
