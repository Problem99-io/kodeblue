package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	internal "github.com/Problem99-io/kodeblue/internal"
)

type createSessionRequest struct {
	Provider     string   `json:"provider"`
	Model        string   `json:"model"`
	AgentID      string   `json:"agent_id"`
	AgentName    string   `json:"agent_name"`
	CWD          string   `json:"cwd"`
	Instructions []string `json:"instructions"`
	// InitialContext is a separate user message saved before the first request.
	// It supplies background without starting or queuing an agent run.
	InitialContext string `json:"initial_context"`
}

func handleCreateSession(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req createSessionRequest
		if err := readJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}

		// Resolve agent by ID or name
		var agentDef *internal.AgentDefinition
		if req.AgentID != "" {
			a, err := deps.Agents.Get(req.AgentID)
			if err != nil {
				deps.Logger.Error("failed to get agent", "error", err)
				writeError(w, http.StatusInternalServerError, "failed to resolve agent")
				return
			}
			if a == nil {
				writeError(w, http.StatusBadRequest, "agent not found: "+req.AgentID)
				return
			}
			agentDef = a
		} else if req.AgentName != "" {
			a, err := deps.Agents.GetByName(req.AgentName)
			if err != nil {
				deps.Logger.Error("failed to get agent by name", "error", err)
				writeError(w, http.StatusInternalServerError, "failed to resolve agent")
				return
			}
			if a == nil {
				writeError(w, http.StatusBadRequest, "agent not found: "+req.AgentName)
				return
			}
			agentDef = a
		}

		providerName := req.Provider
		model := req.Model
		agentID := ""

		// Apply agent defaults (session-level values take precedence)
		if agentDef != nil {
			agentID = agentDef.ID
			if providerName == "" && agentDef.Provider != "" {
				providerName = agentDef.Provider
			}
			if model == "" && agentDef.Model != "" {
				model = agentDef.Model
			}
		}

		now := time.Now()

		// Validate and resolve cwd if provided.
		resolvedCWD := ""
		if req.CWD != "" {
			var abs string
			if filepath.IsAbs(req.CWD) {
				abs = filepath.Clean(req.CWD)
			} else {
				abs = filepath.Clean(filepath.Join(deps.ProjectRoot, req.CWD))
			}
			rel, err := filepath.Rel(deps.ProjectRoot, abs)
			if err != nil || strings.HasPrefix(rel, "..") {
				writeError(w, http.StatusBadRequest, "cwd must be within the project root")
				return
			}
			info, err := os.Stat(abs)
			if err != nil || !info.IsDir() {
				writeError(w, http.StatusBadRequest, "cwd must be an existing directory within the project root")
				return
			}
			resolvedCWD = abs
		}

		session := &internal.Session{
			ID:           internal.NewSessionID(),
			Status:       internal.SessionActive,
			Provider:     providerName,
			Model:        model,
			AgentID:      agentID,
			CWD:          resolvedCWD,
			Instructions: req.Instructions,
			CreatedAt:    now,
			UpdatedAt:    now,
		}

		if err := deps.Sessions.Create(session); err != nil {
			deps.Logger.Error("failed to create session", "error", err)
			writeError(w, http.StatusInternalServerError, "failed to create session")
			return
		}

		if strings.TrimSpace(req.InitialContext) != "" {
			message := &internal.Message{ID: internal.NewMessageID(), Role: "user", Content: req.InitialContext, CreatedAt: now}
			if err := deps.Messages.Create(session.ID, "", message); err != nil {
				_ = deps.Sessions.Delete(session.ID)
				deps.Logger.Error("failed to save initial session context", "error", err)
				writeError(w, http.StatusInternalServerError, "failed to save initial session context")
				return
			}
		}

		writeJSON(w, http.StatusCreated, session)
	}
}

func handleGetSession(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := internal.SessionID(r.PathValue("id"))

		session, err := deps.Sessions.Get(id)
		if err != nil {
			deps.Logger.Error("failed to get session", "error", err)
			writeError(w, http.StatusInternalServerError, "failed to get session")
			return
		}
		if session == nil {
			writeError(w, http.StatusNotFound, "session not found")
			return
		}

		writeJSON(w, http.StatusOK, session)
	}
}

func handleListSessions(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessions, err := deps.Sessions.List()
		if err != nil {
			deps.Logger.Error("failed to list sessions", "error", err)
			writeError(w, http.StatusInternalServerError, "failed to list sessions")
			return
		}
		if sessions == nil {
			sessions = []*internal.Session{}
		}

		writeJSON(w, http.StatusOK, sessions)
	}
}
