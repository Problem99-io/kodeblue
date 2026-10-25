package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	internal "github.com/Problem99-io/kodeblue/internal"
	"github.com/Problem99-io/kodeblue/internal/state"
)

type sessionRuntimeStatusResponse struct {
	ProviderConnection json.RawMessage         `json:"provider_connection,omitempty"`
	LifecycleRepairs   []state.LifecycleRepair `json:"lifecycle_repairs"`
	SessionID          string                  `json:"session_id"`
	Status             string                  `json:"status"`
	IsRunning          bool                    `json:"is_running"`
	ActiveRunID        string                  `json:"active_run_id,omitempty"`
	LatestRun          *internal.Run           `json:"latest_run,omitempty"`
	PendingQuestions   int                     `json:"pending_questions"`
	PendingMessages    int                     `json:"pending_messages"`
	QueuePaused        bool                    `json:"queue_paused"`
	UpdatedAt          time.Time               `json:"updated_at"`
}

func handleGetSessionStatus(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID := internal.SessionID(r.PathValue("id"))

		status, err := buildSessionRuntimeStatus(deps, sessionID)
		if err != nil {
			switch err {
			case errSessionNotFound:
				writeError(w, http.StatusNotFound, "session not found")
			default:
				deps.Logger.Error("failed to build session status", "session_id", sessionID, "error", err)
				writeError(w, http.StatusInternalServerError, "failed to get session status")
			}
			return
		}

		writeJSON(w, http.StatusOK, status)
	}
}

var errSessionNotFound = fmt.Errorf("session not found")

func buildSessionRuntimeStatus(deps *Dependencies, sessionID internal.SessionID) (*sessionRuntimeStatusResponse, error) {
	// Queue dispatch consumes messages and creates/claims the next run together.
	// Read under that same guard so an old run snapshot cannot be combined with
	// the already-consumed queue and falsely reported as terminal.
	if guard, ok := deps.AgentLoop.(interface{ LockSessionDispatch() func() }); ok {
		unlock := guard.LockSessionDispatch()
		defer unlock()
	}
	session, err := deps.Sessions.Get(sessionID)
	if err != nil {
		return nil, err
	}
	if session == nil {
		return nil, errSessionNotFound
	}

	repairs, err := reconcileSessionBlockers(deps, sessionID)
	if err != nil {
		return nil, err
	}

	runs, err := deps.Runs.GetBySession(sessionID)
	if err != nil {
		return nil, err
	}

	pendingQuestions := deps.EventHub.ListPendingQuestions(sessionID)
	// Also count questions persisted in the DB but no longer held in memory — after a
	// restart the in-memory waiters are gone, yet the questions remain answerable, so
	// the session must still report as awaiting user input (not idle/completed).
	if deps.Questions != nil {
		cutoff := pendingQuestionCutoff
		stored, err := deps.Questions.ListPendingBySession(sessionID, cutoff)
		if err != nil {
			return nil, err
		}
		{
			seen := make(map[string]struct{}, len(pendingQuestions))
			for _, q := range pendingQuestions {
				seen[q.QuestionID] = struct{}{}
			}
			for _, q := range stored {
				if _, ok := seen[q.QuestionID]; ok {
					continue
				}
				pendingQuestions = append(pendingQuestions, q)
			}
		}
	}
	pendingQuestionCount := len(pendingQuestions)

	pendingMessageCount := 0
	queuePaused := false
	if deps.Queue != nil {
		if pendingMessageCount, err = deps.Queue.OutstandingCount(sessionID); err != nil {
			return nil, err
		}
		if queuePaused, err = deps.Queue.IsPaused(sessionID); err != nil {
			return nil, err
		}
	}

	var latestRun *internal.Run
	if len(runs) > 0 {
		latestRun = runs[0]
	}

	var activeRunID string
	isRunning := false
	for i := range runs {
		if runs[i].Status == internal.RunRunning && deps.AgentLoop.IsRunning(string(runs[i].ID)) {
			activeRunID = string(runs[i].ID)
			isRunning = true
			break
		}
	}

	status := "idle"
	switch {
	case pendingQuestionCount > 0:
		status = "awaiting_user"
	case isRunning:
		status = "running"
	case queuePaused && pendingMessageCount > 0:
		status = "paused"
	case pendingMessageCount > 0:
		status = "queued"
	case latestRun != nil && latestRun.Status == internal.RunFailed:
		status = "failed"
	case latestRun != nil && latestRun.Status == internal.RunAborted:
		status = "aborted"
	case latestRun != nil && latestRun.Status == internal.RunInterrupted:
		status = "interrupted"
	}

	var connection json.RawMessage
	if isRunning && deps.Events != nil {
		connection, err = deps.Events.LatestProviderConnection(internal.RunID(activeRunID))
		if err != nil {
			return nil, err
		}
	}

	return &sessionRuntimeStatusResponse{
		ProviderConnection: connection,
		LifecycleRepairs:   repairs,
		SessionID:          string(sessionID),
		Status:             status,
		IsRunning:          isRunning,
		ActiveRunID:        activeRunID,
		LatestRun:          latestRun,
		PendingQuestions:   pendingQuestionCount,
		PendingMessages:    pendingMessageCount,
		QueuePaused:        queuePaused,
		UpdatedAt:          time.Now(),
	}, nil
}
