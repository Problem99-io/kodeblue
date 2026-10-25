package api

import (
	"encoding/json"
	"net/http"
	"strings"

	internal "github.com/Problem99-io/kodeblue/internal"
)

type sessionQueueResponse struct {
	Items  []internal.QueueItem `json:"items"`
	Count  int                  `json:"count"`
	Paused bool                 `json:"paused"`
	// FailureReason explains a pause caused by undeliverable queued input.
	FailureReason string `json:"failure_reason,omitempty"`
}

func requireQueueSession(deps *Dependencies, w http.ResponseWriter, sessionID internal.SessionID) bool {
	session, err := deps.Sessions.Get(sessionID)
	if err != nil {
		deps.Logger.Error("failed to load queue session", "session_id", sessionID, "error", err)
		writeError(w, http.StatusInternalServerError, "failed to load session")
		return false
	}
	if session == nil {
		writeError(w, http.StatusNotFound, "session not found")
		return false
	}
	return true
}

func handleGetSessionQueue(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID := internal.SessionID(r.PathValue("id"))
		if !requireQueueSession(deps, w, sessionID) {
			return
		}
		if deps.Queue == nil {
			writeError(w, http.StatusServiceUnavailable, "session queue is not available")
			return
		}
		items, err := deps.Queue.ListPending(sessionID)
		if err != nil {
			deps.Logger.Error("failed to list session queue", "session_id", sessionID, "error", err)
			writeError(w, http.StatusInternalServerError, "failed to list session queue")
			return
		}
		paused, err := deps.Queue.IsPaused(sessionID)
		if err != nil {
			deps.Logger.Error("failed to read session queue state", "session_id", sessionID, "error", err)
			writeError(w, http.StatusInternalServerError, "failed to read session queue state")
			return
		}
		failureReason, err := deps.Queue.FailureReason(sessionID)
		if err != nil {
			deps.Logger.Error("failed to read session queue failure", "session_id", sessionID, "error", err)
			writeError(w, http.StatusInternalServerError, "failed to read session queue state")
			return
		}
		writeJSON(w, http.StatusOK, sessionQueueResponse{Items: items, Count: len(items), Paused: paused, FailureReason: failureReason})
	}
}

func handleUpdateSessionQueueItem(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID := internal.SessionID(r.PathValue("id"))
		itemID := internal.QueueItemID(r.PathValue("itemId"))
		if !requireQueueSession(deps, w, sessionID) {
			return
		}
		if deps.MessageQueue == nil {
			writeError(w, http.StatusServiceUnavailable, "session queue is not available")
			return
		}
		var body struct {
			Content         string  `json:"content"`
			ExpectedContent *string `json:"expected_content"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20)).Decode(&body); err != nil || strings.TrimSpace(body.Content) == "" || body.ExpectedContent == nil {
			writeError(w, http.StatusBadRequest, "content and expected_content are required")
			return
		}
		updated, err := deps.MessageQueue.UpdateQueuedUser(sessionID, itemID, body.Content, *body.ExpectedContent)
		if err != nil {
			deps.Logger.Error("failed to edit queued message", "session_id", sessionID, "item_id", itemID, "error", err)
			writeError(w, http.StatusInternalServerError, "failed to edit queued message")
			return
		}
		if !updated {
			writeError(w, http.StatusConflict, "queued message changed or is already being delivered; refresh the queue")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "updated", "id": itemID})
	}
}

func handleRemoveSessionQueueItem(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID := internal.SessionID(r.PathValue("id"))
		itemID := internal.QueueItemID(r.PathValue("itemId"))
		if !requireQueueSession(deps, w, sessionID) {
			return
		}
		if deps.Queue == nil || deps.MessageQueue == nil {
			writeError(w, http.StatusServiceUnavailable, "session queue is not available")
			return
		}
		items, err := deps.Queue.ListPending(sessionID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to inspect queued message")
			return
		}
		found := false
		for i := range items {
			if items[i].ID != itemID {
				continue
			}
			found = true
			if items[i].Source != internal.QueueItemSourceUser {
				writeError(w, http.StatusConflict, "only queued user messages can be removed")
				return
			}
			break
		}
		if !found {
			writeError(w, http.StatusNotFound, "queued message not found or already delivered")
			return
		}
		removed, err := deps.MessageQueue.RemoveQueuedUser(sessionID, itemID)
		if err != nil {
			deps.Logger.Error("failed to remove queued user message", "session_id", sessionID, "item_id", itemID, "error", err)
			writeError(w, http.StatusInternalServerError, "failed to remove queued message")
			return
		}
		if !removed {
			writeError(w, http.StatusConflict, "queued message is already being delivered")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "removed", "id": itemID})
	}
}

func handleSteerSessionQueue(deps *Dependencies) http.HandlerFunc {
	return queueActionHandler(deps, "steer")
}

func handleContinueSessionQueue(deps *Dependencies) http.HandlerFunc {
	return queueActionHandler(deps, "continue")
}

func queueActionHandler(deps *Dependencies, action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID := internal.SessionID(r.PathValue("id"))
		if !requireQueueSession(deps, w, sessionID) {
			return
		}
		if deps.MessageQueue == nil {
			writeError(w, http.StatusServiceUnavailable, "session queue is not available")
			return
		}
		var (
			result QueueActionResult
			err    error
		)
		if action == "steer" {
			result, err = deps.MessageQueue.Steer(sessionID)
		} else {
			result, err = deps.MessageQueue.Continue(sessionID)
		}
		if err != nil {
			deps.Logger.Error("session queue action failed", "session_id", sessionID, "action", action, "error", err)
			writeError(w, http.StatusInternalServerError, "session queue action failed")
			return
		}
		status := http.StatusOK
		if result.Status == "interrupting" || result.Status == "started" {
			status = http.StatusAccepted
		}
		writeJSON(w, status, result)
	}
}
