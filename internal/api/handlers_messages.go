package api

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	internal "github.com/Problem99-io/kodeblue/internal"
)

type sendMessageRequest struct {
	Resume          bool                  `json:"resume,omitempty"`
	SteerNow        bool                  `json:"steer,omitempty"`
	RejectIfBusy    bool                  `json:"reject_if_busy,omitempty"`
	Content         string                `json:"content"`
	ClientMessageID string                `json:"client_message_id,omitempty"`
	Attachments     []internal.Attachment `json:"attachments,omitempty"`
	Model           string                `json:"model,omitempty"`
	Provider        string                `json:"provider,omitempty"`
	ReasoningEffort string                `json:"reasoning_effort,omitempty"`
}

type compactSessionRequest struct {
	Model    string `json:"model,omitempty"`
	Provider string `json:"provider,omitempty"`
}

type messageResponse struct {
	ID          string                 `json:"id"`
	Role        string                 `json:"role"`
	Content     string                 `json:"content"`
	Attachments []internal.Attachment  `json:"attachments"`
	ToolCalls   []internal.ToolCall    `json:"tool_calls"`
	ToolResults []internal.ToolResult  `json:"tool_results"`
	Usage       *internal.MessageUsage `json:"usage,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	// ReasoningContent is only filled when the caller asks for it with
	// ?include_reasoning=1 (kodeblue shows its agents' reasoning to operators).
	ReasoningContent string `json:"reasoning_content,omitempty"`
}

func normalizeMessagesForResponse(messages []internal.Message) []messageResponse {
	messages = messagesForPublicResponse(messages)
	if len(messages) == 0 {
		return []messageResponse{}
	}

	resp := make([]messageResponse, 0, len(messages))
	for _, message := range messages {
		attachments := message.Attachments
		if attachments == nil {
			attachments = []internal.Attachment{}
		}

		toolCalls := message.ToolCalls
		if toolCalls == nil {
			toolCalls = []internal.ToolCall{}
		}

		toolResults := message.ToolResults
		if toolResults == nil {
			toolResults = []internal.ToolResult{}
		}

		resp = append(resp, messageResponse{
			ID:          message.ID,
			Role:        message.Role,
			Content:     message.Content,
			Attachments: attachments,
			ToolCalls:   toolCalls,
			ToolResults: toolResults,
			Usage:       message.Usage,
			CreatedAt:   message.CreatedAt,
		})
	}

	return resp
}

func handleGetSessionMessages(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID := internal.SessionID(r.PathValue("id"))

		session, err := deps.Sessions.Get(sessionID)
		if err != nil {
			deps.Logger.Error("failed to get session", "error", err)
			writeError(w, http.StatusInternalServerError, "failed to get session")
			return
		}
		if session == nil {
			writeError(w, http.StatusNotFound, "session not found")
			return
		}

		messages, err := deps.Messages.GetAllBySession(sessionID)
		if err != nil {
			deps.Logger.Error("failed to get session messages", "error", err)
			writeError(w, http.StatusInternalServerError, "failed to get session messages")
			return
		}

		if messages == nil {
			messages = []internal.Message{}
		}

		resp := normalizeMessagesForResponse(messages)
		if r.URL.Query().Get("include_reasoning") == "1" {
			reasoning := make(map[string]string, len(messages))
			for _, m := range messages {
				if m.ReasoningContent != "" {
					reasoning[m.ID] = m.ReasoningContent
				}
			}
			for i := range resp {
				resp[i].ReasoningContent = reasoning[resp[i].ID]
			}
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func handleSendMessage(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID := internal.SessionID(r.PathValue("id"))

		session, err := deps.Sessions.Get(sessionID)
		if err != nil {
			deps.Logger.Error("failed to get session", "error", err)
			writeError(w, http.StatusInternalServerError, "failed to get session")
			return
		}
		if session == nil {
			writeError(w, http.StatusNotFound, "session not found")
			return
		}

		var req sendMessageRequest
		if err := readJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		if req.Content == "" && len(req.Attachments) == 0 {
			writeError(w, http.StatusBadRequest, "content or attachments required")
			return
		}

		if deps.MessageQueue == nil {
			writeError(w, http.StatusServiceUnavailable, "session message queue is not available")
			return
		}
		result, err := deps.MessageQueue.SubmitUser(sessionID, req.Content, req.ClientMessageID, req.Attachments, RunOptions{
			Model:           req.Model,
			Provider:        req.Provider,
			ReasoningEffort: req.ReasoningEffort,
			InputSource:     "direct_message",
			RejectIfBusy:    req.RejectIfBusy,
			Resume:          req.Resume,
			SteerNow:        req.SteerNow,
		})
		if err != nil {
			deps.Logger.Error("failed to submit session message", "session_id", sessionID, "error", err)
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to submit message: %v", err))
			return
		}
		// Keep `id` as a compatibility alias for callers that decoded the old
		// internal.Run response, while `run_id` is the explicit new contract.
		response := map[string]any{
			"id": result.RunID, "run_id": result.RunID, "session_id": result.SessionID,
			"status": result.Status, "queue_item": result.Item,
		}
		if result.Error != "" {
			// status "paused": the message is kept but cannot be delivered.
			response["error"] = result.Error
		}
		writeJSON(w, http.StatusAccepted, response)
	}
}

// ErrSessionBusy is returned by AgentLoop.CompactSession when a run — in this
// or another runtime sharing the database — holds the session.
var ErrSessionBusy = errors.New("session is busy")

func handleCompactSession(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID := internal.SessionID(r.PathValue("id"))

		session, err := deps.Sessions.Get(sessionID)
		if err != nil {
			deps.Logger.Error("failed to get session", "error", err)
			writeError(w, http.StatusInternalServerError, "failed to get session")
			return
		}
		if session == nil {
			writeError(w, http.StatusNotFound, "session not found")
			return
		}

		runs, err := deps.Runs.GetBySession(sessionID)
		if err != nil {
			deps.Logger.Error("failed to get runs", "error", err)
			writeError(w, http.StatusInternalServerError, "failed to get runs")
			return
		}
		for i := range runs {
			run := runs[i]
			if run.Status == internal.RunRunning && deps.AgentLoop.IsRunning(string(run.ID)) {
				writeJSON(w, http.StatusConflict, map[string]string{
					"error":         "session already has an active run; finish or abort it before compacting",
					"active_run_id": string(run.ID),
				})
				return
			}
		}

		var req compactSessionRequest
		if err := readJSON(r, &req); err != nil && err != io.EOF {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}

		// The summary is an LLM call that can take minutes; a client that
		// disconnects cancels it, and the history is left as it was.
		result, err := deps.AgentLoop.CompactSession(r.Context(), string(sessionID), RunOptions{Model: req.Model, Provider: req.Provider})
		if errors.Is(err, ErrSessionBusy) {
			writeJSON(w, http.StatusConflict, map[string]string{
				"error": "session is busy (a run or another compaction holds it); try again when it is idle",
			})
			return
		}
		if err != nil {
			if r.Context().Err() != nil {
				deps.Logger.Info("manual compaction cancelled", "session_id", sessionID, "error", err)
				writeError(w, http.StatusServiceUnavailable, "compaction cancelled")
				return
			}
			deps.Logger.Error("failed to compact session", "session_id", sessionID, "error", err)
			writeError(w, http.StatusInternalServerError, "failed to compact session")
			return
		}

		writeJSON(w, http.StatusOK, result)
	}
}

func handleAbort(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID := internal.SessionID(r.PathValue("id"))
		session, err := deps.Sessions.Get(sessionID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to get session")
			return
		}
		if session == nil {
			writeError(w, http.StatusNotFound, "session not found")
			return
		}

		stop := func() error {
			runs, err := deps.Runs.GetBySession(sessionID)
			if err != nil {
				return err
			}
			for _, run := range runs {
				if run.Status != internal.RunRunning {
					continue
				}
				if deps.AgentLoop.Abort(string(run.ID)) {
					continue
				}
				run.Status = internal.RunAborted
				now := time.Now()
				run.CompletedAt = &now
				if err := deps.Runs.Update(run); err != nil {
					return err
				}
				if deps.Queue != nil {
					if _, err := deps.Queue.ReleaseClaim(sessionID, run.ID); err != nil {
						return err
					}
				}
			}
			return nil
		}
		if deps.MessageQueue == nil {
			writeError(w, http.StatusServiceUnavailable, "session message queue is not available")
			return
		}
		var stopErr error
		if coordinator, ok := deps.MessageQueue.(interface {
			StopSession(internal.SessionID, func() error) error
		}); ok {
			stopErr = coordinator.StopSession(sessionID, stop)
		} else if stopErr = deps.MessageQueue.Pause(sessionID); stopErr == nil {
			stopErr = stop()
		}
		if stopErr != nil {
			deps.Logger.Error("failed to stop session", "error", stopErr)
			writeError(w, http.StatusInternalServerError, "failed to stop session")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "stopping", "session_id": string(sessionID)})
	}
}

type sessionStateResponse struct {
	Session   *internal.Session `json:"session"`
	LatestRun *internal.Run     `json:"latest_run,omitempty"`
}

func handleGetSessionState(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID := internal.SessionID(r.PathValue("id"))

		session, err := deps.Sessions.Get(sessionID)
		if err != nil {
			deps.Logger.Error("failed to get session", "error", err)
			writeError(w, http.StatusInternalServerError, "failed to get session")
			return
		}
		if session == nil {
			writeError(w, http.StatusNotFound, "session not found")
			return
		}

		runs, err := deps.Runs.GetBySession(sessionID)
		if err != nil {
			deps.Logger.Error("failed to get runs", "error", err)
			writeError(w, http.StatusInternalServerError, "failed to get runs")
			return
		}

		resp := sessionStateResponse{Session: session}

		if len(runs) > 0 {
			resp.LatestRun = runs[0]
		}

		writeJSON(w, http.StatusOK, resp)
	}
}
