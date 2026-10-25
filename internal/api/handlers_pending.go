package api

import (
	"net/http"
	"time"

	internal "github.com/Problem99-io/kodeblue/internal"
	"github.com/Problem99-io/kodeblue/internal/state"
)

// Pending input remains actionable until answered or its owner is terminal.
var pendingQuestionCutoff = time.Unix(0, 0)

type sessionPendingResponse struct {
	SessionID        string                     `json:"session_id"`
	PendingQuestions []internal.PendingQuestion `json:"pending_questions"`
	TotalPending     int                        `json:"total_pending"`
}

func handleGetSessionPending(deps *Dependencies) http.HandlerFunc {
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

		if _, err := reconcileSessionBlockers(deps, sessionID); err != nil {
			deps.Logger.Error("failed to reconcile session blockers", "session_id", sessionID, "error", err)
			writeError(w, http.StatusInternalServerError, "failed to reconcile session blockers")
			return
		}

		pendingQuestions := deps.EventHub.ListPendingQuestions(sessionID)
		if deps.Questions != nil {
			cutoff := pendingQuestionCutoff
			storedQuestions, err := deps.Questions.ListPendingBySession(sessionID, cutoff)
			if err != nil {
				deps.Logger.Error("failed to get pending questions", "error", err)
				writeError(w, http.StatusInternalServerError, "failed to get pending questions")
				return
			}
			seen := make(map[string]struct{}, len(pendingQuestions))
			for _, question := range pendingQuestions {
				seen[question.QuestionID] = struct{}{}
			}
			for _, question := range storedQuestions {
				if _, ok := seen[question.QuestionID]; ok {
					continue
				}
				pendingQuestions = append(pendingQuestions, question)
			}
		}
		if pendingQuestions == nil {
			pendingQuestions = []internal.PendingQuestion{}
		}

		resp := sessionPendingResponse{
			SessionID:        string(sessionID),
			PendingQuestions: pendingQuestions,
			TotalPending:     len(pendingQuestions),
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func handleIgnorePendingQuestion(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID := internal.SessionID(r.PathValue("id"))
		questionID := r.PathValue("questionId")

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

		pending, ok := deps.EventHub.GetPendingQuestion(questionID)
		if !ok && deps.Questions != nil {
			stored, status, err := deps.Questions.Get(questionID)
			if err != nil {
				deps.Logger.Error("failed to get pending question", "error", err)
				writeError(w, http.StatusInternalServerError, "failed to ignore pending question")
				return
			}
			if stored != nil && (status == state.PendingQuestionStatusPending || status == "resuming") {
				pending = *stored
				ok = true
			}
		}
		if !ok {
			writeError(w, http.StatusNotFound, "pending question not found")
			return
		}
		if pending.SessionID != sessionID {
			writeError(w, http.StatusNotFound, "pending question not found in this session")
			return
		}
		ignoredLive := deps.EventHub.IgnoreQuestion(questionID)
		if deps.Questions != nil {
			answer := internal.QuestionAnswer{
				QuestionID: questionID,
				Mode:       pending.Mode,
				Text:       "ignored by user",
				AnsweredAt: time.Now(),
			}
			if err := deps.Questions.Resolve(questionID, state.PendingQuestionStatusIgnored, answer); err != nil {
				deps.Logger.Error("failed to ignore pending question", "error", err)
				writeError(w, http.StatusInternalServerError, "failed to ignore pending question")
				return
			}
		} else if !ignoredLive {
			writeError(w, http.StatusNotFound, "pending question not found")
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{
			"status":      "ignored",
			"type":        "question",
			"session_id":  string(sessionID),
			"question_id": questionID,
		})
	}
}
