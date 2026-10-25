package api

import (
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	internal "github.com/Problem99-io/kodeblue/internal"
)

// EventHub lets a run wait for an answer to a pending question, and lets the
// HTTP handlers deliver it.
type EventHub struct {
	mu         sync.RWMutex
	questionCh map[string]questionWait
	logger     *slog.Logger
}

type questionWait struct {
	pending internal.PendingQuestion
	ch      chan internal.QuestionAnswer
}

func NewEventHub(logger *slog.Logger) *EventHub {
	return &EventHub{
		questionCh: make(map[string]questionWait),
		logger:     logger,
	}
}

func (h *EventHub) RegisterQuestionWait(pending internal.PendingQuestion) chan internal.QuestionAnswer {
	h.mu.Lock()
	defer h.mu.Unlock()
	ch := make(chan internal.QuestionAnswer, 1)
	h.questionCh[pending.QuestionID] = questionWait{pending: pending, ch: ch}
	return ch
}

func (h *EventHub) ResolveQuestion(id string, answer internal.QuestionAnswer) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if q, ok := h.questionCh[id]; ok {
		answer.Mode = normalizeAnswerMode(answer.Mode, q.pending.Mode)
		answer.Choices = normalizeChoices(answer.Choices, q.pending.Options)
		q.ch <- answer
		close(q.ch)
		delete(h.questionCh, id)
		return true
	}
	return false
}

func (h *EventHub) CancelQuestion(id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if q, ok := h.questionCh[id]; ok {
		close(q.ch)
		delete(h.questionCh, id)
	}
}

func (h *EventHub) GetPendingQuestion(id string) (internal.PendingQuestion, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	q, ok := h.questionCh[id]
	if !ok {
		return internal.PendingQuestion{}, false
	}
	pq := q.pending
	if len(pq.Options) > 0 {
		pq.Options = append([]string(nil), pq.Options...)
	}
	if len(pq.RecommendedChoices) > 0 {
		pq.RecommendedChoices = append([]string(nil), pq.RecommendedChoices...)
	}
	return pq, true
}

func (h *EventHub) IgnoreQuestion(id string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	q, ok := h.questionCh[id]
	if !ok {
		return false
	}
	answer := internal.QuestionAnswer{
		QuestionID: id,
		Mode:       q.pending.Mode,
		Text:       "ignored by user",
		AnsweredAt: time.Now(),
	}
	q.ch <- answer
	close(q.ch)
	delete(h.questionCh, id)
	return true
}

func (h *EventHub) ListPendingQuestions(sessionID internal.SessionID) []internal.PendingQuestion {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]internal.PendingQuestion, 0)
	for _, q := range h.questionCh {
		if q.pending.SessionID != sessionID {
			continue
		}
		pq := q.pending
		if len(pq.Options) > 0 {
			pq.Options = append([]string(nil), pq.Options...)
		}
		if len(pq.RecommendedChoices) > 0 {
			pq.RecommendedChoices = append([]string(nil), pq.RecommendedChoices...)
		}
		out = append(out, pq)
	}
	return out
}

func normalizeAnswerMode(mode, fallback string) string {
	mode = strings.TrimSpace(mode)
	if mode != "" {
		return mode
	}
	return strings.TrimSpace(fallback)
}

func normalizeChoices(in, options []string) []string {
	if len(in) == 0 || len(options) == 0 {
		return in
	}
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if idx, err := strconv.Atoi(v); err == nil {
			if idx >= 1 && idx <= len(options) {
				out = append(out, options[idx-1])
				continue
			}
		}
		out = append(out, v)
	}
	return out
}

func handleGetSessionEventHistory(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID := internal.SessionID(strings.TrimSpace(r.PathValue("id")))
		if sessionID == "" {
			writeError(w, http.StatusBadRequest, "session_id is required")
			return
		}
		session, err := deps.Sessions.Get(sessionID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load session")
			return
		}
		if session == nil {
			writeError(w, http.StatusNotFound, "session not found")
			return
		}

		var events []*internal.Event
		if r.URL.Query().Get("include_tokens") == "true" || r.URL.Query().Get("include_tokens") == "1" {
			afterSeq, parseErr := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("after_seq")), 10, 64)
			if parseErr != nil && strings.TrimSpace(r.URL.Query().Get("after_seq")) != "" {
				writeError(w, http.StatusBadRequest, "after_seq must be an integer")
				return
			}
			limit := 100000
			if rawLimit := strings.TrimSpace(r.URL.Query().Get("limit")); rawLimit != "" {
				parsed, parseErr := strconv.Atoi(rawLimit)
				if parseErr != nil || parsed < 1 || parsed > 100000 {
					writeError(w, http.StatusBadRequest, "limit must be between 1 and 100000")
					return
				}
				limit = parsed
			}
			events, err = deps.Events.GetBySession(sessionID, afterSeq, limit)
		} else {
			events, err = deps.Events.GetBySessionSummary(sessionID)
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load events")
			return
		}
		publicStream := &publicEventStream{}
		visible := make([]*internal.Event, 0, len(events))
		for _, event := range events {
			if projected, show := publicStream.visible(*event); show {
				visible = append(visible, &projected)
			}
		}
		writeJSON(w, http.StatusOK, visible)
	}
}
