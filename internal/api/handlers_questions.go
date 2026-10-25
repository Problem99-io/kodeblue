package api

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	internal "github.com/Problem99-io/kodeblue/internal"
	"github.com/Problem99-io/kodeblue/internal/state"
)

var questionAnswerMu sync.Mutex

type questionAnswerRequest struct {
	Mode    string   `json:"mode"`
	Text    string   `json:"text"`
	Choices []string `json:"choices"`
}

func handleQuestionAnswer(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		questionAnswerMu.Lock()
		defer questionAnswerMu.Unlock()
		questionID := strings.TrimSpace(r.PathValue("questionId"))
		if questionID == "" {
			writeError(w, http.StatusBadRequest, "questionId is required")
			return
		}

		var req questionAnswerRequest
		if err := readJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}

		req.Mode = strings.TrimSpace(req.Mode)
		switch req.Mode {
		case "single_select", "multi_select":
		default:
			writeError(w, http.StatusBadRequest, "mode must be single_select or multi_select")
			return
		}
		// A free-text answer is always allowed in place of (or in addition to) the
		// provided options, so only require choices when no custom text was given.
		if (req.Mode == "single_select" || req.Mode == "multi_select") && len(req.Choices) == 0 && strings.TrimSpace(req.Text) == "" {
			writeError(w, http.StatusBadRequest, "provide at least one choice or a custom answer")
			return
		}

		answer := internal.QuestionAnswer{
			QuestionID: questionID,
			Mode:       req.Mode,
			Text:       req.Text,
			Choices:    req.Choices,
			AnsweredAt: time.Now(),
		}

		var pending *internal.PendingQuestion
		if deps.Questions != nil {
			storedPending, status, err := deps.Questions.Get(questionID)
			if err != nil {
				deps.Logger.Error("failed to get pending question", "question_id", questionID, "error", err)
				writeError(w, http.StatusInternalServerError, "failed to respond to question")
				return
			}

			if storedPending != nil {
				if _, err := reconcileSessionBlockers(deps, storedPending.SessionID); err != nil {
					writeError(w, http.StatusInternalServerError, "failed to reconcile session blockers")
					return
				}
				storedPending, status, err = deps.Questions.Get(questionID)
				if err != nil || storedPending == nil {
					writeError(w, http.StatusInternalServerError, "failed to reload request")
					return
				}
			}
			if storedPending != nil && status != state.PendingQuestionStatusPending && status != "resuming" {
				writeError(w, http.StatusConflict, "question already resolved")
				return
			}
			// A stale client can still hold a question from a deliberately stopped
			// run. Do not resurrect it as an interrupted-run continuation.
			if storedPending != nil && deps.Runs != nil && storedPending.RunID != "" {
				run, err := deps.Runs.Get(storedPending.RunID)
				if err != nil {
					writeError(w, http.StatusInternalServerError, "failed to get question run")
					return
				}
				if run != nil && run.SessionID == storedPending.SessionID && run.Status == internal.RunAborted {
					writeError(w, http.StatusConflict, "question belongs to an aborted run")
					return
				}
			}
			pending = storedPending
		}

		resolvedLive := deps.EventHub.ResolveQuestion(questionID, answer)
		if deps.Questions != nil {
			if pending == nil && !resolvedLive {
				writeError(w, http.StatusNotFound, "question not found")
				return
			}
			if pending != nil {
				resolutionStatus := state.PendingQuestionStatusAnswered
				if !resolvedLive {
					resolutionStatus = "resuming"
				}
				if err := deps.Questions.Resolve(questionID, resolutionStatus, answer); err != nil {
					deps.Logger.Error("failed to resolve pending question", "question_id", questionID, "error", err)
					writeError(w, http.StatusInternalServerError, "failed to respond to question")
					return
				}
			}
		} else if !resolvedLive {
			writeError(w, http.StatusNotFound, "question not found or already resolved")
			return
		}

		// If no live agent consumed the answer, the run that asked this question was
		// interrupted (e.g. a server restart killed the goroutine blocked in ask_user).
		// Once every question from that run has been answered, resume the run by
		// feeding the answers back as a fresh user turn.
		if !resolvedLive && pending != nil {
			if err := resumeInterruptedRun(deps, pending.RunID, pending.SessionID); err != nil {
				reopenErr := deps.Questions.ReopenAfterResumeFailure(questionID)
				deps.Logger.Error("failed to resume answered question", "question_id", questionID, "error", err, "reopen_error", reopenErr)
				writeError(w, http.StatusInternalServerError, "failed to resume run; retry answering the question")
				return
			}
		}
		if !resolvedLive && pending != nil {
			if err := deps.Questions.Resolve(questionID, state.PendingQuestionStatusAnswered, answer); err != nil {
				writeError(w, http.StatusInternalServerError, "run accepted but answer persistence failed; retry answering")
				return
			}
		}

		writeJSON(w, http.StatusOK, map[string]string{
			"question_id": questionID,
			"status":      "answered",
		})
	}
}

// resumeInterruptedRun restarts an agent run whose ask_user wait was lost (the
// goroutine died before the answer arrived, typically across a restart). It is a
// no-op when the run is still alive, when questions from the same run are still
// unanswered, or when the required dependencies are unavailable.
func resumeInterruptedRun(deps *Dependencies, runID internal.RunID, sessionID internal.SessionID) error {
	if deps.Questions == nil || deps.AgentLoop == nil || deps.Runs == nil {
		return nil
	}
	if runID == "" {
		return nil
	}
	// A live run will deliver the answer through its channel; nothing to resume.
	if deps.AgentLoop.IsRunning(string(runID)) {
		return nil
	}

	cutoff := pendingQuestionCutoff

	stillPending, err := deps.Questions.ListPendingByRun(runID, cutoff)
	if err != nil {
		deps.Logger.Error("failed to list pending questions for resume", "run_id", runID, "error", err)
		return err
	}
	if len(stillPending) > 0 {
		// Wait for the remaining questions in this batch before resuming.
		return nil
	}

	answered, err := deps.Questions.ListAnsweredByRun(runID, cutoff)
	if err != nil {
		deps.Logger.Error("failed to list answered questions for resume", "run_id", runID, "error", err)
		return err
	}
	if len(answered) == 0 {
		return nil
	}

	// A continuation checkpoint answered after its run died is still the user's
	// decision about that run: "no" means the work stops here, so there is
	// nothing to resume. "Yes" resumes, but the checkpoint itself is not a
	// question the agent asked and must not be replayed back at it as one.
	for i := range answered {
		if answered[i].Question.Kind != internal.QuestionKindContinuation {
			continue
		}
		proceed, _ := internal.InterpretContinuationAnswer(answered[i].Answer)
		if !proceed {
			deps.Logger.Info("not resuming run: user declined continuation checkpoint",
				"session_id", sessionID, "run_id", runID)
			return nil
		}
	}

	message := buildResumeMessage(answered)

	newRun := &internal.Run{
		ID:        internal.RunID("run_resume_" + string(runID)),
		SessionID: sessionID,
		Status:    internal.RunRunning,
		CreatedAt: time.Now(),
	}
	previous, err := deps.Runs.Get(newRun.ID)
	if err != nil {
		return err
	}
	if previous != nil {
		if deps.AgentLoop.IsRunning(string(previous.ID)) || previous.Status == internal.RunCompleted {
			return nil
		}
		if err := deps.Runs.Update(newRun); err != nil {
			return err
		}
	} else if err := deps.Runs.Create(newRun); err != nil {
		return err
	}

	deps.Logger.Info("resuming interrupted run after question answer",
		"session_id", sessionID, "interrupted_run_id", runID, "resume_run_id", newRun.ID, "answers", len(answered))

	questionID := ""
	for i := len(answered) - 1; i >= 0; i-- {
		if answered[i].Question.Kind != internal.QuestionKindContinuation {
			questionID = answered[i].Question.QuestionID
			break
		}
	}
	if err := deps.AgentLoop.RunAsync(string(sessionID), string(newRun.ID), message, nil, RunOptions{InputSource: "question_answer", QuestionID: questionID}); err != nil {
		deps.Logger.Error("failed to start resume run", "session_id", sessionID, "resume_run_id", newRun.ID, "error", err)
		newRun.Status = internal.RunFailed
		now := time.Now()
		newRun.CompletedAt = &now
		if updateErr := deps.Runs.Update(newRun); updateErr != nil {
			return fmt.Errorf("resume failed: %v; mark failed: %w", err, updateErr)
		}
		return err
	}
	return nil
}

// buildResumeMessage reconstructs the user's reply to one or more interrupted
// questions as a plain user turn the agent can act on.
func buildResumeMessage(answered []state.AnsweredQuestion) string {
	// Continuation checkpoints are the system's question, not the agent's, so
	// they are not quoted back. They contribute only a "carry on" instruction
	// plus whatever steering the user typed in place of a plain yes.
	var guidance []string
	questions := make([]state.AnsweredQuestion, 0, len(answered))
	for i := range answered {
		if answered[i].Question.Kind != internal.QuestionKindContinuation {
			questions = append(questions, answered[i])
			continue
		}
		if _, steer := internal.InterpretContinuationAnswer(answered[i].Answer); steer != "" {
			guidance = append(guidance, steer)
		}
	}

	if len(questions) == 0 {
		var b strings.Builder
		b.WriteString("Continue the work you were doing — you were interrupted partway through.")
		if len(guidance) > 0 {
			b.WriteString("\n\n")
			b.WriteString(strings.Join(guidance, "\n\n"))
		}
		return b.String()
	}
	answered = questions

	var b strings.Builder
	if len(answered) == 1 {
		b.WriteString("I've answered the question you asked:\n\n")
	} else {
		b.WriteString("I've answered the questions you asked:\n\n")
	}
	for i := range answered {
		q := answered[i].Question
		ans := answered[i].Answer
		if len(answered) > 1 {
			fmt.Fprintf(&b, "%d. ", i+1)
		}
		question := strings.TrimSpace(q.Question)
		if question == "" {
			question = strings.TrimSpace(q.Title)
		}
		b.WriteString(question)
		b.WriteString("\n")

		parts := make([]string, 0, len(ans.Choices)+1)
		parts = append(parts, ans.Choices...)
		if text := strings.TrimSpace(ans.Text); text != "" {
			parts = append(parts, text)
		}
		answerText := strings.Join(parts, ", ")
		if answerText == "" {
			answerText = "(no answer provided)"
		}
		fmt.Fprintf(&b, "Answer: %s\n\n", answerText)
	}
	b.WriteString("Please continue with these answers.")
	if len(guidance) > 0 {
		b.WriteString("\n\n")
		b.WriteString(strings.Join(guidance, "\n\n"))
	}
	return b.String()
}
