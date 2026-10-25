package runtime

import (
	"context"
	"net/http"
	"strings"
)

// The engine is built for a human in the loop: at an agent's turn budget it
// pauses the run with a "Keep going?" question, and a model may ask the user
// something. kodeblue runs unattended, so it answers for the missing human:
// the first checkpoint lets the agent wrap up (and stop repeating itself),
// the second ends the run; any model question is told to decide on evidence.
// Without this a run would sit paused until kodeblue's timeout.
const (
	wrapUpText   = "kodeblue (unattended): you have used your turn budget. Do not repeat any call that already failed. Make at most 3 more tool calls, only what is needed to finish your required closing step (incident_resolve, self_evaluation_write, or your final answer), then stop."
	noHumanText  = "kodeblue (unattended): no human is available in this session. Decide yourself from the evidence you have, say what you could not verify, and continue."
	stopChoice   = "No, stop here"
	keepChoice   = "Yes, keep going"
	maxWrapUps   = 1
	continuation = "continuation"
)

func (k *Engine) answerPending(ctx context.Context, sessionID string) {
	var pending struct {
		Questions []struct {
			QuestionID string   `json:"question_id"`
			Mode       string   `json:"mode"`
			Options    []string `json:"options"`
			Kind       string   `json:"kind"`
		} `json:"pending_questions"`
	}
	if err := k.do(ctx, http.MethodGet, "/v1/sessions/"+sessionID+"/pending", nil, &pending); err != nil {
		return
	}
	for _, q := range pending.Questions {
		mode := q.Mode
		if mode != "multi_select" {
			mode = "single_select"
		}
		body := map[string]any{"mode": mode}
		if q.Kind == continuation {
			k.mu.Lock()
			if k.wrapUps == nil {
				k.wrapUps = map[string]int{}
			}
			k.wrapUps[sessionID]++
			n := k.wrapUps[sessionID]
			k.mu.Unlock()
			if n <= maxWrapUps {
				body["choices"], body["text"] = []string{pick(q.Options, keepChoice)}, wrapUpText
			} else {
				body["choices"] = []string{pick(q.Options, stopChoice)}
			}
		} else {
			body["text"] = noHumanText
		}
		if err := k.do(ctx, http.MethodPost, "/v1/questions/"+q.QuestionID+"/answer", body, nil); err != nil {
			k.logger.Warn("could not answer engine question", "session", sessionID, "question", q.QuestionID, "error", err)
		} else {
			k.logger.Info("answered engine checkpoint", "session", sessionID, "kind", q.Kind, "answer", body["choices"])
		}
	}
}

// pick returns the option that starts like want (labels may vary slightly).
func pick(options []string, want string) string {
	for _, o := range options {
		if strings.EqualFold(o, want) || strings.HasPrefix(strings.ToLower(o), strings.ToLower(strings.SplitN(want, ",", 2)[0])) {
			return o
		}
	}
	return want
}
