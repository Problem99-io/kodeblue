package main

import (
	"context"
	"fmt"

	internal "github.com/Problem99-io/kodeblue/internal"
	"github.com/Problem99-io/kodeblue/internal/agent"
	"github.com/Problem99-io/kodeblue/internal/tools"
)

// newContinuationGate builds the checkpoint the agent loop hits after
// cfg.MaxIterations tool-calling turns. It asks through the ordinary pending
// question pipeline — the same one ask_user uses — so the prompt renders,
// persists across reloads, and is answered by the existing UI with no special
// casing. The run stays parked in the gate until the answer arrives, holding
// the finished turn's tool results back from the model.
func newContinuationGate(askUser tools.AskUserHandler) agent.ContinuationGate {
	return func(ctx context.Context, req agent.ContinuationRequest) (agent.ContinuationDecision, error) {
		if askUser == nil {
			return agent.ContinuationDecision{Continue: true}, nil
		}

		answers, err := askUser(ctx, []tools.AskUserPrompt{{
			SessionID:   req.SessionID,
			RunID:       req.RunID,
			Kind:        internal.QuestionKindContinuation,
			Title:       "Keep going?",
			Question:    continuationQuestion(req),
			Mode:        tools.QuestionModeSingle,
			Options:     []string{internal.ContinueYesOption, internal.ContinueNoOption},
			Custom:      true,
			Recommended: internal.ContinueYesOption,
		}})
		if err != nil {
			return agent.ContinuationDecision{}, err
		}
		if len(answers) != 1 {
			return agent.ContinuationDecision{}, fmt.Errorf("expected 1 continuation answer, got %d", len(answers))
		}

		proceed, guidance := internal.InterpretContinuationAnswer(answers[0])
		return agent.ContinuationDecision{Continue: proceed, Guidance: guidance}, nil
	}
}

func continuationQuestion(req agent.ContinuationRequest) string {
	turns := "turns"
	if req.Iterations == 1 {
		turns = "turn"
	}
	return fmt.Sprintf(
		"This run has taken %d tool-calling %s (%d tool calls) without finishing. Keep going?\n\n"+
			"Its last tool results are being held and have not been sent to the model yet — answering yes releases them and the run picks up exactly where it stopped. "+
			"You can type instructions instead, and they reach the model along with those results.",
		req.Iterations, turns, req.ToolCalls,
	)
}
