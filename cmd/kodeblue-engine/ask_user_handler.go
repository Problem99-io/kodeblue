package main

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	internal "github.com/Problem99-io/kodeblue/internal"
	"github.com/Problem99-io/kodeblue/internal/agent"
	"github.com/Problem99-io/kodeblue/internal/api"
	"github.com/Problem99-io/kodeblue/internal/state"
	"github.com/Problem99-io/kodeblue/internal/tools"
)

type answerResult struct {
	index  int
	answer internal.QuestionAnswer
}

func newAskUserHandler(eventHub *api.EventHub, questionRepo *state.PendingQuestionRepo, eventSink agent.EventSink) tools.AskUserHandler {
	return func(ctx context.Context, prompts []tools.AskUserPrompt) ([]internal.QuestionAnswer, error) {
		if len(prompts) == 0 {
			return nil, nil
		}

		pending := buildPendingQuestions(prompts)
		if questionRepo != nil {
			for i := range pending {
				if err := questionRepo.Create(pending[i]); err != nil {
					return nil, err
				}
			}
		}
		emitQuestionEvents(pending, eventSink)

		answerChans := make([]chan internal.QuestionAnswer, len(pending))
		for i := range pending {
			answerChans[i] = eventHub.RegisterQuestionWait(pending[i])
		}

		answers, err := collectQuestionAnswers(ctx, pending, answerChans, eventHub, eventSink)
		if err != nil {
			return nil, err
		}
		return answers, nil
	}
}

func buildPendingQuestions(prompts []tools.AskUserPrompt) []internal.PendingQuestion {
	pending := make([]internal.PendingQuestion, 0, len(prompts))
	for i := range prompts {
		prompt := prompts[i]
		kind := prompt.Kind
		if kind == "" {
			kind = internal.QuestionKindAskUser
		}
		pending = append(pending, internal.PendingQuestion{
			QuestionID:         internal.NewID("qst"),
			SessionID:          prompt.SessionID,
			RunID:              prompt.RunID,
			Kind:               kind,
			Title:              prompt.Title,
			Question:           prompt.Question,
			Mode:               prompt.Mode,
			Options:            prompt.Options,
			Custom:             prompt.Custom,
			Recommended:        prompt.Recommended,
			RecommendedChoices: prompt.RecommendedChoices,
			CreatedAt:          time.Now(),
		})
	}
	return pending
}

func emitQuestionEvents(pending []internal.PendingQuestion, eventSink agent.EventSink) {
	if len(pending) == 1 {
		payload, _ := json.Marshal(pending[0])
		eventSink(internal.Event{
			Type:      internal.EventQuestionAsked,
			Timestamp: time.Now(),
			SessionID: pending[0].SessionID,
			RunID:     pending[0].RunID,
			Payload:   payload,
		})
		return
	}

	payload, _ := json.Marshal(map[string]any{"questions": pending})
	eventSink(internal.Event{
		Type:      internal.EventQuestionBatchAsked,
		Timestamp: time.Now(),
		SessionID: pending[0].SessionID,
		RunID:     pending[0].RunID,
		Payload:   payload,
	})
}

func collectQuestionAnswers(
	ctx context.Context,
	pending []internal.PendingQuestion,
	answerChans []chan internal.QuestionAnswer,
	eventHub *api.EventHub,
	eventSink agent.EventSink,
) ([]internal.QuestionAnswer, error) {
	results := make(chan answerResult, len(pending))
	var wg sync.WaitGroup
	for i := range answerChans {
		wg.Add(1)
		go func(index int, ch chan internal.QuestionAnswer) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			case answer, ok := <-ch:
				if !ok {
					return
				}
				results <- answerResult{index: index, answer: answer}
			}
		}(i, answerChans[i])
	}

	answers := make([]internal.QuestionAnswer, len(pending))
	received := 0
	for received < len(pending) {
		select {
		case <-ctx.Done():
			for i := range pending {
				eventHub.CancelQuestion(pending[i].QuestionID)
			}
			wg.Wait()
			return nil, ctx.Err()
		case result := <-results:
			question := pending[result.index]
			answer := result.answer
			if answer.QuestionID == "" {
				answer.QuestionID = question.QuestionID
			}
			answers[result.index] = answer

			resolvedPayload, _ := json.Marshal(answer)
			eventSink(internal.Event{
				Type:      internal.EventQuestionAnswered,
				Timestamp: time.Now(),
				SessionID: question.SessionID,
				RunID:     question.RunID,
				Payload:   resolvedPayload,
			})
			received++
		}
	}

	wg.Wait()
	return answers, nil
}
