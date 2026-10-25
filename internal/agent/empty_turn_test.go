package agent

import (
	"context"
	"testing"

	"github.com/Problem99-io/kodeblue/internal/provider"
	"github.com/Problem99-io/kodeblue/internal/tools"
)

func reasoningOnlyResponse() []provider.StreamEvent {
	return []provider.StreamEvent{
		{Type: provider.EventToken, Content: "still thinking", Channel: provider.ChannelReasoning},
		{Type: provider.EventDone, Usage: &provider.Usage{InputTokens: 50, OutputTokens: 6000}},
	}
}

func TestLoopContinuesAfterReplyWithNoAnswer(t *testing.T) {
	mp := newMockProvider([][]provider.StreamEvent{
		reasoningOnlyResponse(),
		simpleTextResponse("done"),
	})
	loop := NewLoop(tools.NewRegistry(), newAllowAllToolGuard(), nil, (&eventCollector{}).sink)
	result, err := loop.Run(context.Background(), buildRunConfig(mp, nil), "learn the server", nil)
	if err != nil {
		t.Fatal(err)
	}
	if last := result.Messages[len(result.Messages)-1]; last.Content != "done" {
		t.Fatalf("run ended on %q, want the answer after the nudge", last.Content)
	}
	var nudged bool
	for _, m := range result.Messages {
		if m.Role == "user" && m.Internal && m.Content == emptyTurnNudge {
			nudged = true
		}
	}
	if !nudged {
		t.Fatal("no internal nudge in the history")
	}
}

func TestLoopStopsNudgingAfterLimit(t *testing.T) {
	var responses [][]provider.StreamEvent
	for range maxEmptyTurns + 1 {
		responses = append(responses, reasoningOnlyResponse())
	}
	mp := newMockProvider(append(responses, simpleTextResponse("never reached")))
	loop := NewLoop(tools.NewRegistry(), newAllowAllToolGuard(), nil, (&eventCollector{}).sink)
	result, err := loop.Run(context.Background(), buildRunConfig(mp, nil), "x", nil)
	if err != nil {
		t.Fatal(err)
	}
	if mp.callIndex != maxEmptyTurns+1 {
		t.Fatalf("provider called %d times, want %d", mp.callIndex, maxEmptyTurns+1)
	}
	if last := result.Messages[len(result.Messages)-1]; last.Role != "assistant" {
		t.Fatalf("last message role %q", last.Role)
	}
}
