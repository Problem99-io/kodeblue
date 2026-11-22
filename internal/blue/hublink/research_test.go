package hublink

import (
	"context"
	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
	"testing"
)

type researchAgent struct {
	Agent
	calls int
}

func (a *researchAgent) Investigate(context.Context, hubproto.OperatorMessage) hubproto.MessageReply {
	a.calls++
	return hubproto.MessageReply{Status: "done", Text: "research report"}
}

func TestInvestigatorUsesNormalMessagePermissionsAndRateLimit(t *testing.T) {
	l, _ := newSettingsLink(t)
	a := &researchAgent{}
	l.agent = a
	l.cfg.Hub.MessagesPerHour = 1
	m := hubproto.OperatorMessage{ID: 1, Command: hubproto.CommandInvestigate, Body: "Inspect"}
	l.cfg.Hub.AcceptMessages = false
	if r := l.handle(context.Background(), m); r.Status != "refused" || a.calls != 0 {
		t.Fatal("messages permission bypass")
	}
	l.cfg.Hub.AcceptMessages = true
	if r := l.handle(context.Background(), m); r.Status != "done" || a.calls != 1 {
		t.Fatalf("research was sent to another role: %+v", r)
	}
	if r := l.handle(context.Background(), m); r.Status != "refused" || a.calls != 1 {
		t.Fatal("message rate limit bypass")
	}
}
