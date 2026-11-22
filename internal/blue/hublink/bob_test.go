package hublink

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/Problem99-io/kodeblue/internal/blue/config"
	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

type bobAgent struct {
	Agent
	calls int
	last  hubproto.OperatorMessage
}

func (a *bobAgent) HandleOperatorMessage(_ context.Context, m hubproto.OperatorMessage) hubproto.MessageReply {
	a.calls++
	a.last = m
	return hubproto.MessageReply{Status: "done"}
}

func TestBobSharesMessagePermissionsAndRateLimit(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	cfg := config.Default()
	cfg.Hub.MessagesPerHour = 1
	agent := &bobAgent{}
	link := &Link{cfg: cfg, st: st, agent: agent}
	m := hubproto.OperatorMessage{Command: hubproto.CommandBob, Body: "explain", IncidentID: 7, ConversationID: "c_bob"}
	link.cfg.Hub.AcceptMessages = false
	if r := link.handle(context.Background(), m); r.Status != "refused" || agent.calls != 0 {
		t.Fatal("Bob bypassed message permissions")
	}
	link.cfg.Hub.AcceptMessages = true
	if r := link.handle(context.Background(), m); r.Status != "done" || agent.calls != 1 || agent.last.Command != hubproto.CommandBob {
		t.Fatal("Bob was not routed as a separate mode")
	}
	if r := link.handle(context.Background(), hubproto.OperatorMessage{Body: "ordinary message"}); r.Status != "refused" || agent.calls != 1 {
		t.Fatal("Bob bypassed shared message rate limit")
	}
}
