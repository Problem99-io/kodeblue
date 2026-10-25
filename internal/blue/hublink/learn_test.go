package hublink

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Problem99-io/kodeblue/internal/blue/config"
	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

type learnAgent struct {
	Agent
	got []string
}

func (a *learnAgent) Learn(_ context.Context, m hubproto.OperatorMessage) hubproto.MessageReply {
	a.got = append(a.got, m.Command)
	return hubproto.MessageReply{Status: "done", Text: "started"}
}

func TestHubLearningCommands(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Server.StateDir = dir
	st, err := store.Open(filepath.Join(dir, "kb.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	a := &learnAgent{}
	l := &Link{cfg: cfg, st: st, log: slog.New(slog.NewTextHandler(io.Discard, nil)), agent: a}
	ctx := context.Background()

	l.cfg.Hub.AcceptLearning = false
	if r := l.handle(ctx, hubproto.OperatorMessage{ID: 1, Author: "alice", Command: hubproto.CommandRelearn}); r.Status != "refused" || !strings.Contains(r.Text, "accept_learning") {
		t.Fatalf("learning off: %+v", r)
	}
	l.cfg.Hub.AcceptLearning = true
	if r := l.handle(ctx, hubproto.OperatorMessage{ID: 2, Author: "alice", Command: "wipe"}); r.Status != "refused" {
		t.Fatalf("unknown command: %+v", r)
	}
	// A command is not an operator message: accept_messages does not gate it,
	// and it never reaches the agent's chat.
	l.cfg.Hub.AcceptMessages = false
	if r := l.handle(ctx, hubproto.OperatorMessage{ID: 3, Author: "alice", Command: hubproto.CommandLearn, Body: "Run the learner"}); r.Status != "done" {
		t.Fatalf("learn: %+v", r)
	}
	if len(a.got) != 1 || a.got[0] != hubproto.CommandLearn {
		t.Fatalf("agent got %v", a.got)
	}
}
