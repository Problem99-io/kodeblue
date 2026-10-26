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

type upgradeAgent struct {
	Agent
	got []string
}

func (a *upgradeAgent) Upgrade(m hubproto.OperatorMessage) hubproto.MessageReply {
	a.got = append(a.got, m.Body)
	return hubproto.MessageReply{Status: "done", Text: "recorded"}
}

// Upgrades from the hub follow the root-owned hub.accept_upgrades.
func TestHubUpgradeCommand(t *testing.T) {
	cfg := config.Default()
	a := &upgradeAgent{}
	l := &Link{cfg: cfg, log: slog.New(slog.NewTextHandler(io.Discard, nil)), agent: a, st: openStore(t)}
	ctx := context.Background()
	l.cfg.Hub.AcceptUpgrades = false
	if r := l.handle(ctx, hubproto.OperatorMessage{ID: 1, Author: "alice", Command: hubproto.CommandUpgrade, Body: "v0.1.7"}); r.Status != "refused" || !strings.Contains(r.Text, "accept_upgrades") || !strings.Contains(r.Text, "sudo kodeblue upgrade v0.1.7") {
		t.Fatalf("upgrades off: %+v", r)
	}
	l.cfg.Hub.AcceptUpgrades = true
	if r := l.handle(ctx, hubproto.OperatorMessage{ID: 2, Author: "alice", Command: hubproto.CommandUpgrade, Body: "v0.1.7"}); r.Status != "done" || len(a.got) != 1 || a.got[0] != "v0.1.7" {
		t.Fatalf("upgrade: %+v %v", r, a.got)
	}
}

func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "kb.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}
