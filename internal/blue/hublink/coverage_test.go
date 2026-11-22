package hublink

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/Problem99-io/kodeblue/internal/blue/config"
	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
	"github.com/Problem99-io/kodeblue/internal/blue/services"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

func TestHubCoverageCommands(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Server.StateDir = dir
	cfg.Server.Root = t.TempDir() // an empty host: the sync finds nothing
	st, err := store.Open(filepath.Join(dir, "kb.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	l := &Link{cfg: cfg, st: st, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	cmd := func(c, svc, checks, note string) hubproto.MessageReply {
		return l.handle(context.Background(), hubproto.OperatorMessage{ID: 1, Author: "alice", Command: c, RequestID: svc, SessionID: checks, Body: note})
	}
	const why = "sshd runs in the host network namespace; no sockets monitor can be scoped to it"

	l.cfg.Hub.AcceptMessages = false
	if r := cmd(hubproto.CommandCoverageWaive, "ssh", "network", why); r.Status != "refused" {
		t.Fatalf("messages off: %+v", r)
	}
	l.cfg.Hub.AcceptMessages = true
	if r := cmd(hubproto.CommandCoverageWaive, "ssh", "network", "short"); r.Status != "refused" {
		t.Fatalf("a waiver needs a reason: %+v", r)
	}
	if r := cmd(hubproto.CommandCoverageWaive, "ssh", "network,files", why); r.Status != "done" {
		t.Fatalf("waive: %+v", r)
	}
	w := services.LoadWaivers(st)["ssh"]
	if len(w) != 2 || w["network"].By != "hub:alice" {
		t.Fatalf("waivers: %+v", w)
	}
	if r := cmd(hubproto.CommandCoverageUnwaive, "ssh", "files", ""); r.Status != "done" || len(services.LoadWaivers(st)["ssh"]) != 1 {
		t.Fatalf("unwaive one: %+v %+v", r, services.LoadWaivers(st))
	}
	if r := cmd(hubproto.CommandCoverageUnwaive, "nginx", "", ""); r.Status != "refused" {
		t.Fatalf("nothing to unwaive: %+v", r)
	}
}
