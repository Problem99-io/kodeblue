package hublink

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Problem99-io/kodeblue/internal/blue/config"
	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

func TestHubVulnerabilityCommands(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Server.StateDir = dir
	cfg.Server.Root = "/"
	st, err := store.Open(filepath.Join(dir, "kb.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	conf := filepath.Join(dir, "app.conf")
	_ = os.WriteFile(conf, []byte("debug=true\n"), 0o644)
	check, _ := json.Marshal(map[string]any{"kind": "command", "argv": []string{"cat", conf}, "expect_no_match": "debug=true"})
	_, _ = st.PutVulnerability(&store.Vulnerability{ID: "app-debug", Service: "app", Title: "debug mode", Severity: "medium", Check: check}, "agent")
	_, _ = st.PutVulnerability(&store.Vulnerability{ID: "old-node", Service: "app", Title: "old node", Severity: "low"}, "agent")
	l := &Link{cfg: cfg, st: st, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ctx := context.Background()
	cmd := func(c, id, note string) hubproto.MessageReply {
		return l.handle(ctx, hubproto.OperatorMessage{ID: 1, Author: "alice", Command: c, RequestID: id, Body: note})
	}

	l.cfg.Hub.AcceptMessages = false
	if r := cmd(hubproto.CommandVulnAccept, "app-debug", "lab"); r.Status != "refused" {
		t.Fatalf("messages off: %+v", r)
	}
	l.cfg.Hub.AcceptMessages = true
	if r := cmd(hubproto.CommandVulnAccept, "nope", "lab"); r.Status != "refused" {
		t.Fatalf("unknown: %+v", r)
	}
	if r := cmd(hubproto.CommandVulnRecheck, "app-debug", ""); r.Status != "done" || !strings.Contains(r.Text, "still vulnerable") {
		t.Fatalf("recheck while vulnerable: %+v", r)
	}
	_ = os.WriteFile(conf, []byte("debug=false\n"), 0o644)
	if r := cmd(hubproto.CommandVulnRecheck, "app-debug", ""); r.Status != "done" || !strings.Contains(r.Text, "resolved") {
		t.Fatalf("recheck after fix: %+v", r)
	}
	if v := st.GetVulnerability("app-debug"); v.Status != store.VulnResolved {
		t.Fatalf("after recheck: %+v", v)
	}
	if r := cmd(hubproto.CommandVulnRecheck, "old-node", ""); r.Status != "refused" {
		t.Fatalf("no check to run: %+v", r)
	}
	if r := cmd(hubproto.CommandVulnAccept, "old-node", ""); r.Status != "refused" {
		t.Fatalf("accept without a reason: %+v", r)
	}
	if r := cmd(hubproto.CommandVulnAccept, "old-node", "replaced next quarter"); r.Status != "done" {
		t.Fatalf("accept: %+v", r)
	}
	if v := st.GetVulnerability("old-node"); v.Status != store.VulnAccepted || v.StatusBy != "hub:alice" || v.StatusNote != "replaced next quarter" {
		t.Fatalf("accepted: %+v", v)
	}
	if r := cmd(hubproto.CommandVulnReopen, "old-node", ""); r.Status != "done" || st.GetVulnerability("old-node").Status != store.VulnOpen {
		t.Fatalf("reopen: %+v", r)
	}
}
