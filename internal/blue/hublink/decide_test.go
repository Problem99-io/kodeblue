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
	"github.com/Problem99-io/kodeblue/internal/blue/mcpserver"
	"github.com/Problem99-io/kodeblue/internal/blue/respond"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

func TestHubDecisions(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Server.StateDir = dir
	cfg.Response.StateDir = filepath.Join(dir, "response")
	st, err := store.Open(filepath.Join(dir, "kb.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	b, _ := json.Marshal(respond.Request{ID: "act_1", IncidentID: 7, Action: "block_ip", Params: map[string]string{"ip": "203.0.113.9"}, RequestedBy: "agent"})
	if err := os.WriteFile(filepath.Join(dir, "response-requests.jsonl"), append(b, '\n'), 0o640); err != nil {
		t.Fatal(err)
	}
	l := &Link{cfg: cfg, st: st, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ctx := context.Background()

	l.cfg.Hub.AcceptApprovals = false
	if r := l.handle(ctx, hubproto.OperatorMessage{ID: 1, Author: "alice", Decision: "deny", RequestID: "act_1"}); r.Status != "refused" || !strings.Contains(r.Text, "accept_approvals") {
		t.Fatalf("approvals off: %+v", r)
	}
	l.cfg.Hub.AcceptApprovals = true
	// A decision is not an operator message: accept_messages does not gate it.
	l.cfg.Hub.AcceptMessages = false
	if r := l.handle(ctx, hubproto.OperatorMessage{ID: 2, Author: "alice", Decision: "deny", RequestID: "act_nope"}); r.Status != "refused" {
		t.Fatalf("unknown request: %+v", r)
	}
	if r := l.handle(ctx, hubproto.OperatorMessage{ID: 3, Author: "alice", Decision: "deny", RequestID: "act_1"}); r.Status != "done" {
		t.Fatalf("deny: %+v", r)
	}
	if n := len(mcpserver.LoadRequests(l.cfg)); n != 0 {
		t.Fatalf("denied request still pending: %d", n)
	}
	if r := l.handle(ctx, hubproto.OperatorMessage{ID: 4, Author: "alice", Decision: "approve", RequestID: "act_1"}); r.Status != "refused" {
		t.Fatalf("approve after deny: %+v", r)
	}
}
