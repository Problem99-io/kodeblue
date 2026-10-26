package hublink

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/config"
	"github.com/Problem99-io/kodeblue/internal/blue/containment"
	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
	"github.com/Problem99-io/kodeblue/internal/blue/respond"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

// A hub approval of a containment rule is refused before it reaches the
// root helper unless the server lets the hub turn on automatic actions;
// rejecting needs only messages.
func TestHubRuleCommands(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Server.StateDir = dir
	cfg.Response.StateDir = filepath.Join(dir, "respond")
	cfg.Response.Mode = "recommend"
	st, err := store.Open(filepath.Join(dir, "kb.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	r := respond.Rule{ID: "cr-ssh", Title: "Block SSH brute force", Why: "The same password spraying from new addresses every day.",
		When: respond.Trigger{Rule: "auth.bruteforce", Field: "ip"}, Action: "block_ip", MaxPerHour: 5, Days: 7}
	v, err := containment.Propose(st, r, "agent")
	if err != nil {
		t.Fatal(err)
	}
	l := &Link{cfg: cfg, st: st, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	cmd := func(c, id, note string) hubproto.MessageReply {
		return l.handle(context.Background(), hubproto.OperatorMessage{ID: 1, Author: "alice", Command: c, RequestID: id, Body: note, RuleHash: v.Hash})
	}
	l.cfg.Hub.AcceptApprovals = false
	if rep := cmd(hubproto.CommandRuleApprove, "cr-ssh", ""); rep.Status != "refused" || !strings.Contains(rep.Text, "sudo kodeblue rules approve cr-ssh") {
		t.Fatalf("approvals off: %+v", rep)
	}
	l.cfg.Hub.AcceptApprovals = true
	if rep := cmd(hubproto.CommandRuleApprove, "cr-ssh", ""); rep.Status != "refused" || !strings.Contains(rep.Text, "hub_max_mode") {
		t.Fatalf("recommend without hub_max_mode contain: %+v", rep)
	}
	if rep := cmd(hubproto.CommandRulePause, "cr-nope", "x"); rep.Status != "refused" {
		t.Fatalf("unknown rule: %+v", rep)
	}
	if rep := cmd(hubproto.CommandRuleReject, "cr-ssh", "our VPN is in that range"); rep.Status != "done" {
		t.Fatalf("reject: %+v", rep)
	}
	if got := containment.Get(cfg, st, "cr-ssh"); got == nil || got.Status != respond.RuleRejected || got.Note != "our VPN is in that range" {
		t.Fatalf("after reject: %+v", got)
	}
	if len(containment.Active(cfg, time.Now())) != 0 {
		t.Fatal("a hub command made a rule active without the helper")
	}
}
