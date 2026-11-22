package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/hublink"
	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
	"github.com/Problem99-io/kodeblue/internal/blue/mcpserver"
	"github.com/Problem99-io/kodeblue/internal/blue/respond"
)

// Where block_ip runs automatically, the blocks other servers made are
// blocked here, oldest first and with at most half the hour's actions;
// protected and private addresses never reach the helper, and none is asked
// for twice.
func TestSharedBlocksAutomatic(t *testing.T) {
	d, _, _, out := newTestDaemon(t)
	d.cfg.Hub.URL = "https://hub.example"
	d.cfg.Response.StateDir = t.TempDir()
	d.cfg.Response.Mode = "contain"
	d.cfg.Response.MaxActionsPerHour = 4
	d.cfg.Response.ProtectedIPs = []string{"203.0.113.66"}
	var asked []string
	d.ruleRun = func(_ context.Context, req respond.Request) (*respond.Record, error) {
		if req.RequestedBy != respond.FleetRequester || req.Action != "block_ip" {
			t.Fatalf("asked the helper for %+v", req)
		}
		asked = append(asked, req.Params["ip"])
		rec := respond.Record{Request: req, Status: "done", Result: "blocked", DoneAt: time.Now()}
		appendAction(t, d.cfg.Response.StateDir, rec)
		return &rec, nil
	}
	now := time.Now()
	shareBlocks(t, d, now, "203.0.113.4", "203.0.113.3", "203.0.113.66", "10.1.2.3", "203.0.113.2", "203.0.113.1")
	d.applySharedBlocks(context.Background(), now)
	if !slices.Equal(asked, []string{"203.0.113.1", "203.0.113.2"}) {
		t.Fatalf("blocked %v, want the two oldest public ones", asked)
	}
	if titles := out.titles(); len(titles) != 1 || !strings.Contains(titles[0], "Blocked 2 addresses") {
		t.Fatalf("slack: %v", titles)
	}
	asked = nil
	d.applySharedBlocks(context.Background(), now)
	if len(asked) != 0 {
		t.Fatalf("blocked %v past half the hour's actions", asked)
	}
	d.cfg.Response.MaxActionsPerHour = 20
	d.applySharedBlocks(context.Background(), now)
	d.applySharedBlocks(context.Background(), now)
	if !slices.Equal(asked, []string{"203.0.113.3", "203.0.113.4"}) {
		t.Fatalf("then blocked %v", asked)
	}
	// Turned off on the hub: nothing runs.
	asked = nil
	d.cfg.ActionRules = map[string]string{"block_ip": hubproto.ActionOff}
	shareBlocks(t, d, now, "203.0.113.9")
	d.applySharedBlocks(context.Background(), now)
	if len(asked) != 0 {
		t.Fatalf("blocked %v with block_ip off", asked)
	}
	d.cfg.ActionRules = nil
	d.applySharedBlocks(context.Background(), now)
	if !slices.Equal(asked, []string{"203.0.113.9"}) {
		t.Fatalf("after block_ip was turned on again: %v", asked)
	}
}

// Where block_ip needs approval, a shared block is a request an operator
// approves; it is withdrawn once the fleet no longer shares it.
func TestSharedBlocksAwaitApproval(t *testing.T) {
	d, st, _, out := newTestDaemon(t)
	d.cfg.Hub.URL = "https://hub.example"
	d.cfg.Response.StateDir = t.TempDir()
	d.cfg.Response.Mode = "recommend"
	d.ruleRun = func(_ context.Context, req respond.Request) (*respond.Record, error) {
		t.Fatalf("the helper ran %+v without an approval", req)
		return nil, nil
	}
	now := time.Now()
	ids := shareBlocks(t, d, now, "198.51.100.5", "198.51.100.6")
	d.applySharedBlocks(context.Background(), now)
	d.applySharedBlocks(context.Background(), now)
	reqs := mcpserver.LoadRequests(d.cfg)
	if len(reqs) != 2 || reqs[0].ID != ids[1] || reqs[0].RequestedBy != respond.FleetRequester || !strings.Contains(reqs[0].Justification, `"web-1"`) {
		t.Fatalf("pending: %+v", reqs)
	}
	if titles := out.titles(); len(titles) != 1 || !strings.Contains(titles[0], "2 addresses other servers of the fleet blocked await approval") {
		t.Fatalf("slack: %v", titles)
	}
	shareBlocks(t, d, now)
	d.applySharedBlocks(context.Background(), now)
	if reqs := mcpserver.LoadRequests(d.cfg); len(reqs) != 0 {
		t.Fatalf("still pending after the fleet stopped sharing: %+v", reqs)
	}
	withdrawn := 0
	for _, j := range st.JournalSince(now.Add(-time.Minute), 100) {
		if j.Action == "respond.withdrawn" {
			withdrawn++
		}
	}
	if withdrawn != 2 {
		t.Fatalf("withdrawals journaled: %d", withdrawn)
	}
}

// shareBlocks saves a list from the hub (newest first) with fresh ids.
func shareBlocks(t *testing.T, d *Daemon, at time.Time, ips ...string) []string {
	t.Helper()
	sb := hubproto.SharedBlocks{Version: fmt.Sprint(at.UnixNano(), ips)}
	var ids []string
	for _, ip := range ips {
		id := "sb_" + strings.NewReplacer(".", "", ":", "").Replace(ip) + fmt.Sprint(len(ips))
		ids = append(ids, id)
		sb.Blocks = append(sb.Blocks, hubproto.SharedBlock{ID: id, IP: ip, Server: "web-1", Why: "SSH brute force: 400 failed logins in 5 minutes", At: at})
	}
	b, _ := json.Marshal(sb)
	if err := d.st.Set(hublink.SharedBlocksKey, string(b)); err != nil {
		t.Fatal(err)
	}
	return ids
}

// appendAction writes a record to the helper's action journal, as the
// helper would.
func appendAction(t *testing.T, dir string, rec respond.Record) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(dir, "actions.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b, _ := json.Marshal(rec)
	if _, err := f.Write(append(b, '\n')); err != nil {
		t.Fatal(err)
	}
}
