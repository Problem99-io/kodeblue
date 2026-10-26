package mcpserver

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/config"
	"github.com/Problem99-io/kodeblue/internal/blue/containment"
	"github.com/Problem99-io/kodeblue/internal/blue/respond"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

// An agent proposes a rule only for an attack it has seen before, and the
// proposal acts on nothing: only an approval on the helper does.
func TestContainmentRuleProposal(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Server.StateDir = dir
	cfg.Response.StateDir = filepath.Join(dir, "response")
	st, err := store.Open(filepath.Join(dir, "kb.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s := New(cfg, st)
	var ids []int64
	for _, ip := range []string{"203.0.113.7", "203.0.113.8"} {
		f := &store.Finding{Fingerprint: ip, Collector: "auth", Rule: "auth.bruteforce", Severity: "high", Title: "brute force from " + ip, Evidence: map[string]string{"ip": ip}}
		if err := st.AddFinding(f); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, f.ID)
	}
	other := &store.Finding{Fingerprint: "k", Collector: "auth", Rule: "auth.new_key", Severity: "high", Title: "new key"}
	if err := st.AddFinding(other); err != nil {
		t.Fatal(err)
	}
	propose := func(findings ...int64) (string, error) {
		b, _ := json.Marshal(map[string]any{"id": "cr-ssh", "title": "Block SSH brute force",
			"why": "The same password spraying from new addresses every day.", "trigger_rule": "auth.bruteforce",
			"target_field": "ip", "action": "block_ip", "findings": findings})
		return s.containmentRulePropose(context.Background(), b)
	}
	if _, err := propose(ids[0]); err == nil || !strings.Contains(err.Error(), "at least two") {
		t.Fatalf("one finding: %v", err)
	}
	if _, err := propose(ids[0], other.ID); err == nil || !strings.Contains(err.Error(), "not auth.bruteforce") {
		t.Fatalf("finding of another rule: %v", err)
	}
	if out, err := propose(ids...); err != nil || !strings.Contains(out, "does nothing until a person approves") {
		t.Fatalf("proposal: %q %v", out, err)
	}
	if got := containment.Active(cfg, time.Now()); len(got) != 0 {
		t.Fatalf("a proposal is active: %+v", got)
	}
	v := containment.Get(cfg, st, "cr-ssh")
	if v == nil || v.Status != respond.RuleProposed || v.MaxPerHour != 10 || v.Days != 30 || !strings.Contains(v.Why, "Seen in: finding #") {
		t.Fatalf("view %+v", v)
	}
	if err := containment.Reject(st, "cr-ssh", "hub:alice", "our office VPN is in that range"); err != nil {
		t.Fatal(err)
	}
	if _, err := propose(ids...); err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("the same rejected proposal again: %v", err)
	}
}
