package daemon

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/respond"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

// An approved rule answers its findings before triage: a finding fully
// contained is closed, one the helper refused goes on, and criticals always
// go on.
func TestApplyRulesContainsAndRoutes(t *testing.T) {
	d, st, _, out := newTestDaemon(t)
	d.cfg.Response.StateDir = t.TempDir()
	d.cfg.Response.Mode = "recommend"
	r := respond.Rule{ID: "cr-ssh", Title: "Block SSH brute force",
		Why:  "Incidents #4 and #9: the same password spraying from new addresses each day.",
		When: respond.Trigger{Rule: "auth.bruteforce", Field: "ip"}, Action: "block_ip", MaxPerHour: 10, Days: 30}
	if _, err := respond.ApproveRule(d.cfg.Response, r, r.Hash(), "root", time.Now()); err != nil {
		t.Fatal(err)
	}
	var asked []respond.Request
	d.ruleRun = func(_ context.Context, req respond.Request) (*respond.Record, error) {
		asked = append(asked, req)
		if req.Params["ip"] == "192.0.2.66" {
			return &respond.Record{Request: req, Status: "refused", Result: "192.0.2.66 is protected"}, nil
		}
		return &respond.Record{Request: req, Status: "done", Result: "blocked"}, nil
	}
	add := func(rule, sev, ip string) *store.Finding {
		f := &store.Finding{Fingerprint: rule + ip, Collector: "auth", Rule: rule, Severity: sev, Title: "brute force from " + ip, Evidence: map[string]string{"ip": ip}}
		if err := st.AddFinding(f); err != nil {
			t.Fatal(err)
		}
		return f
	}
	blocked := add("auth.bruteforce", "high", "203.0.113.7")
	protected := add("auth.bruteforce", "high", "192.0.2.66")
	critical := add("auth.bruteforce", "critical", "203.0.113.8")
	other := add("auth.new_key", "high", "203.0.113.9")
	left := d.applyRules(context.Background(), []*store.Finding{blocked, protected, critical, other})
	var ids []int64
	for _, f := range left {
		ids = append(ids, f.ID)
	}
	if len(left) != 3 || left[0] != protected || left[1] != critical || left[2] != other {
		t.Fatalf("routed on: %v", ids)
	}
	if len(asked) != 3 || asked[0].RequestedBy != "rule:cr-ssh" || asked[0].Params["ip"] != "203.0.113.7" {
		t.Fatalf("asked the helper: %+v", asked)
	}
	if f := st.GetFinding(blocked.ID); f.Status != "closed" {
		t.Fatalf("contained finding is %s", f.Status)
	}
	if f := st.GetFinding(critical.ID); f.Status == "closed" {
		t.Fatal("a critical finding was closed by a rule")
	}
	if len(out.titles()) != 3 {
		t.Fatalf("slack: %v", out.titles())
	}
	d.cfg.Response.Mode = "off"
	asked = nil
	if left := d.applyRules(context.Background(), []*store.Finding{add("auth.bruteforce", "high", "203.0.113.10")}); len(left) != 1 || len(asked) != 0 {
		t.Fatal("a rule acted with response off")
	}
	if dg := d.recurringDigest(time.Now()); !strings.Contains(dg, "auth.bruteforce: 4 findings") || !strings.Contains(dg, "cr-ssh [active]") {
		t.Fatalf("digest:\n%s", dg)
	}
}
