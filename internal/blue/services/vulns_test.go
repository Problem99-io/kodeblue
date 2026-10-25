package services

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Problem99-io/kodeblue/internal/blue/sensors"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

// debugCheck fails while conf says debug=true.
func debugCheck(conf string) json.RawMessage {
	b, _ := json.Marshal(map[string]any{"kind": "command", "argv": []string{"cat", conf}, "expect_no_match": "debug=true"})
	return b
}

func vulnCtx(t *testing.T) (VulnContext, string) {
	t.Helper()
	dir := t.TempDir()
	conf := filepath.Join(dir, "app.conf")
	if err := os.WriteFile(conf, []byte("port=3000\ndebug=true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return VulnContext{Store: openStore(t), StateDir: dir, Env: &sensors.Env{Root: "/"}}, conf
}

func debugVuln(conf string) store.Vulnerability {
	return store.Vulnerability{ID: "app-debug-mode", Service: "app", Title: "App runs in debug mode", Severity: "medium", Category: "misconfiguration",
		Evidence: "cat " + conf + ": debug=true", Remediation: "Set debug=false in " + conf + " and restart the app", Check: debugCheck(conf)}
}

func TestReportNeedsAFailingCheck(t *testing.T) {
	c, conf := vulnCtx(t)
	ctx := context.Background()
	v := debugVuln(conf)

	bad := v
	bad.Check, _ = json.Marshal(map[string]any{"kind": "command", "argv": []string{"cat", conf}, "expect_match": "port=3000"})
	if _, _, err := c.Report(ctx, bad, "agent"); err == nil || !strings.Contains(err.Error(), "passes now") {
		t.Fatalf("a check that passes today proves nothing: %v", err)
	}
	bad = v
	bad.Check, _ = json.Marshal(map[string]any{"kind": "file", "paths": []string{conf}})
	if _, _, err := c.Report(ctx, bad, "agent"); err == nil {
		t.Fatal("a file monitor compares with the past; it cannot tell a fix")
	}
	bad = v
	bad.Remediation = "fix it"
	if _, _, err := c.Report(ctx, bad, "agent"); err == nil {
		t.Fatal("a vulnerability without a real remediation cannot be resolved by anyone")
	}
	bad = v
	bad.CVEs = []string{"not-a-cve"}
	if _, _, err := c.Report(ctx, bad, "agent"); err == nil {
		t.Fatal("cves must be CVE or GHSA ids")
	}

	created, note, err := c.Report(ctx, v, "agent")
	if err != nil || !created || !strings.Contains(note, "fails now") {
		t.Fatalf("report: %v %v %s", created, err, note)
	}
	got := c.Store.GetVulnerability(v.ID)
	if got == nil || got.Status != store.VulnOpen || got.CheckOK || got.CheckedAt.IsZero() || got.FoundBy != "agent" {
		t.Fatalf("stored: %+v", got)
	}
	if n := c.Store.VulnerabilityCounts()["app"]["medium"]; n != 1 {
		t.Fatalf("counts: %v", c.Store.VulnerabilityCounts())
	}
	// The same id updates it.
	v.Severity = "high"
	if created, _, err := c.Report(ctx, v, "agent"); err != nil || created {
		t.Fatalf("update: %v %v", created, err)
	}
	if l := c.Store.Vulnerabilities(""); len(l) != 1 || l[0].Severity != "high" {
		t.Fatalf("after update: %+v", l)
	}
}

func TestRecheckResolvesAndReopens(t *testing.T) {
	c, conf := vulnCtx(t)
	ctx := context.Background()
	v := debugVuln(conf)
	if _, _, err := c.Report(ctx, v, "agent"); err != nil {
		t.Fatal(err)
	}
	if res, reo := c.Recheck(ctx); len(res)+len(reo) != 0 {
		t.Fatalf("nothing changed: %v %v", res, reo)
	}
	if _, err := c.Resolve(ctx, v.ID, "agent", "I am sure it is fixed now, trust me"); err == nil {
		t.Fatal("an agent cannot resolve a vulnerability whose check still fails")
	}

	// Someone fixes it: the next recheck resolves it without a model.
	_ = os.WriteFile(conf, []byte("port=3000\ndebug=false\n"), 0o644)
	res, _ := c.Recheck(ctx)
	if len(res) != 1 {
		t.Fatalf("resolved: %v", res)
	}
	got := c.Store.GetVulnerability(v.ID)
	if got.Status != store.VulnResolved || !got.CheckOK || got.StatusBy != "kodeblue" || got.ResolvedAt.IsZero() {
		t.Fatalf("after fix: %+v", got)
	}

	// A rollback brings it back.
	_ = os.WriteFile(conf, []byte("debug=true\n"), 0o644)
	if out, err := c.RecheckOne(ctx, v.ID); err != nil || !strings.Contains(out, "vulnerable again") {
		t.Fatalf("recheck one: %v %s", err, out)
	}
	if got := c.Store.GetVulnerability(v.ID); got.Status != store.VulnOpen || !got.ResolvedAt.IsZero() {
		t.Fatalf("after rollback: %+v", got)
	}

	// An accepted risk is the team's: a passing check records it, nothing more.
	if err := c.Store.SetVulnerabilityStatus(v.ID, store.VulnAccepted, "hub:ram", "training target"); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(conf, []byte("debug=false\n"), 0o644)
	if res, reo := c.Recheck(ctx); len(res)+len(reo) != 0 {
		t.Fatalf("accepted risk changed status: %v %v", res, reo)
	}
	if got := c.Store.GetVulnerability(v.ID); got.Status != store.VulnAccepted || !got.CheckOK {
		t.Fatalf("accepted: %+v", got)
	}
	// Reported again, it stays accepted.
	if _, _, err := c.Report(ctx, debugVuln(conf), "agent"); err == nil {
		t.Fatal("the check passes now, so the report must be refused")
	}
}

func TestResolveWithoutCheck(t *testing.T) {
	c, conf := vulnCtx(t)
	ctx := context.Background()
	v := debugVuln(conf)
	v.ID, v.Check = "old-node", nil
	v.Title, v.Category, v.CVEs = "Node.js 18 is end of life", "outdated-software", []string{"cve-2024-27983"}
	_, note, err := c.Report(ctx, v, "agent")
	if err != nil || !strings.Contains(note, "no check") {
		t.Fatalf("report: %v %s", err, note)
	}
	if got := c.Store.GetVulnerability("old-node"); got.CVEs[0] != "CVE-2024-27983" || got.Check != nil {
		t.Fatalf("stored: %+v", got)
	}
	if _, err := c.Resolve(ctx, "old-node", "agent", "done"); err == nil {
		t.Fatal("resolving without a check needs a note saying how the fix was confirmed")
	}
	if _, err := c.Resolve(ctx, "old-node", "agent", "node --version now prints v22.11.0"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RecheckOne(ctx, "old-node"); err == nil {
		t.Fatal("a vulnerability without a check cannot be rechecked")
	}
	// Reported again after being resolved, it is open again.
	if _, _, err := c.Report(ctx, v, "agent"); err != nil {
		t.Fatal(err)
	}
	if got := c.Store.GetVulnerability("old-node"); got.Status != store.VulnOpen {
		t.Fatalf("reported again: %+v", got)
	}
}

func TestInventoryCountsVulnerabilities(t *testing.T) {
	st := openStore(t)
	_, _ = st.PutVulnerability(&store.Vulnerability{ID: "a", Service: "nginx", Title: "t", Severity: "high"}, "agent")
	_, _ = st.PutVulnerability(&store.Vulnerability{ID: "b", Service: "nginx", Title: "t", Severity: "high"}, "agent")
	_, _ = st.PutVulnerability(&store.Vulnerability{ID: "c", Service: "nginx", Title: "t", Severity: "low"}, "agent")
	_ = st.SetVulnerabilityStatus("c", store.VulnAccepted, "hub:ram", "kept")
	inv := Assess([]sensors.Service{nginx}, Context{Coverage: sensorsOK("process")})
	inv.Attach(st)
	if got := inv.Services[0].Vulns; got["high"] != 2 || got["low"] != 0 {
		t.Fatalf("open vulnerabilities of nginx: %v", got)
	}
}
