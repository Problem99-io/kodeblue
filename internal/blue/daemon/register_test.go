package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/cvefeed"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
	"github.com/Problem99-io/kodeblue/internal/blue/versions"
)

func TestRegisterSortsWhatTheServerKnows(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	vs := []store.Vulnerability{
		{ID: "nginx-listing", Service: "nginx", Title: "Directory listing on /files", Severity: "medium", Status: store.VulnOpen, FoundBy: "assessment", CreatedAt: now, UpdatedAt: now},
		{ID: "ssh-root", Service: "host", Title: "Root login | password", Severity: "high", Status: store.VulnOpen, CVEs: []string{"CVE-2026-1"}, Remediation: "PermitRootLogin no", FoundBy: "reviewer", CreatedAt: now, UpdatedAt: now},
		{ID: "redis-auth", Service: "redis", Title: "No password", Severity: "critical", Status: store.VulnAccepted, StatusBy: "hub:alice", StatusNote: "only on localhost", UpdatedAt: now},
		{ID: "old-fix", Service: "nginx", Title: "Old", Severity: "low", Status: store.VulnResolved, ResolvedAt: now.Add(-2 * 24 * time.Hour), UpdatedAt: now},
		{ID: "ancient", Service: "nginx", Title: "Ancient", Severity: "low", Status: store.VulnResolved, ResolvedAt: now.Add(-60 * 24 * time.Hour), UpdatedAt: now},
	}
	rep := &versions.Report{OS: "Ubuntu 24.04.4 LTS", RebootRequired: true, Updates: []versions.Update{
		{Package: "openssh-server", From: "1:9.6p1-3ubuntu13.14", To: "1:9.6p1-3ubuntu13.15", Security: true},
		{Package: "motd-news-config", To: "x"},
	}}
	cands := []cvefeed.Candidate{{CVE: cvefeed.CVE{ID: "CVE-2026-9", Score: 9.8, Severity: "critical", Description: "bad"}, KEV: true, From: "image traefik:v3"}}
	reg := buildRegister("web-1", vs, rep, cands, now)
	if len(reg.Open) != 2 || reg.Open[0].ID != "ssh-root" || len(reg.Accepted) != 1 || len(reg.Resolved) != 1 || len(reg.SecurityUpdates) != 1 {
		t.Fatalf("register: open %d accepted %d resolved %d updates %d", len(reg.Open), len(reg.Accepted), len(reg.Resolved), len(reg.SecurityUpdates))
	}
	md := reg.markdown()
	for _, want := range []string{
		"# Vulnerabilities on web-1",
		"**2 open** (1 high, 1 medium) · 1 accepted risks · 1 resolved in the last 30 days · 1 security updates waiting · 1 CVEs to check",
		"| host | 1 | high | 0 |",
		"#### Root login \\| password", "[CVE-2026-1](https://nvd.nist.gov/vuln/detail/CVE-2026-1)", "- **Fix:** PermitRootLogin no",
		"A reboot is pending", "| openssh-server |", "| [CVE-2026-9]", "| yes |",
		"## Accepted risks", "only on localhost", "## Resolved in the last 30 days", "`old-fix`",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("register misses %q:\n%s", want, md)
		}
	}
	if strings.Contains(md, "ancient") || strings.Contains(md, "motd-news-config") {
		t.Errorf("old resolutions and plain updates do not belong:\n%s", md)
	}
	if strings.Index(md, "### High") > strings.Index(md, "### Medium") {
		t.Error("open vulnerabilities must come most severe first")
	}
}

func TestRegisterIsWrittenAndKeptCurrent(t *testing.T) {
	d, st, _, _ := newTestDaemon(t)
	d.writeVulnRegister()
	p := filepath.Join(d.cfg.WorkspaceDir(), registerMD)
	b, err := os.ReadFile(p)
	if err != nil || !strings.Contains(string(b), "**0 open**") {
		t.Fatalf("empty register: %v %s", err, b)
	}
	if _, err := st.PutVulnerability(&store.Vulnerability{ID: "x-1", Service: "host", Title: "Weak", Severity: "high"}, "agent"); err != nil {
		t.Fatal(err)
	}
	d.writeVulnRegister()
	b, _ = os.ReadFile(p)
	if !strings.Contains(string(b), "**1 open** (1 high)") {
		t.Fatalf("not refreshed:\n%s", b)
	}
	js, _ := os.ReadFile(filepath.Join(d.cfg.WorkspaceDir(), registerJSON))
	var reg registerData
	if json.Unmarshal(js, &reg) != nil || len(reg.Open) != 1 || reg.Open[0].ID != "x-1" {
		t.Fatalf("json: %s", js)
	}
}
