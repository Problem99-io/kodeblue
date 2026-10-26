package cvefeed

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const nvdDay = `{"resultsPerPage":3,"startIndex":0,"totalResults":3,"vulnerabilities":[
{"cve":{"id":"CVE-2026-0001","published":"2026-10-25T08:00:00.000","descriptions":[{"lang":"en","value":"A flaw in Traefik before 3.7.16 lets a remote attacker bypass middleware."}],
 "metrics":{"cvssMetricV31":[{"type":"Secondary","cvssData":{"baseScore":7.5,"baseSeverity":"HIGH"}}]}}},
{"cve":{"id":"CVE-2026-0002","published":"2026-10-25T09:00:00.000","descriptions":[{"lang":"en","value":"Heap overflow in a library."}],
 "metrics":{"cvssMetricV40":[{"type":"Secondary","cvssData":{"baseScore":9.3,"baseSeverity":"CRITICAL"}}]},
 "affected":[{"affectedData":[{"vendor":"OpenBSD","product":"OpenSSH","versions":[{"version":"8.5","lessThan":"9.8","status":"affected"},{"version":"9.8","status":"unaffected"}]}]}]}},
{"cve":{"id":"CVE-2026-0003","published":"2026-10-25T10:00:00.000","descriptions":[{"lang":"en","value":"SQL injection in the server admin page of some app."}],
 "configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:pig-mesh:pig:*:*:*:*:*:*:*:*","versionEndExcluding":"4.1.1"}]}]}]}}
]}`

const kevCatalog = `{"vulnerabilities":[
{"cveID":"CVE-2020-1111","vendorProject":"Zyxel","product":"Multiple Products","vulnerabilityName":"old","dateAdded":"2021-11-03","shortDescription":"x","requiredAction":"Apply updates"},
{"cveID":"CVE-2026-0002","vendorProject":"OpenBSD","product":"OpenSSH","vulnerabilityName":"OpenSSH heap overflow","dateAdded":"2026-10-25","shortDescription":"exploited","requiredAction":"Apply updates per vendor instructions."},
{"cveID":"CVE-2026-0009","vendorProject":"Sudo project","product":"sudo","vulnerabilityName":"sudo bug","dateAdded":"2026-10-26","shortDescription":"root","requiredAction":"Patch."}
]}`

func feeds(t *testing.T) (*httptest.Server, *[]string) {
	var hits []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.URL.Path+"?"+r.URL.RawQuery+" key="+r.Header.Get("apiKey"))
		if strings.HasSuffix(r.URL.Path, "/kev") {
			_, _ = w.Write([]byte(kevCatalog))
			return
		}
		_, _ = w.Write([]byte(nvdDay))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func TestPublishedAndExploited(t *testing.T) {
	srv, hits := feeds(t)
	c := Client{NVD: srv.URL + "/nvd", KEV: srv.URL + "/kev", APIKey: "k1"}
	to := time.Date(2026, 10, 26, 0, 30, 0, 0, time.UTC)
	cves, err := c.Published(context.Background(), to.Add(-24*time.Hour), to)
	if err != nil || len(cves) != 3 {
		t.Fatalf("published: %v %d", err, len(cves))
	}
	if q := (*hits)[0]; !strings.Contains(q, "pubStartDate=2026-10-25T00%3A30%3A00.000Z") || !strings.Contains(q, "pubEndDate=2026-10-26T00%3A30%3A00.000Z") || !strings.HasSuffix(q, "key=k1") {
		t.Errorf("query %s", q)
	}
	if c := cves[1]; c.Score != 9.3 || c.Severity != "critical" || len(c.Products) != 1 || c.Products[0].Versions != "8.5 to <9.8" {
		t.Errorf("cve read wrong: %+v", c)
	}
	if p := cves[2].Products; len(p) != 1 || p[0].Product != "pig" || p[0].Versions != "<4.1.1" {
		t.Errorf("cpe configuration read wrong: %+v", p)
	}
	kev, err := c.ExploitedSince(context.Background(), to.Add(-24*time.Hour))
	if err != nil || len(kev) != 2 {
		t.Fatalf("kev: %v %+v", err, kev)
	}
	// Long outages are capped, not refused.
	if _, err := c.Published(context.Background(), to.Add(-60*24*time.Hour), to); err != nil {
		t.Fatal(err)
	}
	if q := (*hits)[len(*hits)-1]; !strings.Contains(q, "pubStartDate=2026-10-19") {
		t.Errorf("window not capped to %s: %s", MaxWindow, q)
	}
}

func TestMatch(t *testing.T) {
	var page nvdPage
	if err := json.Unmarshal([]byte(nvdDay), &page); err != nil {
		t.Fatal(err)
	}
	var cves []CVE
	for _, v := range page.Vulnerabilities {
		cves = append(cves, v.CVE.trim())
	}
	var cat struct{ Vulnerabilities []KEV }
	_ = json.Unmarshal([]byte(kevCatalog), &cat)
	terms := []Term{
		{Name: "traefik", From: "image traefik:v3.7.15"},
		{Name: "openssh", From: "package openssh-server", Package: true},
		{Name: "sudo", From: "package sudo", Package: true},
		{Name: "server", From: "service server"}, // generic: never matches
		{Name: "app", From: "package app", Package: true},
	}
	now := time.Now()
	got := Match(cves, cat.Vulnerabilities[1:], terms, now)
	ids := map[string]Candidate{}
	for _, c := range got {
		ids[c.ID] = c
	}
	if len(got) != 3 {
		t.Fatalf("matched %d: %+v", len(got), got)
	}
	if c := ids["CVE-2026-0002"]; !c.KEV || c.Score != 9.3 || c.Term != "openssh" || !c.Urgent() {
		t.Errorf("exploited openssh: %+v", c)
	}
	if c := ids["CVE-2026-0001"]; c.How != "description" || c.From != "image traefik:v3.7.15" || c.Urgent() {
		t.Errorf("traefik by description: %+v", c)
	}
	if c := ids["CVE-2026-0009"]; c.How != "kev" || c.Term != "sudo" {
		t.Errorf("kev-only sudo: %+v", c)
	}
	if _, ok := ids["CVE-2026-0003"]; ok {
		t.Error("an app nobody runs matched")
	}
	if got[0].ID != "CVE-2026-0002" {
		t.Errorf("exploited critical should sort first: %s", got[0].ID)
	}
	// A CVE about another product that mentions one of ours is not ours.
	other := CVE{ID: "CVE-2", Description: "Docker-Proxy before 5.2 lets attackers reach the Docker socket.", Products: []Product{{Vendor: "dqzboy", Product: "Docker-Proxy"}}}
	if m := Match([]CVE{other}, nil, []Term{{Name: "docker", From: "service docker"}}, now); len(m) != 0 {
		t.Errorf("another product's CVE matched by description: %+v", m)
	}
	if m := Match([]CVE{{ID: "CVE-3", Products: []Product{{Vendor: "Linux", Product: "Linux"}}}}, nil, []Term{{Name: "linux", Package: true}}, now); len(m) != 0 {
		t.Errorf("kernel CVE matched: %+v", m)
	}
	// A package name never matches free text.
	if m := Match([]CVE{{ID: "CVE-1", Description: "sudo make me a sandwich"}}, nil, []Term{{Name: "sudo", Package: true}}, now); len(m) != 0 {
		t.Errorf("package term matched a description: %+v", m)
	}
}
