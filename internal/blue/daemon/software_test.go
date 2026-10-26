package daemon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/cvefeed"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

// The daily software check records the server's versions and the day's
// CVEs that name its software, tells Slack about an exploited one at once,
// and hands both to the next review; a failed pull is retried within the
// hour, not tomorrow.
func TestSoftwareCheckFeedsReview(t *testing.T) {
	d, st, _, out := newTestDaemon(t)
	d.cfg.Notify.MinSeverity = "high"
	root := d.cfg.Server.Root
	_ = os.WriteFile(filepath.Join(root, "etc", "os-release"), []byte("PRETTY_NAME=\"Ubuntu 24.04.3 LTS\"\nID=ubuntu\nVERSION_ID=\"24.04\"\n"), 0o644)
	if err := st.UpsertBaseline([]store.BaselineItem{{Collector: "container", Key: "traefik:v3.7.15#coolify-proxy"}}, "learned"); err != nil {
		t.Fatal(err)
	}

	var fail atomic.Bool
	var nvdHits atomic.Int32
	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			http.Error(w, "nope", http.StatusNotFound)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/kev") {
			_, _ = w.Write([]byte(`{"vulnerabilities":[{"cveID":"CVE-2026-1111","vendorProject":"Traefik Labs","product":"Traefik","vulnerabilityName":"Traefik auth bypass","dateAdded":"` +
				time.Now().UTC().Format("2006-01-02") + `","shortDescription":"bypass","requiredAction":"Apply updates per vendor instructions."}]}`))
			return
		}
		nvdHits.Add(1)
		_, _ = w.Write([]byte(`{"totalResults":2,"vulnerabilities":[
{"cve":{"id":"CVE-2026-1111","published":"2026-10-26T01:00:00.000","descriptions":[{"lang":"en","value":"Traefik before 3.7.16 allows an authentication bypass."}],"metrics":{"cvssMetricV31":[{"type":"Primary","cvssData":{"baseScore":8.1,"baseSeverity":"HIGH"}}]}}},
{"cve":{"id":"CVE-2026-2222","published":"2026-10-26T02:00:00.000","descriptions":[{"lang":"en","value":"A bug in some PHP shop."}]}}]}`))
	}))
	defer feed.Close()
	d.cveClient = cvefeed.Client{NVD: feed.URL + "/nvd", KEV: feed.URL + "/kev"}

	since := time.Now().Add(-time.Hour)
	fail.Store(true)
	d.maybeSoftwareCheck(context.Background())
	d.wg.Wait()
	if st.Get(cveCheckedKey) != "" || st.Get(versionsKey) == "" {
		t.Fatal("a failed pull must not count as checked, but the versions are recorded")
	}
	fail.Store(false)
	d.maybeSoftwareCheck(context.Background())
	d.wg.Wait()
	if nvdHits.Load() != 0 {
		t.Fatal("retried before the hour was up")
	}
	_ = st.Set(cveTriedKey, time.Now().Add(-2*time.Hour).UTC().Format(time.RFC3339))
	d.maybeSoftwareCheck(context.Background())
	d.wg.Wait()
	if st.Get(cveCheckedKey) == "" || nvdHits.Load() != 1 {
		t.Fatalf("not pulled: checked=%q hits=%d", st.Get(cveCheckedKey), nvdHits.Load())
	}
	c := d.cveCandidates()
	if len(c) != 1 || c[0].ID != "CVE-2026-1111" || !c[0].KEV || c[0].From != "image traefik:v3.7.15" {
		t.Fatalf("candidates: %+v", c)
	}
	if ts := out.titles(); len(ts) != 1 || !strings.Contains(ts[0], "CVE-2026-1111 may affect this server") {
		t.Errorf("slack: %v", ts)
	}

	dg := d.reviewDigest(since)
	for _, want := range []string{"Ubuntu 24.04.3 LTS", "traefik:v3.7.15", "New CVEs naming software on this server since the last review", "CVE-2026-1111 high 8.1 EXPLOITED", "matched \"traefik\""} {
		if !strings.Contains(dg, want) {
			t.Errorf("digest misses %q:\n%s", want, dg)
		}
	}
	if strings.Contains(dg, "CVE-2026-2222") {
		t.Error("a CVE naming nothing here reached the digest")
	}

	// The same CVE seen again tomorrow is not new, and Slack hears once.
	if fresh := d.keepCandidates(c, time.Now()); len(fresh) != 0 {
		t.Errorf("repeat counted as new: %+v", fresh)
	}
	// A product match that CISA lists as exploited later is raised again.
	plain := cvefeed.Candidate{CVE: cvefeed.CVE{ID: "CVE-2026-3333", Score: 7}, Term: "sudo", How: "product"}
	d.keepCandidates([]cvefeed.Candidate{plain}, time.Now())
	exploited := plain
	exploited.KEV, exploited.How = true, "kev"
	if fresh := d.keepCandidates([]cvefeed.Candidate{exploited}, time.Now()); len(fresh) != 1 || !fresh[0].KEV {
		t.Errorf("newly exploited not raised: %+v", fresh)
	}
	n := 0
	for _, x := range d.cveCandidates() {
		if x.ID == "CVE-2026-3333" {
			n++
			if !x.KEV {
				t.Error("stored entry not updated to exploited")
			}
		}
	}
	if n != 1 {
		t.Errorf("CVE-2026-3333 stored %d times", n)
	}
	// A review due while the check runs waits for it.
	d.software.Store(true)
	_ = st.Set("last_review_at", "")
	d.maybeReview(context.Background())
	if st.Get("last_review_at") != "" {
		t.Error("review started while the software check ran")
	}
	d.software.Store(false)
}

func TestImageNameAndTerms(t *testing.T) {
	for in, want := range map[string]string{
		"traefik:v3.7.15": "traefik", "ghcr.io/coollabsio/sentinel:1.1.2": "sentinel", "localhost:5000/app": "app",
		"postgres@sha256:abc": "postgres", "library/redis": "redis",
	} {
		if got := imageName(in); got != want {
			t.Errorf("imageName(%q) = %q, want %q", in, got, want)
		}
	}
	d, st, _, _ := newTestDaemon(t)
	_ = st.UpsertBaseline([]store.BaselineItem{{Collector: "container", Key: "postgres:16#db"}}, "learned")
	names := map[string]bool{}
	for _, t := range d.softwareTerms() {
		names[t.Name] = true
	}
	if !names["postgres"] || !names["postgresql"] {
		t.Errorf("image and its product name: %v", names)
	}
}

// Debian names libraries by soname and version; CVEs name the project.
func TestProductNames(t *testing.T) {
	for _, c := range []struct{ pkg, src, want string }{
		{"libc6", "glibc", "glibc"}, {"zlib1g", "zlib", "zlib"}, {"libexpat1", "expat", "libexpat"}, {"libexpat1", "expat", "expat"},
		{"postgresql-16", "postgresql-16", "postgresql"}, {"php8.3-fpm", "php8.3", "php"}, {"nodejs", "nodejs", "node.js"},
		{"sqlite3", "sqlite3", "sqlite"}, {"libgnutls30t64", "gnutls28", "gnutls"}, {"python3-urllib3", "python-urllib3", "urllib3"},
		{"openjdk-17-jre-headless", "openjdk-17", "openjdk"}, {"bind9", "bind9", "bind"}, {"libssh-4", "libssh", "libssh"},
		{"openssh-server", "openssh", "openssh"},
	} {
		got := productNames(c.pkg, c.src)
		found := false
		for _, n := range got {
			found = found || n == c.want
		}
		if !found {
			t.Errorf("productNames(%s, %s) = %v, want %s among them", c.pkg, c.src, got, c.want)
		}
	}
}

// A pull whose exploited list failed keeps its NVD matches but not the
// window, so the next pull asks for the same days; failures back off.
func TestCVEFeedKEVFailureAndBackoff(t *testing.T) {
	d, st, _, _ := newTestDaemon(t)
	_ = st.UpsertBaseline([]store.BaselineItem{{Collector: "container", Key: "traefik:v3.7.15#proxy"}}, "learned")
	var nvd atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/kev") {
			http.Error(w, "gone", http.StatusNotFound)
			return
		}
		nvd.Add(1)
		_, _ = w.Write([]byte(`{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2026-4444","published":"2026-10-26T01:00:00.000","descriptions":[{"lang":"en","value":"x"}],"affected":[{"affectedData":[{"vendor":"Traefik Labs","product":"Traefik"}]}]}}]}`))
	}))
	defer srv.Close()
	d.cveClient = cvefeed.Client{NVD: srv.URL + "/nvd", KEV: srv.URL + "/kev"}
	start := time.Now().UTC()
	if d.cveFeed(context.Background(), start) {
		t.Fatal("a failed KEV pull reported success")
	}
	if st.Get(cveUntilKey) != "" {
		t.Error("window advanced past a failed KEV pull")
	}
	if c := d.cveCandidates(); len(c) != 1 || c[0].ID != "CVE-2026-4444" {
		t.Errorf("NVD matches lost: %+v", c)
	}
	// Two failures in a row: the next try waits two hours, not one.
	_ = st.Set(cveFailuresKey, "2")
	_ = st.Set(versionsAtKey, start.Format(time.RFC3339))
	_ = st.Set(cveTriedKey, start.Add(-90*time.Minute).Format(time.RFC3339))
	d.maybeSoftwareCheck(context.Background())
	d.wg.Wait()
	if nvd.Load() != 1 {
		t.Errorf("retried after 90 minutes despite two failures (hits %d)", nvd.Load())
	}
	_ = st.Set(cveTriedKey, start.Add(-150*time.Minute).Format(time.RFC3339))
	d.maybeSoftwareCheck(context.Background())
	d.wg.Wait()
	if nvd.Load() != 2 || st.Get(cveFailuresKey) != "3" {
		t.Errorf("hits %d failures %s", nvd.Load(), st.Get(cveFailuresKey))
	}
}

// With NVD turned off on the hub only CISA's list is pulled, and the hub's
// status carries the sources, the versions and the matches.
func TestCVEFeedSourcesAndStatus(t *testing.T) {
	d, st, _, _ := newTestDaemon(t)
	_ = st.UpsertBaseline([]store.BaselineItem{{Collector: "container", Key: "traefik:v3.7.15#proxy"}}, "learned")
	var nvd atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/kev") {
			_, _ = w.Write([]byte(`{"vulnerabilities":[{"cveID":"CVE-2026-5555","vendorProject":"Traefik Labs","product":"Traefik","vulnerabilityName":"x","dateAdded":"` +
				time.Now().UTC().Format("2006-01-02") + `","shortDescription":"y","requiredAction":"Patch."}]}`))
			return
		}
		nvd.Add(1)
		_, _ = w.Write([]byte(`{"totalResults":0,"vulnerabilities":[]}`))
	}))
	defer srv.Close()
	d.cveClient = cvefeed.Client{NVD: srv.URL + "/nvd", KEV: srv.URL + "/kev"}
	d.cfg.RootCVEFeed = d.cfg.CVEFeed
	d.cfg.CVEFeed.NVD = false
	if !d.cveFeed(context.Background(), time.Now().UTC()) || nvd.Load() != 0 {
		t.Fatalf("NVD pulled while off (hits %d)", nvd.Load())
	}
	s := d.Software()
	if strings.Join(s.Feed.Sources, ",") != "cisa_kev" || strings.Join(s.Feed.Allowed, ",") != "nvd,cisa_kev" {
		t.Errorf("sources %v allowed %v", s.Feed.Sources, s.Feed.Allowed)
	}
	if s.Feed.Total != 1 || s.Feed.Matches[0].ID != "CVE-2026-5555" || !s.Feed.Matches[0].KEV || s.Feed.Through == "" {
		t.Errorf("feed status: %+v", s.Feed)
	}
	d.cfg.CVEFeed.Enabled = false
	_ = st.Set(versionsAtKey, time.Now().UTC().Format(time.RFC3339))
	_ = st.Set(cveCheckedKey, "")
	d.maybeSoftwareCheck(context.Background())
	d.wg.Wait()
	if nvd.Load() != 0 || st.Get(cveCheckedKey) != "" {
		t.Error("feed ran while turned off")
	}
	if !strings.Contains(d.reviewDigest(time.Now().Add(-time.Hour)), "the CVE feed is off") {
		t.Error("digest does not say the feed is off")
	}
}
