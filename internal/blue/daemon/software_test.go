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
	if st.Get(softwareCheckedKey) != "" || st.Get(versionsKey) == "" {
		t.Fatal("a failed pull must not count as checked, but the versions are recorded")
	}
	fail.Store(false)
	d.maybeSoftwareCheck(context.Background())
	d.wg.Wait()
	if nvdHits.Load() != 0 {
		t.Fatal("retried before the hour was up")
	}
	_ = st.Set(softwareTriedKey, time.Now().Add(-2*time.Hour).UTC().Format(time.RFC3339))
	d.maybeSoftwareCheck(context.Background())
	d.wg.Wait()
	if st.Get(softwareCheckedKey) == "" || nvdHits.Load() != 1 {
		t.Fatalf("not pulled: checked=%q hits=%d", st.Get(softwareCheckedKey), nvdHits.Load())
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
