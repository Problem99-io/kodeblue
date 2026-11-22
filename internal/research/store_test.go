package research

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func testStore(t *testing.T, change func(*Limits)) *Store {
	t.Helper()
	l := DefaultLimits()
	if change != nil {
		change(&l)
	}
	s, err := Open(t.TempDir(), l)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	for _, id := range []string{"website", "other"} {
		if err = s.PutSite(context.Background(), Site{ID: id, Name: id, Timezone: "UTC", Origins: []string{"https://example.com"}, Servers: []string{"srv_gateway"}, BrowserEnabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func request(id string, at time.Time) Event {
	return Event{ID: id, At: at, Kind: "request", Path: "/.env", Method: "GET", Status: 404, PeerIP: "203.0.113.5"}
}

func TestIngestIdempotentAndSourceBound(t *testing.T) {
	s := testStore(t, nil)
	ctx := context.Background()
	now := time.Now().UTC()
	e := request("one", now)
	if _, err := s.Ingest(ctx, "website", "srv_foreign", false, []Event{e}, now); !errors.Is(err, ErrScope) {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.Ingest(ctx, "website", "srv_gateway", false, []Event{e}, now)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	r, err := s.Daily(ctx, "website", now.Format("2006-01-02"))
	if err != nil || r.Requests != 1 {
		t.Fatalf("duplicate count: %+v %v", r, err)
	}
	p, err := s.Events(ctx, "other", 0, 100)
	if err != nil || len(p.Observations) != 0 {
		t.Fatalf("site leaked: %+v %v", p, err)
	}
}

func TestBrowserCannotForgeTrustedFields(t *testing.T) {
	s := testStore(t, nil)
	now := time.Now().UTC()
	ctx := context.Background()
	for _, e := range []Event{request("request", now), {ID: "ip", At: now, Kind: "pageview", PeerIP: "203.0.113.5"}, {ID: "fp", At: now, Kind: "pageview", Fingerprint: &Fingerprint{Algorithm: "ja4", Version: "1", Value: "abcd", CapturePoint: "ingress"}}, {ID: "name", At: now, Kind: "interaction", Name: "arbitrary_value"}, {ID: "perf", At: now, Kind: "performance", Name: "contact_click"}} {
		if _, err := s.Ingest(ctx, "website", "browser", true, []Event{e}, now); !errors.Is(err, ErrInvalid) {
			t.Fatalf("accepted forged browser field: %+v %v", e, err)
		}
	}
	e := Event{ID: "view", At: now, Kind: "pageview", Path: "/reset/secret-value?token=credential#secret"}
	if _, err := s.Ingest(ctx, "website", "browser", true, []Event{e}, now); err != nil {
		t.Fatal(err)
	}
	p, err := s.Events(ctx, "website", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Observations) != 1 || p.Observations[0].Provenance != "browser_claimed" || p.Observations[0].Event.Path != "/:other" {
		t.Fatalf("not minimized: %+v", p)
	}
}

func TestCapacityRetainsCountsAndRetryKeys(t *testing.T) {
	s := testStore(t, func(l *Limits) { l.MaxEvents = 5; l.MaxSiteEvents = 3 })
	ctx := context.Background()
	now := time.Now().UTC()
	for i := 0; i < 12; i++ {
		e := request(fmt.Sprintf("r%d", i), now)
		if _, err := s.Ingest(ctx, "website", "srv_gateway", false, []Event{e}, now); err != nil {
			t.Fatal(err)
		}
	}
	p, err := s.Events(ctx, "website", 0, 100)
	if err != nil || len(p.Observations) != 3 || p.Coverage.DetailEvicted != 9 {
		t.Fatalf("detail cap: %+v %v", p, err)
	}
	if _, err = s.Ingest(ctx, "website", "srv_gateway", false, []Event{request("r0", now)}, now); err != nil {
		t.Fatal(err)
	}
	r, err := s.Daily(ctx, "website", now.Format("2006-01-02"))
	if err != nil || r.Requests != 12 {
		t.Fatalf("compaction/retry changed counts: %+v %v", r, err)
	}
	for i := 0; i < 3; i++ {
		if _, err = s.Ingest(ctx, "other", "srv_gateway", false, []Event{request(fmt.Sprintf("o%d", i), now)}, now); err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err = s.db.QueryRow("SELECT COUNT(*) FROM events").Scan(&count); err != nil || count != 5 {
		t.Fatalf("global row budget: %d %v", count, err)
	}
}

func TestReceiptCapacityIsVisibleAndRetriesStillWork(t *testing.T) {
	s := testStore(t, func(l *Limits) { l.MaxEvents = 2; l.MaxSiteEvents = 2 })
	ctx := context.Background()
	now := time.Now().UTC()
	for i := 0; i < 8; i++ {
		if _, err := s.Ingest(ctx, "website", "srv_gateway", false, []Event{request(fmt.Sprintf("r%d", i), now)}, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Ingest(ctx, "website", "srv_gateway", false, []Event{request("overflow", now)}, now); !errors.Is(err, ErrCapacity) {
		t.Fatalf("overflow not surfaced: %v", err)
	}
	r, err := s.Ingest(ctx, "website", "srv_gateway", false, []Event{request("r0", now)}, now)
	if err != nil || r.Duplicates != 1 {
		t.Fatalf("retry refused at cap: %+v %v", r, err)
	}
}

func TestPruneAndDeleteRemoveDependentData(t *testing.T) {
	s := testStore(t, nil)
	ctx := context.Background()
	now := time.Now().UTC()
	if _, err := s.Ingest(ctx, "website", "srv_gateway", false, []Event{request("one", now)}, now); err != nil {
		t.Fatal(err)
	}
	if err := s.Maintain(ctx, now.Add(4*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	var raw, compact int
	s.db.QueryRow("SELECT COUNT(*) FROM events").Scan(&raw)
	s.db.QueryRow("SELECT COUNT(*) FROM buckets").Scan(&compact)
	if raw != 0 || compact != 1 {
		t.Fatalf("retention tiers: %d %d", raw, compact)
	}
	if err := s.DeleteSite(ctx, "website"); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"events", "receipts", "buckets", "coverage"} {
		var n int
		if err := s.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil || n != 0 {
			t.Fatalf("orphan %s: %d %v", table, n, err)
		}
	}
}

func TestFingerprintIsNotActorOrCommunication(t *testing.T) {
	s := testStore(t, nil)
	ctx := context.Background()
	now := time.Now().UTC()
	e := request("fingerprint", now)
	e.Fingerprint = &Fingerprint{Algorithm: "ja4", Version: "1", Value: "common_browser", CapturePoint: "client_ingress"}
	connection := Event{ID: "connection", At: now, Kind: "connection", PeerIP: "10.0.0.2", DestinationIP: "10.0.0.3"}
	if _, err := s.Ingest(ctx, "website", "srv_gateway", false, []Event{e, connection}, now); err != nil {
		t.Fatal(err)
	}
	g, err := s.Graph(ctx, "website")
	if err != nil || g.Identity != "not_established" || len(g.Edges) != 2 {
		t.Fatalf("graph %+v %v", g, err)
	}
	if g.Edges[0].Relation != "fingerprint_observed_at_source" || g.Edges[1].Relation != "producer_reported_connection" {
		t.Fatalf("misleading relation: %+v", g)
	}
}

func TestCalendarBoundariesAndHonestSuspicion(t *testing.T) {
	s := testStore(t, nil)
	ctx := context.Background()
	now := time.Now().UTC()
	site, _ := s.Site(ctx, "website")
	site.Timezone = "Asia/Kathmandu"
	if err := s.PutSite(ctx, site); err != nil {
		t.Fatal(err)
	}
	loc, _ := time.LoadLocation(site.Timezone)
	date := now.In(loc).Format("2006-01-02")
	day, _ := time.ParseInLocation("2006-01-02", date, loc)
	at := day.Add(time.Minute)
	if at.After(now) {
		at = now
	}
	for i := 0; i < 20; i++ {
		e := request(fmt.Sprintf("r%d", i), at)
		if _, err := s.Ingest(ctx, "website", "srv_gateway", false, []Event{e}, now); err != nil {
			t.Fatal(err)
		}
	}
	r, err := s.Daily(ctx, "website", date)
	if err != nil || r.Requests != 20 || r.BoundaryUncertainty || len(r.Findings) != 1 || r.Findings[0].Conclusion != "needs_review" || r.Findings[0].Identity != "not_established" {
		t.Fatalf("report: %+v %v", r, err)
	}
	// Find a DST transition within the retained test range without depending on
	// today's date or a hard-coded deployment timezone.
	site.Timezone = "America/New_York"
	if err = s.PutSite(ctx, site); err != nil {
		t.Fatal(err)
	}
	ny, _ := time.LoadLocation(site.Timezone)
	for i := 0; i < 29; i++ {
		d := now.In(ny).AddDate(0, 0, -i).Format("2006-01-02")
		report, err := s.Daily(ctx, "website", d)
		if err != nil {
			t.Fatal(err)
		}
		if report.End.Sub(report.Start) != 24*time.Hour && report.End.Sub(report.Start) != 23*time.Hour && report.End.Sub(report.Start) != 25*time.Hour {
			t.Fatal("invalid calendar window")
		}
	}
}

func TestBrowserFloodPreservesTrustedDetailAndReceiptReserve(t *testing.T) {
	s := testStore(t, func(l *Limits) { l.MaxEvents = 5; l.MaxSiteEvents = 3 })
	ctx := context.Background()
	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		if _, err := s.Ingest(ctx, "website", "srv_gateway", false, []Event{request(fmt.Sprintf("trusted%d", i), now)}, now); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 15; i++ {
		e := Event{ID: fmt.Sprintf("b%d", i), At: now, Kind: "pageview", Path: "/"}
		if _, err := s.Ingest(ctx, "website", "browser", true, []Event{e}, now); err != nil {
			t.Fatal(err)
		}
	}
	p, err := s.Events(ctx, "website", 0, 100)
	if err != nil || len(p.Observations) != 3 {
		t.Fatal(err)
	}
	for _, o := range p.Observations {
		if o.Source == "browser" {
			t.Fatal("browser evicted protected producer detail")
		}
	}
	if _, err = s.Ingest(ctx, "website", "browser", true, []Event{{ID: "overflow", At: now, Kind: "pageview"}}, now); !errors.Is(err, ErrCapacity) {
		t.Fatal("browser used reserved receipt capacity")
	}
	if _, err = s.Ingest(ctx, "website", "srv_gateway", false, []Event{request("new_trusted", now)}, now); err != nil {
		t.Fatalf("no source reserve: %v", err)
	}
}

func TestPathRedactsAfterInvisibleNormalization(t *testing.T) {
	path, err := NormalizePath("/token/abcdef\u200babcdefabcdefabcdefabcdefabcdef?password=never-store#fragment")
	if err != nil || path != "/token/:redacted" {
		t.Fatalf("normalization: %q %v", path, err)
	}
}

func TestRepeatedIngestRetentionCyclesStayBounded(t *testing.T) {
	s := testStore(t, func(l *Limits) { l.MaxBytes = 3 << 20; l.MaxEvents = 1000; l.MaxSiteEvents = 20; l.MaxBuckets = 20 })
	ctx := context.Background()
	base := time.Now().UTC()
	var peak int64
	for cycle := 0; cycle < 4; cycle++ {
		now := base.Add(time.Duration(cycle) * 4 * 24 * time.Hour)
		if err := s.Maintain(ctx, now); err != nil {
			t.Fatal(err)
		}
		for start := 0; start < 1000; start += 32 {
			batch := []Event{}
			for i := start; i < start+32 && i < 1000; i++ {
				batch = append(batch, request(fmt.Sprintf("cycle%d-%d", cycle, i), now))
			}
			if _, err := s.Ingest(ctx, "website", "srv_gateway", false, batch, now); err != nil {
				t.Fatal(err)
			}
			bytes, err := s.PhysicalBytes()
			if err != nil || bytes > s.limits.MaxBytes {
				t.Fatalf("physical storage exceeded: %d %v", bytes, err)
			}
			if bytes > peak {
				peak = bytes
			}
		}
		var raw int
		if err := s.db.QueryRow("SELECT COUNT(*) FROM events").Scan(&raw); err != nil || raw != 20 {
			t.Fatalf("detail did not roll: %d %v", raw, err)
		}
	}
	var total int
	if err := s.db.QueryRow("SELECT SUM(n) FROM buckets").Scan(&total); err != nil || total != 4000 {
		t.Fatalf("compaction lost or duplicated counts: %d %v", total, err)
	}
	t.Logf("4,000 observations across four retention cycles; detail capped at 20; physical DB/journal peak %d bytes", peak)
}

func TestPhysicalBudgetAndBoundedDimensions(t *testing.T) {
	l := DefaultLimits()
	l.MaxBytes = 3 << 20
	l.MaxEvents = 50
	l.MaxSiteEvents = 5
	l.MaxBuckets = 4
	dir := t.TempDir()
	s, err := Open(dir, l)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	if err = s.PutSite(ctx, Site{ID: "site", Name: "Site", Timezone: "UTC", Servers: []string{"srv"}}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 80; i++ {
		e := request(fmt.Sprintf("r%d", i), now.Add(-time.Duration(i)*time.Hour/2))
		e.Path = "/" + strings.Repeat("x", 200)
		if _, err = s.Ingest(ctx, "site", "srv", false, []Event{e}, now); err != nil {
			t.Fatal(err)
		}
	}
	var buckets int
	s.db.QueryRow("SELECT COUNT(*) FROM buckets").Scan(&buckets)
	if buckets > 4 {
		t.Fatal("bucket cap")
	}
	bytes, err := s.PhysicalBytes()
	if err != nil || bytes > l.MaxBytes {
		t.Fatalf("physical budget: %d %v", bytes, err)
	}
	st, err := os.Stat(s.path)
	if err != nil || st.Size() > l.MaxBytes/3 {
		t.Fatal("database page cap")
	}
	c, err := s.Coverage(ctx, "site")
	if err != nil || c.SummaryEvicted == 0 {
		t.Fatal("summary gaps hidden")
	}
}
