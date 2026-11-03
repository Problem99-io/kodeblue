package hub

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
	"github.com/Problem99-io/kodeblue/internal/research"
)

type autoFixture struct {
	server       *Server
	store        *Store
	research     *research.Store
	http         *httptest.Server
	client       *http.Client
	csrf, worker string
	now          time.Time
	serial       int
}

func newAutoFixture(t *testing.T) *autoFixture {
	t.Helper()
	r, err := research.Open(t.TempDir(), research.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	s, st, ts := newHubWith(t, func(o *Options) { o.Research = r })
	client, csrf := signIn(t, st, ts)
	source, token, err := st.CreateServer("automation-worker", "test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = st.Enroll(token, "worker", "test")
	if err != nil {
		t.Fatal(err)
	}
	_ = st.ApplySync(source.ID, &hubproto.SyncRequest{Status: hubproto.Status{SupportsInvestigator: true, AcceptsMessages: true, ModelsEnabled: true}})
	if err = r.PutSite(context.Background(), research.Site{ID: "website", Name: "Website", Timezone: "UTC", Servers: []string{source.ID}, BrowserEnabled: true, Origins: []string{"https://example.com"}}); err != nil {
		t.Fatal(err)
	}
	return &autoFixture{s, st, r, ts, client, csrf, source.ID, time.Now().UTC(), 0}
}

func TestResearchAutomationManualAdmissionStillWorks(t *testing.T) {
	f := newAutoFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	job, err := f.server.queueResearchInvestigation(ctx, "website", investigationRequest{Server: f.worker, Day: f.now.Format("2006-01-02"), Question: "Manual question"}, "test", "", nil)
	if err != nil {
		t.Fatalf("manual admission: %T: %v", err, err)
	}
	if job == nil {
		t.Fatal("missing native job")
	}
}

func (f *autoFixture) save(t *testing.T, suspicious, daily bool, hour int) {
	t.Helper()
	code, b := do(t, f.client, "PUT", f.http.URL+"/api/research/sites/website/automation", "", f.csrf, map[string]any{"worker": f.worker, "auto_suspicious": suspicious, "daily_report": daily, "daily_hour": hour})
	if code != 200 {
		t.Fatalf("save %d %s", code, b)
	}
}
func (f *autoFixture) requests(t *testing.T, count int, at time.Time) {
	t.Helper()
	events := []research.Event{}
	for i := 0; i < count; i++ {
		f.serial++
		events = append(events, research.Event{ID: fmt.Sprintf("automation-%d", f.serial), At: at, Kind: "request", Path: "/.env", Method: "GET", Status: 404})
	}
	for len(events) > 0 {
		n := min(len(events), 32)
		if _, err := f.research.Ingest(context.Background(), "website", f.worker, false, events[:n], f.now); err != nil {
			t.Fatal(err)
		}
		events = events[n:]
	}
}
func (f *autoFixture) jobs() []Message {
	return f.store.messages("WHERE command=? ORDER BY id", hubproto.CommandInvestigate)
}

func TestResearchAutomationDefaultsPermissionsAndValidation(t *testing.T) {
	f := newAutoFixture(t)
	url := f.http.URL + "/api/research/sites/website/automation"
	code, b := do(t, f.client, "GET", url, "", "", nil)
	var response struct {
		Settings researchAutoConfig `json:"settings"`
	}
	_ = json.Unmarshal(b, &response)
	if code != 200 || response.Settings.Suspicious || response.Settings.Daily || response.Settings.Hour != 8 {
		t.Fatalf("not opt-in: %d %s", code, b)
	}
	if code, _ = do(t, f.client, "PUT", url, "", "", map[string]any{}); code != 403 {
		t.Fatal("settings bypassed CSRF")
	}
	if code, _ = do(t, f.client, "PUT", url, "", f.csrf, map[string]any{"daily_hour": 24}); code != 400 {
		t.Fatal("invalid schedule accepted")
	}
	if code, _ = do(t, f.client, "PUT", url, "", f.csrf, map[string]any{"worker": "foreign", "auto_suspicious": true}); code != 403 {
		t.Fatal("foreign worker accepted")
	}
	f.requests(t, 40, f.now)
	f.server.researchAutomationTick(context.Background(), f.now)
	if len(f.jobs()) != 0 || len(f.store.Notifications("", 20)) != 0 {
		t.Fatal("disabled automation ran")
	}
}

func TestResearchAutomaticInvestigationBaselineCooldownAndDailyCap(t *testing.T) {
	f := newAutoFixture(t)
	ctx := context.Background()
	tick := f.now.Truncate(24 * time.Hour).Add(time.Hour)
	f.requests(t, 19, f.now)
	f.save(t, true, false, 8)
	f.server.researchAutomationTick(ctx, tick)
	if len(f.jobs()) != 0 {
		t.Fatal("historical traffic investigated on enable")
	}
	// Client claims cannot produce request evidence or satisfy the threshold.
	views := []research.Event{}
	for i := 0; i < 25; i++ {
		views = append(views, research.Event{ID: fmt.Sprintf("browser-%d", i), At: f.now, Kind: "pageview", Path: "/"})
	}
	if _, err := f.research.Ingest(ctx, "website", "browser", true, views, f.now); err != nil {
		t.Fatal(err)
	}
	f.server.researchAutomationTick(ctx, tick.Add(5*time.Minute))
	if len(f.jobs()) != 0 {
		t.Fatal("browser claims woke investigator")
	}
	f.requests(t, 20, f.now)
	f.server.researchAutomationTick(ctx, tick.Add(10*time.Minute))
	jobs := f.jobs()
	if len(jobs) != 1 || jobs[0].Author != "research-scheduler" {
		t.Fatal("lead did not use native message path", jobs)
	}
	f.requests(t, 20, f.now)
	f.server.researchAutomationTick(ctx, tick.Add(20*time.Minute))
	if len(f.jobs()) != 1 {
		t.Fatal("cooldown bypassed")
	}
	if err := f.store.Reply(f.worker, jobs[0].ID, hubproto.MessageReply{Status: "done"}); err != nil {
		t.Fatal(err)
	}
	for n := 1; n < 4; n++ {
		if n > 1 {
			f.requests(t, 20, f.now)
		}
		f.server.researchAutomationTick(ctx, tick.Add(time.Duration(n)*time.Hour+10*time.Minute))
		jobs = f.jobs()
		if len(jobs) != n+1 {
			t.Fatalf("run %d: %+v", n, jobs)
		}
		_ = f.store.Reply(f.worker, jobs[len(jobs)-1].ID, hubproto.MessageReply{Status: "done"})
	}
	f.requests(t, 100, f.now)
	f.server.researchAutomationTick(ctx, tick.Add(5*time.Hour))
	if len(f.jobs()) != 4 {
		t.Fatal("per-site daily cap bypassed")
	}
	p, err := readResearchAuto(ctx, f.store.db, "website")
	if err != nil || p.State.Runs != 4 {
		t.Fatalf("durable cap %+v %v", p, err)
	}
	// Saving the same enabled policy cannot reset the cap.
	f.save(t, true, false, 8)
	f.server.researchAutomationTick(ctx, tick.Add(6*time.Hour))
	if len(f.jobs()) != 4 {
		t.Fatal("save reset daily cap")
	}
}

func TestResearchAutomationDisableWithdrawsQueueAndRejectsStaleClaim(t *testing.T) {
	f := newAutoFixture(t)
	ctx := context.Background()
	f.save(t, true, false, 8)
	old, _ := readResearchAuto(ctx, f.store.db, "website")
	f.requests(t, 20, f.now)
	f.server.researchAutomationTick(ctx, f.now)
	if len(f.jobs()) != 1 {
		t.Fatal("job not queued")
	}
	f.save(t, false, false, 8)
	if f.jobs()[0].Status != "refused" {
		t.Fatal("disabled pending automatic job retained grant")
	}
	_, err := f.server.queueResearchInvestigation(ctx, "website", investigationRequest{Server: f.worker, Day: f.now.Format("2006-01-02"), Question: "stale tick"}, "research-scheduler", "", &researchAutoClaim{Version: old.Version, Day: f.now.Format("2006-01-02"), At: f.now})
	if err == nil || len(f.jobs()) != 1 {
		t.Fatal("stale scheduler queued after disable")
	}
}

func TestResearchAutomationReservationIsAtomicAndScopeChangesPause(t *testing.T) {
	f := newAutoFixture(t)
	ctx := context.Background()
	f.save(t, true, false, 8)
	f.requests(t, 20, f.now)
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); f.server.researchAutomationTick(ctx, f.now) }()
	}
	wg.Wait()
	if len(f.jobs()) != 1 {
		t.Fatal("concurrent ticks duplicated model dispatch")
	}
	_ = f.store.Reply(f.worker, f.jobs()[0].ID, hubproto.MessageReply{Status: "done"})
	site, _ := f.research.Site(ctx, "website")
	site.Timezone = "Asia/Jerusalem"
	if err := f.research.PutSite(ctx, site); err != nil {
		t.Fatal(err)
	}
	f.requests(t, 50, f.now)
	f.server.researchAutomationTick(ctx, f.now.Add(2*time.Hour))
	if len(f.jobs()) != 1 {
		t.Fatal("site scope expanded without renewed consent")
	}
	p, _ := readResearchAuto(ctx, f.store.db, "website")
	if !strings.Contains(p.State.SusError, "scope changed") {
		t.Fatal("scope pause was silent")
	}
}

func TestResearchDailyOverviewNoModelAndRestartDeduplication(t *testing.T) {
	f := newAutoFixture(t)
	ctx := context.Background()
	day := f.now.Truncate(24 * time.Hour)
	yesterday := day.AddDate(0, 0, -1)
	f.requests(t, 20, yesterday.Add(time.Hour))
	// Daily overviews are a hub calculation and do not require a live model.
	_ = f.store.ApplySync(f.worker, &hubproto.SyncRequest{Status: hubproto.Status{ModelsEnabled: false}})
	f.save(t, false, true, 8)
	f.server.researchAutomationTick(ctx, day.Add(7*time.Hour))
	if len(f.store.Notifications("", 20)) != 0 {
		t.Fatal("report sent before scheduled hour")
	}
	f.server.researchAutomationTick(ctx, day.Add(8*time.Hour))
	notes := f.store.Notifications("", 20)
	if len(notes) != 1 || !strings.Contains(notes[0].Body, "Received requests: 20") || !strings.Contains(notes[0].Body, "No model was called") || len(f.jobs()) != 0 {
		t.Fatalf("daily report %+v", notes)
	}
	restarted := NewServer(f.server.opt, f.store, f.server.log)
	restarted.researchAutomationTick(ctx, day.Add(10*time.Hour))
	if len(f.store.Notifications("", 20)) != 1 {
		t.Fatal("restart duplicated daily report")
	}
	// Empty days still report the coverage gap, without starting an agent.
	restarted.researchAutomationTick(ctx, day.AddDate(0, 0, 1).Add(8*time.Hour))
	notes = f.store.Notifications("", 20)
	if len(notes) != 2 || !strings.Contains(notes[0].Body, "Received requests: 0") || len(f.jobs()) != 0 {
		t.Fatal("empty-day reporting spent model calls or disappeared")
	}
}

func TestResearchDailyUsesSiteCalendarAcrossDST(t *testing.T) {
	for _, tc := range []struct{ zone, at, want string }{
		{"America/New_York", "2026-03-09T08:00:00", "2026-03-08"},
		{"America/New_York", "2026-11-02T08:00:00", "2026-11-01"},
		{"Asia/Kathmandu", "2026-10-31T08:00:00", "2026-10-30"},
	} {
		zone, err := time.LoadLocation(tc.zone)
		if err != nil {
			t.Fatal(err)
		}
		local, err := time.ParseInLocation("2006-01-02T15:04:05", tc.at, zone)
		if err != nil {
			t.Fatal(err)
		}
		if got := researchDailyDate(local); got != tc.want {
			t.Fatalf("%s: %s != %s", tc.zone, got, tc.want)
		}
	}
}

func TestResearchAutomationCounterLossResetsWithoutCallingModel(t *testing.T) {
	f := newAutoFixture(t)
	ctx := context.Background()
	f.requests(t, 30, f.now)
	f.save(t, true, false, 8)
	p, _ := readResearchAuto(ctx, f.store.db, "website")
	// Simulate bounded-summary loss, which makes today's counter fall.
	f.server.updateResearchAutoState(ctx, p, func(state *researchAutoState) { state.Sensitive = 100 })
	f.server.researchAutomationTick(ctx, f.now)
	current, _ := readResearchAuto(ctx, f.store.db, "website")
	if current.State.Sensitive != 30 || len(f.jobs()) != 0 || !strings.Contains(current.State.SusError, "coverage changed") {
		t.Fatal("counter loss caused an investigation or a permanently blocked baseline")
	}
	f.requests(t, 20, f.now)
	f.server.researchAutomationTick(ctx, f.now.Add(6*time.Minute))
	if len(f.jobs()) != 1 {
		t.Fatal("new evidence did not qualify after baseline recovery")
	}
}

func TestResearchAutomaticCooldownCrossesMidnight(t *testing.T) {
	f := newAutoFixture(t)
	ctx := context.Background()
	f.save(t, true, false, 8)
	f.requests(t, 20, f.now)
	day := f.now.Truncate(24 * time.Hour)
	p, _ := readResearchAuto(ctx, f.store.db, "website")
	f.server.updateResearchAutoState(ctx, p, func(state *researchAutoState) {
		state.Day = day.AddDate(0, 0, -1).Format("2006-01-02")
		state.LastSus = day.Add(-10 * time.Minute).Unix()
		state.Runs = 4
		state.Sensitive = 100
	})
	f.server.researchAutomationTick(ctx, day.Add(5*time.Minute))
	if len(f.jobs()) != 0 {
		t.Fatal("midnight bypassed hourly cooldown")
	}
	f.server.researchAutomationTick(ctx, day.Add(time.Hour))
	if len(f.jobs()) != 1 {
		t.Fatal("new calendar day did not reset the daily cap after cooldown")
	}
}
