package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/config"
	"github.com/Problem99-io/kodeblue/internal/blue/detect"
	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
	"github.com/Problem99-io/kodeblue/internal/blue/llm"
	"github.com/Problem99-io/kodeblue/internal/blue/notify"
	"github.com/Problem99-io/kodeblue/internal/blue/runtime"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
	"github.com/Problem99-io/kodeblue/internal/blue/triage"
)

// logRecorder keeps every log record for assertions.
type logRecorder struct {
	mu   sync.Mutex
	recs []string
}

func (l *logRecorder) Enabled(context.Context, slog.Level) bool { return true }
func (l *logRecorder) WithAttrs([]slog.Attr) slog.Handler       { return l }
func (l *logRecorder) WithGroup(string) slog.Handler            { return l }
func (l *logRecorder) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString(r.Time.Format("15:04:05.000 ") + r.Message)
	r.Attrs(func(a slog.Attr) bool { fmt.Fprintf(&b, " %s=%v", a.Key, a.Value); return true })
	l.mu.Lock()
	l.recs = append(l.recs, b.String())
	l.mu.Unlock()
	return nil
}

func (l *logRecorder) matching(prefix string) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	for _, r := range l.recs {
		if strings.HasPrefix(r[13:], prefix) {
			out = append(out, r)
		}
	}
	return out
}

// sent records notifications instead of posting them.
type sent struct {
	mu   sync.Mutex
	msgs []notify.Message
}

func (s *sent) Send(_ context.Context, m notify.Message) error { s.Async(m, nil); return nil }
func (s *sent) Async(m notify.Message, _ func(error)) {
	s.mu.Lock()
	s.msgs = append(s.msgs, m)
	s.mu.Unlock()
}
func (s *sent) titles() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, m := range s.msgs {
		out = append(out, m.Title)
	}
	return out
}
func (s *sent) reset() { s.mu.Lock(); s.msgs = nil; s.mu.Unlock() }

func newTestDaemon(t *testing.T) (*Daemon, *store.Store, *logRecorder, *sent) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Server.StateDir = filepath.Join(dir, "state")
	cfg.Server.Root = filepath.Join(dir, "root")
	cfg.Requests.Disabled = true
	for _, p := range []string{cfg.Server.StateDir, filepath.Join(cfg.Server.Root, "etc")} {
		if err := os.MkdirAll(p, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	st, err := store.Open(filepath.Join(cfg.Server.StateDir, "kb.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	rec := &logRecorder{}
	d := New(cfg, st, slog.New(rec))
	d.restartGap = 0 // tests restart at once
	out := &sent{}
	d.slack = out
	t.Cleanup(d.wg.Wait) // investigations opened by a test finish before the store closes
	return d, st, rec, out
}

// fakeEngine stands in for the agent engine child process.
type fakeEngine struct {
	id       int
	startErr error
	alive    atomic.Bool
	stopped  atomic.Bool
	// runFor is how long a session's run takes; 0 runs until ctx ends.
	runFor time.Duration
	n      atomic.Int32
	// script, when it holds one, is the next run's outcome.
	script chan runtime.Outcome
}

func (f *fakeEngine) Start(context.Context) error {
	if f.startErr != nil {
		return f.startErr
	}
	f.alive.Store(true)
	return nil
}
func (f *fakeEngine) Stop()       { f.stopped.Store(true); f.alive.Store(false) }
func (f *fakeEngine) Alive() bool { return f.alive.Load() }
func (f *fakeEngine) StartSession(context.Context, string, string, string, string) (*runtime.Session, error) {
	if f.stopped.Load() {
		return nil, errors.New("connection refused")
	}
	return &runtime.Session{ID: fmt.Sprintf("e%d-s%d", f.id, f.n.Add(1)), RunID: "r1"}, nil
}
func (f *fakeEngine) FollowUp(_ context.Context, s *runtime.Session, _ string) (*runtime.Session, error) {
	if f.stopped.Load() {
		return nil, errors.New("connection refused")
	}
	return s, nil
}
func (f *fakeEngine) Steer(context.Context, *runtime.Session, string) error { return nil }
func (f *fakeEngine) Abort(context.Context, string) error                   { return nil }
func (f *fakeEngine) WaitSession(ctx context.Context, s *runtime.Session, timeout time.Duration) runtime.Outcome {
	return f.Wait(ctx, s, timeout)
}
func (f *fakeEngine) Wait(ctx context.Context, _ *runtime.Session, timeout time.Duration) runtime.Outcome {
	select {
	case o := <-f.script:
		return o
	default:
	}
	var done <-chan time.Time
	if f.runFor > 0 {
		done = time.After(f.runFor)
	}
	select {
	case <-ctx.Done():
		return runtime.Outcome{Status: "timeout"}
	case <-time.After(timeout):
		return runtime.Outcome{Status: "timeout"}
	case <-done:
		return runtime.Outcome{Status: "completed", Text: "done"}
	}
}
func (f *fakeEngine) SessionCost(context.Context, string) (float64, int, int, int) {
	return 0.01, 100, 10, 0
}
func (f *fakeEngine) Transcript(context.Context, string, bool) ([]hubproto.Turn, error) {
	if f.stopped.Load() {
		return nil, errors.New("connection refused")
	}
	return nil, nil
}

// engines makes fake engines; every failEvery-th one fails to start.
type engines struct {
	mu        sync.Mutex
	made      []*fakeEngine
	failEvery int
	runFor    time.Duration
}

func (e *engines) factory() agentEngine {
	e.mu.Lock()
	defer e.mu.Unlock()
	f := &fakeEngine{id: len(e.made) + 1, runFor: e.runFor}
	if e.failEvery > 0 && f.id%e.failEvery == 0 {
		f.startErr = errors.New("engine did not become healthy")
	}
	e.made = append(e.made, f)
	return f
}

func (e *engines) last() *fakeEngine {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.made[len(e.made)-1]
}

func newIncident(t *testing.T, st *store.Store, sev string) (*store.Incident, []store.Finding) {
	t.Helper()
	f := &store.Finding{Fingerprint: fmt.Sprint(time.Now().UnixNano()), Collector: "c", Rule: "r", Severity: sev, Title: "x"}
	if err := st.AddFinding(f); err != nil {
		t.Fatal(err)
	}
	in := &store.Incident{Title: "t", Severity: sev, Kind: "incident"}
	if err := st.CreateIncident(in); err != nil {
		t.Fatal(err)
	}
	_ = st.SetFindingStatus(f.ID, "incident", "", "", in.ID)
	return in, []store.Finding{*f}
}

// The engine supervisor replaces the engine (or leaves none, when a restart
// fails) while investigations and hub handlers use it. Run with -race: the
// old code swapped d.kc unsynchronized and a nil d.kc panicked in an
// investigation goroutine, killing the daemon.
func TestEngineSwapUnderLoad(t *testing.T) {
	d, st, _, _ := newTestDaemon(t)
	d.modelsOn = true
	d.engMinBackoff = 0
	d.incSem = make(chan struct{}, 4)
	eng := &engines{failEvery: 3, runFor: 20 * time.Millisecond}
	d.newEngine = eng.factory
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := d.startEngine(ctx); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	var ids []int64
	for i := 0; i < 24; i++ {
		in, fs := newIncident(t, st, detect.SevHigh)
		ids = append(ids, in.ID)
		wg.Add(1)
		go func() { defer wg.Done(); d.investigate(ctx, in, fs) }()
	}
	stopHub := make(chan struct{})
	var hubWG sync.WaitGroup
	hubWG.Add(1)
	go func() { // hub handlers read the engine at the same time
		defer hubWG.Done()
		for {
			select {
			case <-stopHub:
				return
			default:
			}
			_ = d.ModelsEnabled()
			_, _ = d.Transcript(ctx, "s", true)
			_ = d.StopSession(ctx, hubproto.OperatorMessage{SessionID: "nope"})
			_ = d.joinLiveIncident(ctx, []*store.Finding{{ID: 1, Severity: detect.SevHigh}})
		}
	}()
	for i := 0; i < 60; i++ {
		if e := d.engine(); e != nil {
			e.(*fakeEngine).alive.Store(false) // the child died
		}
		d.superviseEngine(ctx)
		time.Sleep(2 * time.Millisecond)
	}
	wg.Wait()
	close(stopHub)
	hubWG.Wait()

	for _, id := range ids {
		in := st.GetIncident(id)
		if in.Status == "investigating" {
			t.Fatalf("incident %d left investigating: %+v", id, in)
		}
	}
	// Every engine but the current one was stopped.
	cur := d.engine()
	for _, e := range eng.made {
		if agentEngine(e) != cur && !e.stopped.Load() {
			t.Fatalf("engine %d left running", e.id)
		}
	}
}

// An investigation waiting on an engine that dies ends at once and goes to a
// human, instead of polling a dead process for 20 minutes or panicking.
func TestInvestigationEndsWhenEngineDies(t *testing.T) {
	d, st, _, out := newTestDaemon(t)
	d.modelsOn = true
	eng := &engines{} // sessions run until their context ends
	d.newEngine = eng.factory
	ctx := context.Background()
	if err := d.startEngine(ctx); err != nil {
		t.Fatal(err)
	}
	in, fs := newIncident(t, st, detect.SevHigh)
	done := make(chan struct{})
	go func() { defer close(done); d.investigate(ctx, in, fs) }()
	waitFor(t, func() bool { return len(d.LiveSessions()) == 1 })

	eng.last().alive.Store(false)
	d.superviseEngine(ctx)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("investigation still waiting on a dead engine")
	}
	got := st.GetIncident(in.ID)
	if got.Status != "needs_human" || !strings.Contains(got.Summary, "engine went away") {
		t.Fatalf("incident after engine loss: %s %q", got.Status, got.Summary)
	}
	if len(eng.made) != 2 || d.engine() != agentEngine(eng.made[1]) || !eng.made[0].stopped.Load() {
		t.Fatalf("engine not replaced: made %d", len(eng.made))
	}
	if !strings.Contains(strings.Join(out.titles(), "\n"), fmt.Sprintf("#%d", in.ID)) {
		t.Fatalf("no notification for the incident: %v", out.titles())
	}
}

// A failed restart used to leave d.kc nil for good: the supervisor returned
// early on nil. It now keeps trying with backoff.
func TestEngineRestartRetriesWithBackoff(t *testing.T) {
	d, _, _, _ := newTestDaemon(t)
	d.modelsOn = true
	d.engMinBackoff = 30 * time.Millisecond
	fails := 2
	var made int
	d.newEngine = func() agentEngine {
		made++
		f := &fakeEngine{id: made}
		if made <= fails {
			f.startErr = errors.New("boom")
		}
		return f
	}
	ctx := context.Background()
	d.superviseEngine(ctx) // fails (1)
	if d.engine() != nil || made != 1 {
		t.Fatalf("made %d", made)
	}
	d.superviseEngine(ctx) // within backoff: no attempt
	if made != 1 {
		t.Fatalf("retried inside the backoff: made %d", made)
	}
	time.Sleep(40 * time.Millisecond)
	d.superviseEngine(ctx) // fails (2), backoff doubles
	if made != 2 || d.engBackoff != 60*time.Millisecond {
		t.Fatalf("made %d backoff %s", made, d.engBackoff)
	}
	time.Sleep(70 * time.Millisecond)
	d.superviseEngine(ctx)
	if d.engine() == nil || made != 3 || d.engBackoff != 0 {
		t.Fatalf("engine not started after failures: made %d", made)
	}
	// No model layer: never started.
	d2, _, _, _ := newTestDaemon(t)
	d2.newEngine = func() agentEngine { t.Fatal("started without models"); return nil }
	d2.superviseEngine(ctx)
}

// slowModel is an inference endpoint that holds every request until
// released, like a model chewing on a big triage batch.
func slowModel(t *testing.T) (url string, calls *atomic.Int32, release func()) {
	t.Helper()
	calls = &atomic.Int32{}
	gate := make(chan struct{})
	var once sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		select {
		case <-gate:
		case <-r.Context().Done():
		}
		http.Error(w, "bad request", http.StatusBadRequest)
	}))
	release = func() { once.Do(func() { close(gate) }) }
	t.Cleanup(func() { release(); srv.Close() })
	return srv.URL, calls, release
}

// Triage used to run inline in the sweep loop (up to 5 batches × 2 attempts
// × 120 s): during an attack burst sweeps and fast-watch wakes stalled, and
// wakes beyond the channel's 8 slots were dropped. Sweeps now keep running
// while triage waits on the model, and wakes coalesce.
func TestSweepsContinueWhileTriageWaits(t *testing.T) {
	d, st, rec, _ := newTestDaemon(t)
	_ = st.Set("learned_at", time.Now().UTC().Format(time.RFC3339))
	url, calls, release := slowModel(t)
	d.tri = &triage.Triager{Client: llm.New(url, "k"), Model: "m", Store: st, Env: d.env}
	d.claimGrace = 0 // the finding below is recorded straight into the queue
	f := &store.Finding{Fingerprint: "fp", Collector: "c", Rule: "r", Severity: detect.SevHigh, Title: "suspicious"}
	if err := st.AddFinding(f); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // a failed wait must not leave Run running for the cleanup
	ran := make(chan error, 1)
	go func() { ran <- d.Run(ctx) }()
	waitFor(t, func() bool { return calls.Load() > 0 }) // triage is stuck on the model

	for i := 0; i < 3; i++ {
		why := fmt.Sprintf("probe-%d", i)
		d.Wake(why)
		waitFor(t, func() bool { return len(rec.matching("sweep trigger="+why)) > 0 })
	}
	// A burst of wakes while the loop is busy: none is lost, they coalesce.
	for i := 0; i < 50; i++ {
		d.Wake(fmt.Sprintf("burst-%d", i))
	}
	waitFor(t, func() bool { return len(rec.matching("sweep trigger=burst-")) > 0 })
	if g := st.GetFinding(f.ID); g.Status != "triaging" {
		t.Fatalf("finding should be claimed by the running triage, is %s", g.Status)
	}
	// The systemd watchdog's deadline is the main loop's own: it keeps
	// renewing it while triage waits on the model.
	if by := time.Unix(0, d.progressBy.Load()); !by.After(time.Now()) || by.After(time.Now().Add(time.Duration(max(d.cfg.Schedule.SweepSeconds, 10))*time.Second+loopGrace)) {
		t.Fatalf("main loop deadline %s while triage waits", by)
	}

	release()
	waitFor(t, func() bool { return st.GetFinding(f.ID).Status != "triaging" })
	cancel()
	select {
	case err := <-ran:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not stop")
	}
	// The model failing escalates the finding into an incident (fail safe).
	if g := st.GetFinding(f.ID); g.Status != "incident" && g.Status != "escalated" {
		t.Fatalf("finding after failed triage: %s", g.Status)
	}
}

func TestWakesCoalesce(t *testing.T) {
	d, _, _, _ := newTestDaemon(t)
	for i := 0; i < 20; i++ {
		d.Wake(fmt.Sprintf("w%d", i%7))
	}
	if len(d.wakeCh) != 1 {
		t.Fatalf("want one pending wake, got %d", len(d.wakeCh))
	}
	<-d.wakeCh
	if why := d.takeWake(); why != "w0; w1; w2; w3; w4 (+15 more)" {
		t.Fatalf("reasons %q", why)
	}
	if why := d.takeWake(); why != "wake" {
		t.Fatalf("reasons not reset: %q", why)
	}
}

// A change right after a fast-watch wake used to be forgotten: the 10 s rate
// limit skipped it and the next tick no longer saw it as a change.
func TestFastWatchKeepsChangesInsideTheGap(t *testing.T) {
	d, _, _, _ := newTestDaemon(t)
	d.cfg.Schedule.FastWatchSeconds = 1
	d.wakeGap = 1500 * time.Millisecond
	passwd := d.env.Path("/etc/passwd")
	if err := os.WriteFile(passwd, []byte("root:x:0:0::/root:/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.fastWatch(ctx)
	time.Sleep(1200 * time.Millisecond) // first tick records the state
	_ = os.WriteFile(passwd, []byte("root:x:0:0::/root:/bin/sh\nx:x:0:0::/:/bin/sh\n"), 0o644)
	waitFor(t, func() bool { return len(d.wakeCh) == 1 })
	<-d.wakeCh
	_ = d.takeWake()
	// Inside the gap: must still produce a wake once the gap has passed.
	_ = os.WriteFile(d.env.Path("/etc/group"), []byte("root:x:0:\n"), 0o644)
	waitFor(t, func() bool { return len(d.wakeCh) == 1 })
	if why := d.takeWake(); !strings.Contains(why, "/etc/group") {
		t.Fatalf("wake reasons %q", why)
	}
}

// The maintenance-until file is kodeblue-writable; only the CLI enforced the
// 24 h limit. The daemon clamps it, reports a longer one as tampering, and
// announces the window opening, being extended, and ending.
func TestMaintenanceWindowClampedAndAnnounced(t *testing.T) {
	d, st, _, out := newTestDaemon(t)
	path := d.cfg.MaintenanceFile()
	write := func(until time.Time, mtime time.Time) {
		t.Helper()
		if err := os.WriteFile(path, []byte(until.UTC().Format(time.RFC3339)), 0o640); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, mtime, mtime); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now()
	d.announceMaintenance() // the startup sweep: no window yet

	// A normal 2 h window from the CLI.
	write(now.Add(2*time.Hour), now)
	d.announceMaintenance()
	if d.mode() != detect.ModeMaintenance {
		t.Fatal("2h window not active")
	}
	if got := out.titles(); len(got) != 1 || !strings.HasPrefix(got[0], "Maintenance window opened") {
		t.Fatalf("open: %v", got)
	}
	out.reset()
	d.announceMaintenance()
	if len(out.titles()) != 0 {
		t.Fatalf("re-announced an unchanged window: %v", out.titles())
	}

	// Extended within the limit.
	write(now.Add(5*time.Hour), now)
	d.announceMaintenance()
	if got := out.titles(); len(got) != 1 || !strings.HasPrefix(got[0], "Maintenance window extended") {
		t.Fatalf("extend: %v", got)
	}
	out.reset()

	// 30 days by hand: clamped to 24 h from the write, reported as tampering.
	write(now.Add(30*24*time.Hour), now)
	w := d.maintenance(time.Now())
	if w.Tamper == "" || w.Until.After(now.Add(24*time.Hour+time.Second)) {
		t.Fatalf("30-day window not clamped: %+v", w)
	}
	d.announceMaintenance()
	got := strings.Join(out.titles(), "\n")
	if !strings.Contains(got, "not written by kodeblue maintenance") || !strings.Contains(got, "extended") {
		t.Fatalf("tamper: %v", got)
	}
	if j := st.JournalSince(now.Add(-time.Minute), 50); !hasAction(j, "maintenance.tamper") {
		t.Fatal("tampering not journaled")
	}
	if until, tamper, ok := MaintenanceStatus(st, now.Add(30*24*time.Hour).UTC().Format(time.RFC3339)); !ok || tamper == "" || !until.Equal(w.Until) {
		t.Fatalf("status: %v %q %v", until, tamper, ok)
	}
	if _, _, ok := MaintenanceStatus(st, "something else"); ok {
		t.Fatal("status for a file the daemon has not seen")
	}
	out.reset()
	d.announceMaintenance()
	if len(out.titles()) != 0 {
		t.Fatalf("tampering re-announced every sweep: %v", out.titles())
	}

	// Written 25 h ago (or with an mtime set back): no window at all.
	write(now.Add(30*24*time.Hour), now.Add(-25*time.Hour))
	if d.mode() != detect.ModeDetect {
		t.Fatal("window older than 24 h still active")
	}
	d.announceMaintenance()
	if got := strings.Join(out.titles(), "\n"); !strings.Contains(got, "Maintenance window ended") {
		t.Fatalf("end: %v", got)
	}
	out.reset()

	// An mtime in the future does not stretch the window either.
	write(now.Add(30*24*time.Hour), now.Add(10*24*time.Hour))
	w = d.maintenance(time.Now())
	if w.Tamper == "" || w.Until.After(time.Now().Add(24*time.Hour+time.Second)) {
		t.Fatalf("future mtime: %+v", w)
	}
	d.announceMaintenance()
	// The daemon remembers when it first saw this file: a day later the
	// window is over even though now+24h keeps moving.
	var saved maintenanceWindow
	if err := jsonGet(st, &saved); err != nil {
		t.Fatal(err)
	}
	if w := d.maintenance(time.Unix(saved.Seen, 0).Add(25 * time.Hour)); w.active(time.Unix(saved.Seen, 0).Add(25 * time.Hour)) {
		t.Fatalf("future-mtime window never ends: %+v", w)
	}

	// Closed with `kodeblue maintenance off`.
	out.reset()
	_ = os.Remove(path)
	d.announceMaintenance()
	if got := out.titles(); len(got) != 1 || got[0] != "Maintenance window ended" {
		t.Fatalf("close: %v", got)
	}
}

func hasAction(js []store.JournalEntry, action string) bool {
	for _, j := range js {
		if j.Action == action {
			return true
		}
	}
	return false
}

func jsonGet(st *store.Store, v *maintenanceWindow) error {
	return json.Unmarshal([]byte(st.Get(maintenanceKey)), v)
}

func TestQueuedNotifiedIsBounded(t *testing.T) {
	d, st, _, out := newTestDaemon(t)
	d.claimGrace = 0
	var ids []int64
	for i := 0; i < 30; i++ {
		f := &store.Finding{Fingerprint: fmt.Sprint(i), Collector: "c", Rule: "r", Severity: detect.SevHigh, Title: fmt.Sprint("f", i)}
		_ = st.AddFinding(f)
		ids = append(ids, f.ID)
	}
	d.triageOnce(context.Background()) // no model: notify once each
	d.triageOnce(context.Background())
	if n := len(out.titles()); n != 30 {
		t.Fatalf("notified %d times, want 30", n)
	}
	for _, id := range ids[:25] {
		_ = st.SetFindingStatus(id, "closed", "", "", 0)
	}
	d.triageOnce(context.Background())
	if len(d.queuedNotified) != 5 {
		t.Fatalf("queuedNotified kept %d entries, want 5", len(d.queuedNotified))
	}
}

func TestPruneRunsOnSchedule(t *testing.T) {
	d, st, _, _ := newTestDaemon(t)
	st.Journal("x", "y", "z")
	d.cfg.Schedule.RetentionDays = -1
	d.prune()
	if st.Get("pruned_at") != "" {
		t.Fatal("pruning disabled but it ran")
	}
	d.cfg.Schedule.RetentionDays = 0
	d.prune()
	first := st.Get("pruned_at")
	if first == "" {
		t.Fatal("prune did not run")
	}
	d.prune() // within six hours: skipped
	if st.Get("pruned_at") != first {
		t.Fatal("prune ran twice within its interval")
	}
}

// A relearn cancelled by shutdown returned from Run without waiting for the
// goroutines it started. Run now always stops them before it returns.
func TestRunWaitsForGoroutinesWhenRelearnIsCancelled(t *testing.T) {
	d, st, _, _ := newTestDaemon(t)
	_ = st.Set("learned_at", time.Now().UTC().Format(time.RFC3339))
	d.cfg.Schedule.LearningSweeps = 3
	d.cfg.Schedule.LearningMinutes = 60 // 20 min between learning sweeps
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // a failed wait must not leave Run running for the cleanup
	var exited atomic.Bool
	d.wg.Add(1)
	go func() { // stands in for a slow investigation winding down
		defer d.wg.Done()
		<-ctx.Done()
		time.Sleep(200 * time.Millisecond)
		exited.Store(true)
	}()
	ran := make(chan error, 1)
	go func() { ran <- d.Run(ctx) }()
	d.relearnNow <- struct{}{}
	waitFor(t, func() bool { return d.st.Get("learned_at") == "" })
	time.Sleep(100 * time.Millisecond) // inside the learning sweeps' wait
	cancel()
	select {
	case err := <-ran:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return")
	}
	if !exited.Load() {
		t.Fatal("Run returned before its goroutines stopped")
	}
}

// Learning without a model used to end for good: the learner and the
// vulnerability assessment never ran. Detection still starts on the baseline,
// but the learner waits for a model and runs once the engine is up.
func TestLearnerWaitsForModel(t *testing.T) {
	d, st, _, out := newTestDaemon(t)
	d.cfg.Schedule.LearningSweeps = 1
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := d.learn(ctx); err != nil {
		t.Fatal(err)
	}
	if st.Get("learned_at") == "" || st.Get(store.LearnerPendingKey) == "" {
		t.Fatalf("learned_at %q, learner_pending %q: want both set", st.Get("learned_at"), st.Get(store.LearnerPendingKey))
	}
	out.mu.Lock()
	body := out.msgs[len(out.msgs)-1].Body
	out.mu.Unlock()
	if !strings.Contains(body, "wait for a model") {
		t.Fatalf("learning message does not say the learner waits: %q", body)
	}
	d.learnWhenModelReady(ctx) // no models configured: nothing to wait for
	if d.learnWaiting.Load() {
		t.Fatal("waiting for an engine without models")
	}

	// Models are set (a restart applies them) and the engine comes up late.
	d.modelsOn = true
	d.engCheckEvery = 10 * time.Millisecond
	d.learnWhenModelReady(ctx)
	time.Sleep(50 * time.Millisecond)
	if st.Get(store.LearnerPendingKey) == "" {
		t.Fatal("learner pending cleared without an engine")
	}
	eng := &engines{runFor: time.Millisecond}
	d.newEngine = eng.factory
	if err := d.startEngine(ctx); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return st.Get(store.LearnerPendingKey) == "" && !d.learnWaiting.Load() })
	var titles []string
	for _, in := range st.Incidents(`WHERE kind=?`, "learning") {
		titles = append(titles, in.Title)
	}
	slices.Sort(titles)
	if !slices.Equal(titles, []string{"Learning run", "Vulnerability assessment"}) {
		t.Fatalf("learning cases %v, want the learner and the assessment", titles)
	}
	if d.learning.Load() {
		t.Fatal("learning flag left set")
	}
}

// A pending learner that fails (its engine went away, it would not start)
// used to clear the waiting state and announce success. It now stays
// pending and is retried until a run works.
func TestPendingLearnerRetriesAfterFailure(t *testing.T) {
	d, st, _, out := newTestDaemon(t)
	_ = st.Set("learned_at", time.Now().UTC().Format(time.RFC3339))
	_ = st.Set(store.LearnerPendingKey, time.Now().UTC().Format(time.RFC3339))
	d.modelsOn = true
	d.engCheckEvery, d.learnRetry = 10*time.Millisecond, 50*time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	broken := &fakeEngine{id: 1}
	broken.stopped.Store(true) // StartSession fails: "connection refused"
	d.setEngine(broken)
	d.learnWhenModelReady(ctx)
	waitFor(t, func() bool { return len(st.Incidents(`WHERE kind=?`, "learning")) >= 1 })
	if st.Get(store.LearnerPendingKey) == "" {
		t.Fatal("a learner that failed to start cleared the waiting state")
	}
	for _, title := range out.titles() {
		if strings.Contains(title, "has learned") {
			t.Fatalf("announced success after a failed run: %q", title)
		}
	}
	d.setEngine(&fakeEngine{id: 2, runFor: time.Millisecond}) // a working engine
	waitFor(t, func() bool { return st.Get(store.LearnerPendingKey) == "" && !d.learnWaiting.Load() })
	if !slices.Contains(out.titles(), "kodeblue has learned this server") {
		t.Fatalf("no success message after the retry: %v", out.titles())
	}
}

// The assessment after a learner used to run once: when the provider's
// spending limit stopped it, the server never had one. It now stays pending
// and runs again, after the limit resets when the provider said when.
func TestFailedAssessmentIsRetriedAfterTheLimitResets(t *testing.T) {
	d, st, _, _ := newTestDaemon(t)
	_ = st.Set("learned_at", time.Now().UTC().Format(time.RFC3339))
	_ = st.Set(store.LearnerPendingKey, time.Now().UTC().Format(time.RFC3339))
	d.modelsOn = true
	d.engCheckEvery, d.learnRetry = 10*time.Millisecond, 20*time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	eng := &fakeEngine{id: 1, runFor: time.Millisecond, script: make(chan runtime.Outcome, 4)}
	eng.alive.Store(true)
	resets := time.Now().Add(400 * time.Millisecond)
	eng.script <- runtime.Outcome{Status: "completed", Text: "profile"} // the learner
	eng.script <- runtime.Outcome{Status: "failed", Error: "The API key's spending limit at the model provider is reached. (HTTP 403)", ErrorClass: "spend_limit", ResetsAt: resets}
	d.setEngine(eng)
	d.learnWhenModelReady(ctx)
	waitFor(t, func() bool { return st.Get(store.LearnerPendingKey) == "" })
	if st.Get(store.AssessmentPendingKey) == "" {
		t.Fatal("a failed assessment was not kept pending")
	}
	failed := st.Incidents(`WHERE kind=? AND title=?`, "learning", "Vulnerability assessment")
	if len(failed) != 1 || !strings.Contains(failed[0].Summary, "spending limit") {
		t.Fatalf("assessment case: %+v", failed)
	}
	// The retry waits for the reset (a minute past it), not learnRetry.
	time.Sleep(200 * time.Millisecond)
	if n := len(st.Incidents(`WHERE kind=? AND title=?`, "learning", "Vulnerability assessment")); n != 1 {
		t.Fatalf("retried before the limit reset: %d runs", n)
	}
	if !d.limitResetsAt().Equal(resets) {
		t.Fatalf("reset time %v", d.limitResetsAt())
	}
	// Past the reset, a run is tried again and clears it (shortened here).
	d.limitReset.Store(time.Time{})
	cancel()
	waitFor(t, func() bool { return !d.learnWaiting.Load() })
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	d.learnWhenModelReady(ctx)
	waitFor(t, func() bool { return st.Get(store.AssessmentPendingKey) == "" && !d.learnWaiting.Load() })
	if n := len(st.Incidents(`WHERE kind=? AND title=?`, "learning", "Vulnerability assessment")); n != 2 {
		t.Fatalf("assessment runs: %d", n)
	}
	if n := len(st.Incidents(`WHERE kind=? AND title=?`, "learning", "Learning run")); n != 1 {
		t.Fatalf("the learner ran again: %d", n)
	}
}

// A learner the hub asks for does the pending learning run too.
func TestHubLearnClearsPendingLearner(t *testing.T) {
	d, st, _, _ := newTestDaemon(t)
	_ = st.Set("learned_at", time.Now().UTC().Format(time.RFC3339))
	_ = st.Set(store.LearnerPendingKey, time.Now().UTC().Format(time.RFC3339))
	d.modelsOn = true
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	eng := &engines{runFor: time.Millisecond}
	d.newEngine = eng.factory
	if err := d.startEngine(ctx); err != nil {
		t.Fatal(err)
	}
	if r := d.Learn(ctx, hubproto.OperatorMessage{Command: hubproto.CommandLearn, Author: "ram"}); r.Status != "done" {
		t.Fatalf("learn: %+v", r)
	}
	waitFor(t, func() bool { return st.Get(store.LearnerPendingKey) == "" && !d.learning.Load() })
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second) // generous: CI and busy hosts run -race slowly
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The triage worker must not take a finding the sweep loop has recorded but
// not routed yet (a low would go to the model instead of the digest, a high
// would miss its live incident). It takes routed ones at once and leftovers
// after claimGrace.
func TestTriageClaimsOnlyRoutedFindings(t *testing.T) {
	d, st, _, _ := newTestDaemon(t)
	url, calls, release := slowModel(t)
	release() // answer at once (with an error: escalation is the fail-safe)
	d.tri = &triage.Triager{Client: llm.New(url, "k"), Model: "m", Store: st, Env: d.env}
	add := func(sev string) *store.Finding {
		f := &store.Finding{Fingerprint: fmt.Sprint(time.Now().UnixNano()), Collector: "c", Rule: "r", Severity: sev, Title: sev}
		if err := st.AddFinding(f); err != nil {
			t.Fatal(err)
		}
		return f
	}
	low, high := add(detect.SevLow), add(detect.SevHigh)
	d.triageOnce(context.Background()) // recorded, not routed: hands off
	if calls.Load() != 0 || st.GetFinding(low.ID).Status != "new" || st.GetFinding(high.ID).Status != "new" {
		t.Fatalf("worker took unrouted findings (calls %d)", calls.Load())
	}
	d.handleFindings(context.Background(), []*store.Finding{low, high})
	if st.GetFinding(low.ID).Status != "digest" {
		t.Fatalf("low not routed to the digest: %s", st.GetFinding(low.ID).Status)
	}
	d.triageOnce(context.Background()) // the routed high is released to triage
	if calls.Load() == 0 || st.GetFinding(high.ID).Status == "new" {
		t.Fatalf("released high not triaged (calls %d, status %s)", calls.Load(), st.GetFinding(high.ID).Status)
	}
	if len(d.released) != 0 {
		t.Fatalf("released set not emptied: %v", d.released)
	}
	// A finding the worker already holds is not routed again by the loop.
	h2 := add(detect.SevHigh)
	_ = st.SetFindingStatus(h2.ID, "triaging", "", "", 0)
	if got := d.unclaimed([]*store.Finding{h2}); len(got) != 0 {
		t.Fatal("sweep loop would route a finding triage holds")
	}
	// Leftovers (older than the grace) are taken without being routed.
	d.claimGrace = 0
	h3 := add(detect.SevMedium)
	d.triageOnce(context.Background())
	if st.GetFinding(h3.ID).Status == "new" {
		t.Fatal("leftover finding never triaged")
	}
}

// Criticals left "new" (a stop between recording and routing, a monitor
// finding dropped on shutdown) used to stay there forever, and 40 of them
// filled the triage query's window and stopped triage altogether.
func TestStrandedCriticalsAreRouted(t *testing.T) {
	d, st, _, out := newTestDaemon(t)
	_ = st.Set("learned_at", time.Now().UTC().Format(time.RFC3339))
	d.claimGrace = 0
	for i := 0; i < 45; i++ {
		_ = st.AddFinding(&store.Finding{Fingerprint: fmt.Sprint("c", i), Collector: "c", Rule: "r", Severity: detect.SevCritical, Title: "planted key"})
	}
	high := &store.Finding{Fingerprint: "h", Collector: "c", Rule: "r", Severity: detect.SevHigh, Title: "h"}
	_ = st.AddFinding(high)
	d.triageOnce(context.Background()) // no model: the high is queued and announced
	if got := out.titles(); len(got) != 1 || got[0] != "h" {
		t.Fatalf("criticals crowded the triage queue out: %v", got)
	}
	d.resumeQueued(context.Background()) // one call drains more than one query's worth
	if n := len(st.QueuedFindings(true, 100)); n != 0 {
		t.Fatalf("%d criticals still unrouted", n)
	}
	inc := st.Incidents(`WHERE kind='incident'`)
	if len(inc) != 6 { // 45 criticals, 8 per incident
		t.Fatalf("want 6 incidents, got %d", len(inc))
	}
	for _, f := range st.FindingsByStatus("escalated", 100) {
		t.Fatalf("finding %d escalated without an incident", f.ID)
	}
	// Young criticals belong to the sweep loop: not taken.
	d.claimGrace = time.Hour
	young := &store.Finding{Fingerprint: "y", Collector: "c", Rule: "r", Severity: detect.SevCritical, Title: "y"}
	_ = st.AddFinding(young)
	d.resumeQueued(context.Background())
	if st.GetFinding(young.ID).Status != "new" {
		t.Fatal("took a critical the sweep loop has yet to route")
	}
	// At startup there is no sweep loop yet: everything stranded goes.
	d.routeStranded(context.Background(), 0)
	if st.GetFinding(young.ID).Status != "incident" {
		t.Fatalf("startup did not route it: %s", st.GetFinding(young.ID).Status)
	}
}

// The store is as writable by the kodeblue user as the maintenance file.
// Forging the daemon's record must not lengthen a window or silence it, a
// touch must not restart the 24 h, and a restarted daemon announces an open
// window (and its tampering) again.
func TestMaintenanceClampIgnoresForgedState(t *testing.T) {
	d, st, _, out := newTestDaemon(t)
	path := d.cfg.MaintenanceFile()
	now := time.Now()
	content := now.Add(31 * 24 * time.Hour).UTC().Format(time.RFC3339)
	if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
	future := now.Add(30 * 24 * time.Hour)
	_ = os.Chtimes(path, future, future) // an mtime in the future as well
	// The record says the daemon first saw this a month from now, that the
	// window was announced, and that it ends in 31 days.
	forged, _ := json.Marshal(maintenanceWindow{Written: content, ModTime: future.Unix(), Seen: future.Unix(), Until: now.Add(31 * 24 * time.Hour), Tamper: "x", Open: true})
	_ = st.Set(maintenanceKey, string(forged))

	d.announceMaintenance()
	w := d.maintenance(time.Now())
	if w.Until.After(now.Add(24*time.Hour + time.Minute)) {
		t.Fatalf("forged record lengthened the window to %s", w.Until)
	}
	got := strings.Join(out.titles(), "\n")
	if !strings.Contains(got, "not written by kodeblue maintenance") || !strings.Contains(got, "Maintenance window open until") {
		t.Fatalf("forged record silenced the announcements: %v", got)
	}
	if hub := d.Maintenance(); hub != w.Until.UTC().Format(time.RFC3339) {
		t.Fatalf("hub sees %q, want the clamped end", hub)
	}

	// Touching the file a day later does not start a new 24 h.
	d.maintMu.Lock()
	d.maintSeen = d.maintSeen.Add(-25 * time.Hour) // first seen 25 h ago
	d.maintMu.Unlock()
	_ = os.Chtimes(path, time.Now(), time.Now())
	if d.mode() != detect.ModeDetect || d.Maintenance() != "" {
		t.Fatal("touch restarted a forged window")
	}

	// A new process (kodeblue restarted) announces the open window again.
	d2, _, _, _ := newTestDaemon(t)
	d2.st, d2.cfg = st, d.cfg
	out2 := &sent{}
	d2.slack = out2
	_ = os.Chtimes(path, now, now)
	d2.announceMaintenance()
	got = strings.Join(out2.titles(), "\n")
	if !strings.Contains(got, "kodeblue started during it") || !strings.Contains(got, "not written by kodeblue maintenance") {
		t.Fatalf("restart did not re-announce: %v", got)
	}
}

// Findings the daemon raises itself (a stuck sensor, a monitoring gap) are
// routed like a sweep's, so triage takes them at once instead of after the
// leftover grace.
func TestDaemonFindingsAreRouted(t *testing.T) {
	d, st, _, _ := newTestDaemon(t)
	raised := d.reportStuckSensors(map[string]time.Time{"integrity": time.Now().Add(-stuckSensorAfter - time.Second)})
	if len(raised) != 1 {
		t.Fatalf("raised %d stuck findings", len(raised))
	}
	d.handleFindings(context.Background(), raised)
	_ = st.Set("heartbeat", time.Now().Add(-time.Hour).UTC().Format(time.RFC3339))
	d.checkGap(context.Background())
	gap := st.FindingsByStatus("new", 10)
	if len(gap) != 2 {
		t.Fatalf("want the stuck and gap findings queued, got %d", len(gap))
	}
	for _, f := range gap {
		if !d.released[f.ID] {
			t.Fatalf("finding %s not released to triage", f.Rule)
		}
	}
}

// The "now watching" message lists root's learned keys for a human to check,
// and nothing else.
func TestRootKeysNoteListsLearnedRootKeys(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "kb.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if n := rootKeysNote(st); n != "" {
		t.Fatalf("no keys, want no note, got %q", n)
	}
	_ = st.UpsertBaseline([]store.BaselineItem{
		{ID: "ssh_key|root/aaaa1111", Collector: "ssh_key", Key: "root/aaaa1111", Attrs: map[string]string{"comment": "ops@bastion", "file": "/root/.ssh/authorized_keys", "has_options": "false"}},
		{ID: "ssh_key|root/bbbb2222", Collector: "ssh_key", Key: "root/bbbb2222", Attrs: map[string]string{"comment": "", "file": "/root/.ssh/authorized_keys2", "has_options": "true"}},
		{ID: "ssh_key|alice/cccc3333", Collector: "ssh_key", Key: "alice/cccc3333", Attrs: map[string]string{"comment": "alice@laptop"}},
		{ID: "ssh_key|notroot/dddd4444", Collector: "ssh_key", Key: "notroot/dddd4444", Attrs: map[string]string{"comment": "other"}},
	}, "learned")
	n := rootKeysNote(st)
	for _, want := range []string{"root has 2 authorized SSH key(s)", "root/aaaa1111 (ops@bastion) in /root/.ssh/authorized_keys", "root/bbbb2222 with options in /root/.ssh/authorized_keys2"} {
		if !strings.Contains(n, want) {
			t.Errorf("note lacks %q:\n%s", want, n)
		}
	}
	if strings.Contains(n, "alice") || strings.Contains(n, "notroot") {
		t.Errorf("note lists other users' keys:\n%s", n)
	}
}

// New hub settings (say, the model the learner needs) used to wait until the
// whole baseline was collected, so the hub looked stuck for half an hour.
// They now restart the daemon between sweeps, and the baseline resumes.
func TestSettingsRestartBetweenBaselineSweepsAndResume(t *testing.T) {
	d, st, _, _ := newTestDaemon(t)
	d.cfg.Schedule.LearningSweeps = 3
	d.cfg.Schedule.LearningMinutes = 60 // 20 min between sweeps: only a restart ends the wait
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ran := make(chan error, 1)
	go func() { ran <- d.learn(ctx) }()
	waitFor(t, func() bool { done, _, _ := st.BaselineProgress(); return done == 1 })
	d.ApplySettings()
	select {
	case err := <-ran:
		if !errors.Is(err, ErrRestart) {
			t.Fatalf("learn returned %v, want ErrRestart", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("new settings did not restart the daemon during the baseline")
	}
	if done, total, eta := st.BaselineProgress(); done != 1 || total != 3 || eta == "" {
		t.Fatalf("progress after the restart: %d/%d %q", done, total, eta)
	}

	// After the restart the next sweep keeps its interval: 2 of 3 done, the
	// last one 2 minutes ago, so it waits.
	d2, _, _, _ := newTestDaemon(t)
	d2.st = st
	d2.cfg.Schedule.LearningSweeps = 3
	d2.cfg.Schedule.LearningMinutes = 60
	st.SetBaselineProgress(2, 3, time.Now().Add(18*time.Minute))
	ctx2, cancel2 := context.WithCancel(ctx)
	early := make(chan error, 1)
	go func() { early <- d2.learn(ctx2) }()
	select {
	case <-early:
		t.Fatal("the resumed baseline swept before its interval was up")
	case <-time.After(500 * time.Millisecond):
	}
	cancel2()
	<-early

	// The last sweep 25 minutes ago: its interval is up, so it sweeps at once.
	st.SetBaselineProgress(2, 3, time.Now().Add(-5*time.Minute))
	done := make(chan error, 1)
	go func() { done <- d2.learn(ctx) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the resumed baseline waited instead of taking its last sweep")
	}
	if _, total, _ := st.BaselineProgress(); total != 0 || st.Get("learned_at") == "" || st.Get("baseline_at") == "" {
		t.Fatalf("after the baseline: progress total %d, learned_at %q", total, st.Get("learned_at"))
	}

}

// Saved settings restart the daemon only once it has run for restartGap, so
// a hub saving settings every sync cannot keep findings from forming.
func TestSettingsRestartWaitsForGap(t *testing.T) {
	d, _, _, _ := newTestDaemon(t)
	d.restartGap = time.Hour
	d.ApplySettings()
	if d.restartDue() {
		t.Fatal("restart due within the gap")
	}
	d.started = time.Now().Add(-2 * time.Hour)
	if !d.restartDue() {
		t.Fatal("restart not due after the gap")
	}
	d.mu.Lock()
	d.following[7] = true
	d.mu.Unlock()
	if d.restartDue() {
		t.Fatal("restart due while a decision follow-up runs")
	}
}

// A change of the response mode, above all to contain from the hub, is
// announced once; a first start on the server's own mode is not.
func TestAnnounceMode(t *testing.T) {
	d, st, _, out := newTestDaemon(t)
	d.cfg.Response.Mode, d.cfg.RootResponseMode = "recommend", "recommend"
	d.announceMode()
	if n := len(out.titles()); n != 0 {
		t.Fatalf("first start announced: %v", out.titles())
	}
	d.cfg.Response.Mode = "contain"
	d.announceMode()
	d.announceMode()
	got := out.titles()
	if len(got) != 1 || got[0] != "Response mode is now contain" {
		t.Fatalf("announcements: %v", got)
	}
	if st.Get("announced_response_mode") != "contain" {
		t.Fatal("mode not remembered")
	}
}

func (f *fakeEngine) SessionBusy(context.Context, string) (bool, error) { return false, nil }
