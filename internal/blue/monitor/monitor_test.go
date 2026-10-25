package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Problem99-io/kodeblue/internal/blue/sensors"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

// fakeProc writes /proc/<pid> under root the way the sensors read it.
func fakeProc(t *testing.T, root string, pid, ppid int, exe, state string) {
	t.Helper()
	d := filepath.Join(root, "proc", fmt.Sprint(pid))
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(exe, filepath.Join(d, "exe")); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(d, "cmdline"), []byte(exe+"\x00arg"), 0o644)
	_ = os.WriteFile(filepath.Join(d, "comm"), []byte(filepath.Base(exe)), 0o644)
	_ = os.WriteFile(filepath.Join(d, "status"), []byte(fmt.Sprintf("Name:\tx\nState:\t%s (x)\nPPid:\t%d\nUid:\t1000\t1000\t1000\t1000\n", state, ppid)), 0o644)
}

func newRunner(t *testing.T, root string) (*Runner, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "kb.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return NewRunner(st, &sensors.Env{Root: root, State: sensors.NewCursorStore(filepath.Join(t.TempDir(), "cursors.json"))}), st
}

func run(t *testing.T, r *Runner, st *store.Store, s Spec) (bool, string) {
	t.Helper()
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(s)
	_ = st.PutMonitor(s.ID, b, "test")
	return r.eval(context.Background(), s)
}

func TestProcessNoChildren(t *testing.T) {
	root := t.TempDir()
	fakeProc(t, root, 1, 0, "/usr/bin/node", "S")
	r, st := newRunner(t, root)
	spec := Spec{ID: "app-no-children", Description: "d", Rationale: "r", Kind: "process", Severity: "high", ProcessExe: "/usr/bin/node", NoChildren: true, AllowChildren: []string{"/usr/bin/git"}}
	if ok, out := run(t, r, st, spec); !ok {
		t.Fatalf("no children yet, got failure: %s", out)
	}
	fakeProc(t, root, 7, 1, "/usr/bin/git", "S")  // allowed
	fakeProc(t, root, 8, 1, "/usr/bin/node", "Z") // reaped worker
	if ok, out := run(t, r, st, spec); !ok || !strings.Contains(out, "1 live child process(es), all allowed; ignored 1 zombie(s)") {
		t.Fatalf("allowed child and zombie should pass and say what was ignored: ok=%v %s", ok, out)
	}
	// The service re-executing its own interpreter is what code execution
	// through it looks like, so it counts.
	fakeProc(t, root, 9, 1, "/usr/bin/node", "S")
	ok, out := run(t, r, st, spec)
	if ok || !strings.Contains(out, "pid 9") {
		t.Fatalf("node under node should fail, got ok=%v %s", ok, out)
	}
	spec.NoChildren, spec.MaxCount = false, 1
	if ok, out := run(t, r, st, spec); ok || !strings.Contains(out, "at most 1") {
		t.Fatalf("max_count 1 with two nodes should fail, got ok=%v %s", ok, out)
	}
}

func TestSocketsMonitor(t *testing.T) {
	root := t.TempDir()
	fakeProc(t, root, 1, 0, "/usr/bin/node", "S")
	self, _ := os.Executable()
	self, _ = filepath.EvalSymlinks(self)
	fakeProc(t, root, 30, 0, self, "S") // kodeblue as a sidecar in the same namespace
	fd := filepath.Join(root, "proc", "30", "fd")
	_ = os.MkdirAll(fd, 0o755)
	_ = os.Symlink("socket:[105]", filepath.Join(fd, "3"))
	net := filepath.Join(root, "proc", "1", "net")
	_ = os.MkdirAll(net, 0o755)
	head := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	row := func(local, remote, st, inode string) string {
		return fmt.Sprintf("   0: %s %s %s 00000000:00000000 00:00000000 00000000  1000        0 %s 1 0000000000000000 100 0 0 10 0\n", local, remote, st, inode)
	}
	tcp := head +
		row("00000000:0BB8", "00000000:0000", "0A", "100") + // listening on 3000
		row("0200A8C0:0BB8", "0500A8C0:D2F4", "01", "101") + // inbound to 3000 from 192.168.0.5
		row("0100007F:B22B", "00000000:0000", "0A", "105") + // kodeblue's engine API on a random port
		row("0B00007F:A077", "00000000:0000", "0A", "106") // Docker's embedded DNS
	_ = os.WriteFile(filepath.Join(net, "tcp"), []byte(tcp), 0o644)
	r, st := newRunner(t, root)
	spec := Spec{ID: "app-net", Description: "d", Rationale: "r", Kind: "sockets", Severity: "high", ProcessExe: "/usr/bin/node", ListenPorts: []int{3000}, NoOutbound: true, AllowRemotes: []string{"10.0.0.0/8"}}
	if ok, out := run(t, r, st, spec); !ok {
		t.Fatalf("listener and inbound connection should pass: %s", out)
	}
	// An outbound connection to a private address outside allow_remotes, and
	// one still being opened, both count.
	tcp += row("0200A8C0:9C40", "0900A8C0:115C", "01", "102") + // to 192.168.0.9:4444
		row("0200A8C0:9C41", "0100000A:01BB", "02", "103") + // to 10.0.0.1:443, allowed
		row("00000000:1F90", "00000000:0000", "0A", "104") // new listener on 8080
	_ = os.WriteFile(filepath.Join(net, "tcp"), []byte(tcp), 0o644)
	ok, out := run(t, r, st, spec)
	if ok || !strings.Contains(out, "192.168.0.9:4444") || !strings.Contains(out, "tcp/8080") || strings.Contains(out, "10.0.0.1") {
		t.Fatalf("want failure naming 192.168.0.9:4444 and tcp/8080 only, got ok=%v %s", ok, out)
	}
}

func TestFileMonitorDirectory(t *testing.T) {
	root := t.TempDir()
	fakeProc(t, root, 42, 0, "/usr/bin/node", "S")
	// The workload's /tmp, reached through its /proc/<pid>/root.
	app := filepath.Join(root, "proc", "42", "root", "tmp")
	_ = os.MkdirAll(app, 0o777)
	r, st := newRunner(t, root)
	spec := Spec{ID: "app-tmp", Description: "d", Rationale: "r", Kind: "file", Severity: "high", Paths: []string{"/proc/{pid:/usr/bin/node}/root/tmp"}, Fast: true}
	if ok, out := run(t, r, st, spec); !ok {
		t.Fatalf("first run is the baseline: %s", out)
	}
	if ok, out := run(t, r, st, spec); !ok {
		t.Fatalf("nothing changed: %s", out)
	}
	_ = os.WriteFile(filepath.Join(app, "x.js"), []byte("require('child_process')"), 0o644)
	ok, out := run(t, r, st, spec)
	if ok || !strings.Contains(out, "new: x.js") {
		t.Fatalf("want a change naming x.js, got ok=%v %s", ok, out)
	}
	if got := r.FastPaths(); len(got) != 1 || got[0] != "/proc/42/root/tmp" {
		t.Fatalf("fast paths = %v", got)
	}
}

func TestDirectoryMonitorUpgradeIsQuiet(t *testing.T) {
	root := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, "srv", "uploads"), 0o755)
	r, st := newRunner(t, root)
	spec := Spec{ID: "uploads", Description: "d", Rationale: "r", Kind: "file", Severity: "medium", Paths: []string{"/srv/uploads"}}
	// What older versions stored for a directory.
	_ = st.Set("monitor_file:uploads:/srv/uploads", "unreadable")
	if ok, out := run(t, r, st, spec); !ok {
		t.Fatalf("upgrade from the old directory hash must not alert: %s", out)
	}
}

func TestPIDRefMissingProcess(t *testing.T) {
	root := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, "proc"), 0o755)
	r, st := newRunner(t, root)
	spec := Spec{ID: "gone", Description: "d", Rationale: "r", Kind: "file", Severity: "low", Paths: []string{"/proc/{pid:/usr/bin/nope}/root/tmp"}}
	if ok, out := run(t, r, st, spec); ok || !strings.Contains(out, "no running process /usr/bin/nope") {
		t.Fatalf("got ok=%v %s", ok, out)
	}
}

func TestFixedPIDRefused(t *testing.T) {
	bad := Spec{ID: "x-tmp", Description: "d", Rationale: "r", Kind: "file", Severity: "low", Paths: []string{"/proc/4242/root/tmp"}}
	if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "{pid:<exe>}") {
		t.Fatalf("fixed PID: %v", err)
	}
	ok := Spec{ID: "x-tmp", Description: "d", Rationale: "r", Kind: "file", Severity: "low", Paths: []string{"/proc/1/root/tmp"}}
	if err := ok.Validate(); err != nil {
		t.Fatalf("PID 1 is stable: %v", err)
	}
}

func TestNoChildrenIgnoresKodeblue(t *testing.T) {
	root := t.TempDir()
	fakeProc(t, root, 1, 0, "/usr/bin/node", "S")
	// kodeblue sharing the container's PID namespace: its orphan is
	// re-parented to the container's PID 1.
	self, _ := os.Executable()
	if real, err := filepath.EvalSymlinks(self); err == nil {
		self = real
	}
	fakeProc(t, root, 50, 1, self, "S")
	r, st := newRunner(t, root)
	spec := Spec{ID: "app-no-children", Description: "d", Rationale: "r", Kind: "process", Severity: "high", ProcessExe: "/usr/bin/node", NoChildren: true}
	if ok, out := run(t, r, st, spec); !ok {
		t.Fatalf("kodeblue's own process is not the service's child: %s", out)
	}
}

// needsHuman files the finding under an incident left for a human, the way
// an investigation ends with a true positive.
func needsHuman(t *testing.T, st *store.Store, f *store.Finding) *store.Incident {
	t.Helper()
	in := &store.Incident{Title: f.Title, Severity: f.Severity, Status: "needs_human"}
	if err := st.CreateIncident(in); err != nil {
		t.Fatal(err)
	}
	_ = st.SetFindingStatus(f.ID, "closed", "true_positive", "confirmed", in.ID)
	return in
}

func TestConditionMonitorIncident(t *testing.T) {
	var status atomic.Int32
	status.Store(500)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(int(status.Load())) }))
	defer srv.Close()
	r, st := newRunner(t, t.TempDir())
	spec := Spec{ID: "app-up", Description: "the app answers", Rationale: "r", Kind: "http", Severity: "high", ConsecutiveFailures: 1, URL: srv.URL}
	run(t, r, st, spec)
	ctx := context.Background()

	fs := r.RunDue(ctx, true)
	if len(fs) != 1 || !strings.HasPrefix(fs[0].Title, "Monitor failing: ") {
		t.Fatalf("want one failing finding, got %+v", fs)
	}
	in := needsHuman(t, st, fs[0])
	// Still down: the incident waiting for a human covers it.
	if fs := r.RunDue(ctx, true); len(fs) != 0 {
		t.Fatalf("a condition already waiting for a human opened %d new finding(s)", len(fs))
	}
	if f := st.LastFinding("monitor:app-up"); f.ID != fs[0].ID || f.Occurrences < 2 {
		t.Fatalf("want the first finding bumped, got %+v", f)
	}
	// A duplicate older versions opened while the monitor kept failing.
	dup := &store.Finding{Fingerprint: "monitor:app-up", Collector: "monitor", Rule: "monitor.app-up", Severity: "high", Title: "Monitor failed: d", Evidence: map[string]string{"monitor_id": "app-up"}}
	_ = st.AddFinding(dup)
	in2 := needsHuman(t, st, dup)
	status.Store(200)
	r.RunDue(ctx, true)
	for _, id := range []int64{in.ID, in2.ID} {
		if got := st.GetIncident(id); got.Status != "resolved" || !strings.Contains(got.Summary, "app-up passes again") {
			t.Fatalf("incident #%d should be cleared once the monitor passes, got %s %q", id, got.Status, got.Summary)
		}
	}
	// Failing again later is a new problem.
	status.Store(500)
	if fs := r.RunDue(ctx, true); len(fs) != 1 {
		t.Fatalf("want a new finding after the incident cleared, got %d", len(fs))
	}
}

func TestClearKeepsIncidentWithOtherFindings(t *testing.T) {
	var status atomic.Int32
	status.Store(500)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(int(status.Load())) }))
	defer srv.Close()
	r, st := newRunner(t, t.TempDir())
	run(t, r, st, Spec{ID: "app-up", Description: "d", Rationale: "r", Kind: "http", Severity: "high", ConsecutiveFailures: 1, URL: srv.URL})
	fs := r.RunDue(context.Background(), true)
	in := needsHuman(t, st, fs[0])
	key := &store.Finding{Fingerprint: "ssh_key|alice", Collector: "ssh_key", Rule: "ssh_key.added", Severity: "high", Title: "key added"}
	_ = st.AddFinding(key)
	_ = st.SetFindingStatus(key.ID, "closed", "true_positive", "confirmed", in.ID)
	status.Store(200)
	r.RunDue(context.Background(), true)
	if got := st.GetIncident(in.ID); got.Status != "needs_human" {
		t.Fatalf("an incident with a planted key must stay for a human, got %s", got.Status)
	}
}

func TestEventMonitorAlertsEveryTime(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "srv", "drop")
	_ = os.MkdirAll(dir, 0o755)
	r, st := newRunner(t, root)
	run(t, r, st, Spec{ID: "drop", Description: "files dropped", Rationale: "r", Kind: "file", Severity: "high", Paths: []string{"/srv/drop"}})
	ctx := context.Background()
	r.RunDue(ctx, true) // baseline
	_ = os.WriteFile(filepath.Join(dir, "a"), nil, 0o644)
	fs := r.RunDue(ctx, true)
	if len(fs) != 1 || !strings.HasPrefix(fs[0].Title, "Monitor alert: ") {
		t.Fatalf("want one alert, got %+v", fs)
	}
	in := needsHuman(t, st, fs[0])
	r.RunDue(ctx, true) // unchanged: passes, but what it saw still needs a human
	if got := st.GetIncident(in.ID); got.Status != "needs_human" {
		t.Fatalf("a change monitor passing again must not clear its incident, got %s", got.Status)
	}
	_ = os.WriteFile(filepath.Join(dir, "b"), nil, 0o644)
	if fs := r.RunDue(ctx, true); len(fs) != 1 {
		t.Fatalf("a second change is a new alert, got %d", len(fs))
	}
}

func TestLineAt(t *testing.T) {
	out := "/var/tmp\n/var/tmp/.x\n"
	re := regexp.MustCompile(`\.x`)
	if got := lineAt(out, re.FindStringIndex(out)); got != "/var/tmp/.x" {
		t.Fatalf("lineAt = %q", got)
	}
	if got := lineAt("/var/tmp/.x", []int{0, 1}); got != "/var/tmp/.x" {
		t.Fatalf("lineAt without newline = %q", got)
	}
}

func TestConditionReportedOncePerStreak(t *testing.T) {
	var status atomic.Int32
	status.Store(500)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(int(status.Load())) }))
	defer srv.Close()
	r, st := newRunner(t, t.TempDir())
	run(t, r, st, Spec{ID: "app-up", Description: "d", Rationale: "r", Kind: "http", Severity: "critical", ConsecutiveFailures: 1, URL: srv.URL})
	ctx := context.Background()
	fs := r.RunDue(ctx, true)
	if len(fs) != 1 {
		t.Fatalf("want one finding, got %d", len(fs))
	}
	// The investigation calls it harmless and closes it; the check still fails.
	in := &store.Incident{Title: fs[0].Title, Severity: "critical", Status: "resolved"}
	_ = st.CreateIncident(in)
	_ = st.SetFindingStatus(fs[0].ID, "closed", "benign_change", "expected", in.ID)
	for i := 0; i < 3; i++ {
		if fs := r.RunDue(ctx, true); len(fs) != 0 {
			t.Fatalf("check %d: a failure already judged opened a new finding", i)
		}
	}
	// Nor after a restart.
	r = NewRunner(st, &sensors.Env{Root: t.TempDir()})
	if fs := r.RunDue(ctx, true); len(fs) != 0 {
		t.Fatalf("a restart made the same failure look new")
	}
	status.Store(200)
	r.RunDue(ctx, true)
	status.Store(500)
	if fs := r.RunDue(ctx, true); len(fs) != 1 {
		t.Fatalf("failing again after passing is a new report, got %d", len(fs))
	}
}
