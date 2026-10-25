package monitor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/sensors"
)

func appendLine(t *testing.T, path, line string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(line + "\n")
	f.Close()
}

// A log monitor on a directory follows the newest file, including the first
// lines of a file the log rotated into.
func TestLogMonitorFollowsRotation(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "app", "logs")
	_ = os.MkdirAll(dir, 0o755)
	day1 := filepath.Join(dir, "access.log.2026-10-21")
	appendLine(t, day1, `10.0.0.1 - - "GET / HTTP/1.1" 200`)
	r, st := newRunner(t, root)
	spec := Spec{ID: "app-errors", Description: "d", Rationale: "r", Kind: "log", Severity: "high", Path: "/app/logs", Pattern: `" 500 `, Threshold: 2}
	if ok, out := run(t, r, st, spec); !ok || !strings.Contains(out, "access.log.2026-10-21") {
		t.Fatalf("first run: ok=%v %s", ok, out)
	}
	appendLine(t, day1, `10.0.0.1 - - "GET /a HTTP/1.1" 500 `)
	if ok, out := run(t, r, st, spec); !ok {
		t.Fatalf("one error is under the threshold: %s", out)
	}
	day2 := filepath.Join(dir, "access.log.2026-10-22")
	appendLine(t, day2, `10.0.0.1 - - "GET /b HTTP/1.1" 500 `)
	future := time.Now().Add(time.Minute)
	_ = os.Chtimes(day2, future, future)
	ok, out := run(t, r, st, spec)
	if ok || !strings.Contains(out, "access.log.2026-10-22") {
		t.Fatalf("the error in the new file must count: ok=%v %s", ok, out)
	}
}

func TestLogMonitorCountsPerClient(t *testing.T) {
	root := t.TempDir()
	log := filepath.Join(root, "access.log")
	appendLine(t, log, "start")
	r, st := newRunner(t, root)
	spec := Spec{ID: "app-4xx", Description: "d", Rationale: "r", Kind: "log", Severity: "high", Path: "/access.log", Pattern: `" 40[0-9] `, GroupBy: `^(\S+)`, Threshold: 3, WindowSeconds: 600}
	run(t, r, st, spec)
	// Six errors spread over six clients: no single client is over 3.
	for _, ip := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6"} {
		appendLine(t, log, ip+` - - "GET /x HTTP/1.1" 404 `)
	}
	if ok, out := run(t, r, st, spec); !ok {
		t.Fatalf("spread errors should pass: %s", out)
	}
	for i := 0; i < 3; i++ {
		appendLine(t, log, `172.30.0.3 - - "GET /api/Users HTTP/1.1" 401 `)
	}
	ok, out := run(t, r, st, spec)
	if ok || !strings.Contains(out, "172.30.0.3: 3 matches") || strings.Contains(out, "10.0.0.1") {
		t.Fatalf("want 172.30.0.3 named alone: ok=%v %s", ok, out)
	}
}

func TestLogMonitorNewValues(t *testing.T) {
	root := t.TempDir()
	log := filepath.Join(root, "access.log")
	appendLine(t, log, `10.0.0.1 - - "POST /login HTTP/1.1" 200 "curl"`)
	r, st := newRunner(t, root)
	spec := Spec{ID: "app-logins", Description: "d", Rationale: "r", Kind: "log", Severity: "high", Path: "/access.log", Pattern: `"POST /login[^"]*" 200 `, GroupBy: `^(\S+)`, NewValues: true}
	if ok, out := run(t, r, st, spec); !ok || !strings.Contains(out, "1 known") {
		t.Fatalf("the client already in the log is known: ok=%v %s", ok, out)
	}
	appendLine(t, log, `10.0.0.1 - - "POST /login HTTP/1.1" 200 "curl"`)
	appendLine(t, log, `172.30.0.3 - - "POST /login HTTP/1.1" 401 "curl"`) // failed: not a match
	if ok, out := run(t, r, st, spec); !ok {
		t.Fatalf("known client and a failed login: %s", out)
	}
	appendLine(t, log, `172.30.0.3 - - "POST /login HTTP/1.1" 200 "curl"`)
	ok, out := run(t, r, st, spec)
	if ok || !strings.Contains(out, "first time seen") || !strings.Contains(out, "172.30.0.3") {
		t.Fatalf("new client logging in: ok=%v %s", ok, out)
	}
	appendLine(t, log, `172.30.0.3 - - "POST /login HTTP/1.1" 200 "curl"`)
	if ok, out := run(t, r, st, spec); !ok {
		t.Fatalf("reported once: %s", out)
	}
}

func TestLogSpecValidation(t *testing.T) {
	bad := []Spec{
		{GroupBy: `\S+`},                 // no capture group
		{NewValues: true},                // new_values without group_by
		{Pattern: `(`, Threshold: 1},     // bad regex
		{FilePattern: `[`, Threshold: 1}, // bad file regex
	}
	for i, s := range bad {
		s.ID, s.Description, s.Rationale, s.Kind, s.Severity, s.Path = "x-log", "d", "r", "log", "high", "/var/log/app"
		if s.Pattern == "" {
			s.Pattern = "x"
		}
		if s.Threshold == 0 && !s.NewValues {
			s.Threshold = 1
		}
		if err := s.Validate(); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
}

// A file monitor on a log directory shows what was appended.
func TestFileMonitorShowsAppendedLines(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "logs")
	_ = os.MkdirAll(dir, 0o755)
	appendLine(t, filepath.Join(dir, "access.log"), "old line")
	r, st := newRunner(t, root)
	spec := Spec{ID: "logs-dir", Description: "d", Rationale: "r", Kind: "file", Severity: "medium", Paths: []string{"/logs"}}
	run(t, r, st, spec)
	appendLine(t, filepath.Join(dir, "access.log"), `172.30.0.3 "POST /b2b/v2/orders HTTP/1.1" 200`)
	ok, out := run(t, r, st, spec)
	if ok || !strings.Contains(out, "appended to access.log") || !strings.Contains(out, "/b2b/v2/orders") || strings.Contains(out, "old line") {
		t.Fatalf("want only the appended line: ok=%v %s", ok, out)
	}
}

// The backtest reports what a pattern finds in the log already written, per
// group, without touching the real monitor's file record.
func TestLogBacktest(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "logs")
	_ = os.MkdirAll(dir, 0o755)
	log := filepath.Join(dir, "access.log")
	for i := 0; i < 4; i++ {
		appendLine(t, log, `10.0.0.1 - - "GET /x HTTP/1.1" 404 `)
	}
	appendLine(t, log, `10.0.0.2 - - "GET /y HTTP/1.1" 404 `)
	appendLine(t, log, `10.0.0.2 - - "GET / HTTP/1.1" 200 `)
	r, st := newRunner(t, root)
	spec := Spec{ID: "app-404", Kind: "log", Path: "/logs", Pattern: `" 404 `, GroupBy: `^(\S+)`, Threshold: 3}
	out := r.LogBacktest(spec)
	for _, want := range []string{"last 6 lines", "5 matching", "2 distinct values", "10.0.0.1=4", "10.0.0.2=1", "10.0.0.1 reaches the threshold of 3"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in %s", want, out)
		}
	}
	if v := st.Get("monitor_logfile:app-404"); v != "" {
		t.Fatalf("backtest recorded the real monitor's file: %q", v)
	}
}

// Monitors on the same log each read every new line: a shared cursor would
// hand the lines to whichever monitor ran first.
func TestLogMonitorsShareAFile(t *testing.T) {
	root := t.TempDir()
	log := filepath.Join(root, "access.log")
	appendLine(t, log, "start")
	r, st := newRunner(t, root)
	errs := Spec{ID: "app-errors", Description: "d", Rationale: "r", Kind: "log", Severity: "high", Path: "/access.log", Pattern: `" 404 `, Threshold: 1}
	trav := Spec{ID: "app-traversal", Description: "d", Rationale: "r", Kind: "log", Severity: "high", Path: "/access.log", Pattern: `\.\./`, Threshold: 1}
	run(t, r, st, errs)
	run(t, r, st, trav)
	appendLine(t, log, `10.0.0.9 - - "GET /../../etc/passwd HTTP/1.1" 404 `)
	if ok, out := run(t, r, st, errs); ok {
		t.Fatalf("first monitor missed the line: %s", out)
	}
	if ok, out := run(t, r, st, trav); ok {
		t.Fatalf("second monitor missed the line: %s", out)
	}
}

// known_values replaces the log as the known population, so a client that
// was already in the log when learning ran still alerts.
func TestLogMonitorKnownValues(t *testing.T) {
	root := t.TempDir()
	log := filepath.Join(root, "access.log")
	appendLine(t, log, `10.0.0.1 - - "POST /login HTTP/1.1" 200 "x"`)
	appendLine(t, log, `10.0.0.7 - - "POST /login HTTP/1.1" 200 "x"`)
	r, st := newRunner(t, root)
	known := []string{"10.0.0.1"}
	spec := Spec{ID: "app-logins", Description: "d", Rationale: "r", Kind: "log", Severity: "high", Path: "/access.log", Pattern: `"POST /login[^"]*" 200 `, GroupBy: `^(\S+)`, NewValues: true, KnownValues: &known}
	if out := r.LogBacktest(spec); !strings.Contains(out, "not in known_values, so they alert on their next matching line: 10.0.0.7") {
		t.Fatalf("backtest should name 10.0.0.7: %s", out)
	}
	if ok, out := run(t, r, st, spec); !ok || !strings.Contains(out, "1 known") {
		t.Fatalf("only known_values are known: ok=%v %s", ok, out)
	}
	appendLine(t, log, `10.0.0.7 - - "POST /login HTTP/1.1" 200 "x"`)
	if ok, out := run(t, r, st, spec); ok || !strings.Contains(out, "10.0.0.7") {
		t.Fatalf("10.0.0.7 was in the log but not known: ok=%v %s", ok, out)
	}
	bad := spec
	bad.NewValues = false
	if err := bad.Validate(); err == nil {
		t.Fatal("known_values without new_values must be refused")
	}
}

// A log monitor never reads a secret: its matching lines reach findings and
// monitor_test's output. A secret path is refused when the monitor is
// created, and the file it resolves to (the newest file of a directory, a
// symlink) is refused at every read.
func TestLogMonitorRefusesSecrets(t *testing.T) {
	spec := Spec{ID: "x", Description: "d", Rationale: "r", Kind: "log", Severity: "low", Path: "/etc/shadow", Pattern: ":", Threshold: 1}
	if err := spec.Validate(); err == nil {
		t.Fatal("log monitor on /etc/shadow accepted")
	}

	root := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, "etc"), 0o755)
	_ = os.MkdirAll(filepath.Join(root, "app", "logs"), 0o755)
	appendLine(t, filepath.Join(root, "etc", "shadow"), "root:$6$SALT$SECRETHASH:20000:0:99999:7:::")
	_ = os.Symlink("../../etc/shadow", filepath.Join(root, "app", "logs", "current"))
	r, st := newRunner(t, root)
	for _, s := range []Spec{
		{ID: "dir", Description: "d", Rationale: "r", Kind: "log", Severity: "low", Path: "/etc", FilePattern: "^shadow$", Pattern: ":", Threshold: 1},
		{ID: "link", Description: "d", Rationale: "r", Kind: "log", Severity: "low", Path: "/app/logs/current", Pattern: ":", Threshold: 1},
	} {
		if err := s.Validate(); err != nil {
			t.Fatalf("%s: %v", s.ID, err)
		}
		if _, out := run(t, r, st, s); strings.Contains(out, "SECRETHASH") {
			t.Errorf("%s: monitor output leaked the secret: %s", s.ID, out)
		}
		if out := r.LogBacktest(s); strings.Contains(out, "SECRETHASH") || !strings.Contains(out, "secret path") {
			t.Errorf("%s: backtest: %s", s.ID, out)
		}
	}
}

// What a monitor reads from the host gets host_exec's redaction before it
// reaches a finding or monitor_test: here a credential in an app log.
func TestLogMonitorOutputIsRedacted(t *testing.T) {
	root := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, "app"), 0o755)
	log := filepath.Join(root, "app", "app.log")
	appendLine(t, log, "boot")
	r, st := newRunner(t, root)
	spec := Spec{ID: "errs", Description: "d", Rationale: "r", Kind: "log", Severity: "low", Path: "/app/app.log", Pattern: "ERROR", Threshold: 1}
	run(t, r, st, spec)
	appendLine(t, log, "ERROR connecting with DB_PASSWORD=hunter2-monitor")
	if _, out := run(t, r, st, spec); strings.Contains(out, "hunter2-monitor") || !strings.Contains(out, "DB_PASSWORD") {
		t.Fatalf("finding output not redacted: %s", out)
	}
	if out := r.LogBacktest(spec); strings.Contains(out, "hunter2-monitor") {
		t.Fatalf("backtest not redacted: %s", out)
	}
}

// monitor_test backtests with a runner that has no store: a log monitor on a
// directory must pick its newest file without one (it panicked).
func TestLogBacktestWithoutStore(t *testing.T) {
	root := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, "app", "logs"), 0o755)
	appendLine(t, filepath.Join(root, "app", "logs", "access.log"), `10.0.0.1 - - "GET /x HTTP/1.1" 500 `)
	r := NewRunner(nil, &sensors.Env{Root: root})
	spec := Spec{ID: "e", Description: "d", Rationale: "r", Kind: "log", Severity: "low", Path: "/app/logs", Pattern: `" 500 `, Threshold: 1}
	if out := r.LogBacktest(spec); !strings.Contains(out, "1 matching") {
		t.Fatalf("backtest: %s", out)
	}
}
