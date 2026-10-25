package services

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Problem99-io/kodeblue/internal/blue/monitor"
	"github.com/Problem99-io/kodeblue/internal/blue/sensors"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

var (
	nginx = sensors.Service{Name: "nginx", Unit: "nginx.service", State: sensors.ServiceRunning, Exes: []string{"/usr/sbin/nginx"},
		Listen: []sensors.Port{{Proto: "tcp", Port: 80, Address: "0.0.0.0"}}}
	sshd = sensors.Service{Name: "ssh", Unit: "ssh.service", State: sensors.ServiceRunning, Exes: []string{"/usr/sbin/sshd"},
		Listen: []sensors.Port{{Proto: "tcp", Port: 22, Address: "0.0.0.0"}}}
	journald = sensors.Service{Name: "systemd-journald", Unit: "systemd-journald.service", State: sensors.ServiceRunning, Exes: []string{"/usr/lib/systemd/systemd-journald"}}
	redis    = sensors.Service{Name: "redis-server", Unit: "redis-server.service", State: sensors.ServiceRunning, Exes: []string{"/usr/bin/redis-server"},
		Listen: []sensors.Port{{Proto: "tcp", Port: 6379, Address: "127.0.0.1"}}}
	postgres = sensors.Service{Name: "postgresql", Unit: "postgresql.service", State: sensors.ServiceEnabled, Exes: []string{"/usr/lib/postgresql/16/bin/postgres"}}
	app      = sensors.Service{Name: "container 0123456789ab", Container: "0123456789ab", State: sensors.ServiceRunning, Exes: []string{"/usr/local/bin/node"},
		Root: "/proc/200/root", Net: "/proc/200/net", Listen: []sensors.Port{{Proto: "tcp", Port: 3000, Address: "0.0.0.0"}}}
)

func sensorsOK(names ...string) []sensors.Coverage {
	var out []sensors.Coverage
	for _, n := range names {
		out = append(out, sensors.Coverage{Collector: n, Status: sensors.CoverageOK})
	}
	return out
}

func find(t *testing.T, inv Inventory, name string) Result {
	t.Helper()
	for _, r := range inv.Services {
		if r.Name == name {
			return r
		}
	}
	t.Fatalf("no %s in inventory", name)
	return Result{}
}

func TestAssess(t *testing.T) {
	mons := []monitor.Spec{
		{ID: "nginx-up", Kind: "process", ProcessExe: "/usr/sbin/nginx"},
		{ID: "nginx-exec", Kind: "process", ProcessExe: "/usr/sbin/nginx", NoChildren: true},
		{ID: "host-sockets", Kind: "sockets", ListenPorts: []int{22, 80}},
		{ID: "tmp-drop", Kind: "file", Paths: []string{"/tmp", "/var/tmp"}},
		{ID: "ssh-up", Kind: "port", Port: 22},
		{ID: "app-health", Kind: "http", URL: "http://172.17.0.2:3000/health"},
		{ID: "app-sockets", Kind: "sockets", ProcessExe: "/usr/local/bin/node", NoOutbound: true},
	}
	inv := Assess([]sensors.Service{nginx, sshd, journald, redis, postgres, app}, Context{
		Monitors: mons, Coverage: sensorsOK("process", "auth"), TapDir: "/var/lib/kodeblue/requests", TapPorts: []int{80},
	})

	n := find(t, inv, "nginx")
	// Public and tapped: all five checks, and only the request log is missing.
	if len(n.Checks) != 5 || !slices.Equal(n.Missing, []string{Requests}) {
		t.Fatalf("nginx: %+v", n)
	}
	s := find(t, inv, "ssh")
	if !s.Covered() {
		t.Fatalf("ssh exec is the auth sensor's job: %+v", s)
	}
	if j := find(t, inv, "systemd-journald"); j.Role != "system" || len(j.Checks) != 0 {
		t.Fatalf("journald is OS plumbing: %+v", j)
	}
	if r := find(t, inv, "redis-server"); !slices.Equal(r.Missing, []string{Health}) {
		t.Fatalf("a loopback-only workload needs a health check: %+v", r)
	}
	if p := find(t, inv, "postgresql"); !p.Covered() || p.Checks[0].By[0] != "sensor:process" {
		t.Fatalf("a dormant unit is covered by the process sensor: %+v", p)
	}
	a := find(t, inv, "container 0123456789ab")
	if !slices.Equal(a.Missing, []string{Exec, Files}) {
		t.Fatalf("container: %+v", a)
	}
	// The host's sockets monitor is not the container's network.
	for _, c := range a.Checks {
		if c.Check == Network && !slices.Equal(c.By, []string{"app-sockets"}) {
			t.Fatalf("container network: %+v", c)
		}
	}

	// With the process sensor off, nothing notices a dormant unit starting.
	inv = Assess([]sensors.Service{postgres}, Context{Coverage: sensorsOK("process"), Off: map[string]sensors.DisabledSensor{"process": {}}})
	if !slices.Equal(inv.Services[0].Missing, []string{Start}) {
		t.Fatalf("postgresql with the process sensor off: %+v", inv.Services[0])
	}

	// More monitors close the gaps.
	mons = append(mons,
		monitor.Spec{ID: "nginx-requests", Kind: "log", Path: "/var/lib/kodeblue/requests"},
		monitor.Spec{ID: "app-exec", Kind: "process", ProcessExe: "/usr/local/bin/node", NoChildren: true},
		monitor.Spec{ID: "app-tmp", Kind: "file", Paths: []string{"/proc/{pid:/usr/local/bin/node}/root/tmp"}},
	)
	inv = Assess([]sensors.Service{nginx, app}, Context{Monitors: mons, Coverage: sensorsOK("process"), TapDir: "/var/lib/kodeblue/requests", TapPorts: []int{80}})
	if g := inv.Gaps(); len(g) != 0 {
		t.Fatalf("gaps left: %+v", g)
	}

	inv = Assess(nil, Context{Coverage: []sensors.Coverage{{Collector: "process", Status: sensors.CoverageBlind, Reason: "own PID namespace"}}})
	if inv.Blind == "" {
		t.Fatal("a blind process sensor must be reported")
	}
}

func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "kb.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func openCoverage(st *store.Store) []store.Incident {
	return st.Incidents(`WHERE kind=? AND status<>'resolved' ORDER BY id`, Kind)
}

func TestSyncOpensAndResolvesCases(t *testing.T) {
	st := openStore(t)
	ctx := Context{Coverage: sensorsOK("process", "auth")}
	inv := Assess([]sensors.Service{nginx, journald, redis}, ctx)

	opened, resolved := Sync(st, inv)
	if len(opened) != 2 || len(resolved) != 0 {
		t.Fatalf("opened %d, resolved %d", len(opened), len(resolved))
	}
	cases := openCoverage(st)
	if len(cases) != 2 || cases[0].Title != CaseTitle("nginx") || cases[0].Status != "needs_human" || cases[0].Severity != "medium" {
		t.Fatalf("cases: %+v", cases)
	}
	if cases[1].Title != CaseTitle("redis-server") || cases[1].Severity != "low" {
		t.Fatalf("a loopback service's gap is low: %+v", cases[1])
	}
	if !strings.Contains(cases[0].Report, "**exec: missing**") {
		t.Fatalf("report must name the missing checks:\n%s", cases[0].Report)
	}

	// A second pass does not pile up cases.
	if opened, _ := Sync(st, inv); len(opened) != 0 || len(openCoverage(st)) != 2 {
		t.Fatalf("second sync opened %d", len(opened))
	}

	// Monitors for redis: its case resolves by itself.
	ctx.Monitors = []monitor.Spec{{ID: "redis-up", Kind: "port", Port: 6379}}
	_, resolved = Sync(st, Assess([]sensors.Service{nginx, journald, redis}, ctx))
	if len(resolved) != 1 || resolved[0].Title != CaseTitle("redis-server") || resolved[0].Verdict != "covered" {
		t.Fatalf("resolved: %+v", resolved)
	}
	if got := openCoverage(st); len(got) != 1 || got[0].Title != CaseTitle("nginx") {
		t.Fatalf("still open: %+v", got)
	}
}

func TestAgentCaseKeepsItsExplanation(t *testing.T) {
	st := openStore(t)
	ctx := Context{Coverage: sensorsOK("process")}
	inv := Assess([]sensors.Service{app}, ctx)
	r := inv.Services[0]

	in, created, err := OpenCase(st, Gap{Service: r.Name, Severity: "high", Summary: "kodeblue cannot see into the container's processes.",
		Notes: "no_children on node failed: the container's PID namespace is separate.", Checks: []string{Exec, "access-log"}, Result: &r, By: "agent"})
	if err != nil || !created {
		t.Fatal(created, err)
	}

	// kodeblue's own pass updates the case instead of opening another, and
	// keeps the agent's summary and the checks it named.
	if opened, _ := Sync(st, inv); len(opened) != 0 {
		t.Fatalf("opened a second case: %+v", opened)
	}
	got := st.GetIncident(in.ID)
	if got.Summary != "kodeblue cannot see into the container's processes." || got.Severity != "high" || !strings.Contains(got.Report, "PID namespace is separate") {
		t.Fatalf("agent's explanation lost: %+v", got)
	}
	var m caseMeta
	_ = json.Unmarshal([]byte(st.Get(metaKey(in.ID))), &m)
	if !slices.Contains(m.Checks, "access-log") || !slices.Contains(m.Checks, Files) {
		t.Fatalf("checks: %v", m.Checks)
	}

	// Every check kodeblue knows is covered now, but the agent named one it
	// cannot verify: the case stays for a human.
	ctx.Monitors = []monitor.Spec{
		{ID: "app-up", Kind: "process", ProcessExe: "/usr/local/bin/node"},
		{ID: "app-exec", Kind: "process", ProcessExe: "/usr/local/bin/node", NoChildren: true},
		{ID: "app-sockets", Kind: "sockets", ProcessExe: "/usr/local/bin/node", NoOutbound: true},
		{ID: "app-tmp", Kind: "file", Paths: []string{"/proc/{pid:/usr/local/bin/node}/root/tmp"}},
	}
	if _, resolved := Sync(st, Assess([]sensors.Service{app}, ctx)); len(resolved) != 0 {
		t.Fatalf("resolved a case about a check kodeblue cannot verify: %+v", resolved)
	}
}

func TestSyncBlind(t *testing.T) {
	st := openStore(t)
	inv := Assess(nil, Context{Coverage: []sensors.Coverage{{Collector: "process", Status: sensors.CoverageBlind, Reason: "own PID namespace"}}})
	opened, _ := Sync(st, inv)
	if len(opened) != 1 || opened[0].Severity != "high" {
		t.Fatalf("blind: %+v", opened)
	}
}

func TestURLPort(t *testing.T) {
	for u, want := range map[string]int{"http://127.0.0.1:8080/x": 8080, "https://localhost/health": 443, "http://10.0.0.2": 80, "http://[::1]:9000/": 9000} {
		if got := urlPort(u); got != want {
			t.Errorf("urlPort(%q) = %d, want %d", u, got, want)
		}
	}
}
