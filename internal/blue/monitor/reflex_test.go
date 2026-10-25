package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

// reflexRun saves spec, runs the due monitors once and returns what the
// reflex hook was handed.
func reflexRun(t *testing.T, r *Runner, st *store.Store, s Spec) ([]Reflex, []*store.Finding) {
	t.Helper()
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(s)
	_ = st.PutMonitor(s.ID, b, "test")
	var got []Reflex
	r.OnReflex(func(_ Spec, _ *store.Finding, rx []Reflex) string {
		got = append(got, rx...)
		return fmt.Sprintf("handled %d", len(rx))
	})
	return got, r.RunDue(context.Background(), false)
}

func pids(rx []Reflex) string {
	var out []string
	for _, x := range rx {
		out = append(out, x.Action+":"+x.Params["pid"]+x.Params["path"])
	}
	return strings.Join(out, ",")
}

func TestContainKillsUnexpectedChildren(t *testing.T) {
	root := t.TempDir()
	fakeProc(t, root, 1, 0, "/usr/bin/node", "S")
	r, st := newRunner(t, root)
	spec := Spec{ID: "app-rce", Description: "d", Rationale: "r", Kind: "process", Severity: "high", ProcessExe: "/usr/bin/node", NoChildren: true, ConsecutiveFailures: 1, IntervalSeconds: 3600, Contain: true}
	if rx, f := reflexRun(t, r, st, spec); len(rx) != 0 || len(f) != 0 {
		t.Fatalf("clean service: reflexes %v findings %d", pids(rx), len(f))
	}
	fakeProc(t, root, 9, 1, "/bin/sh", "S")
	fakeProc(t, root, 10, 9, "/usr/bin/nc", "S")
	// Even with a long interval a contain monitor runs on every tick.
	rx, f := reflexRun(t, r, st, spec)
	if pids(rx) != "kill_process:10,kill_process:9" {
		t.Fatalf("want the grandchild then the child killed, got %s", pids(rx))
	}
	if rx[1].Params["expect_exe"] != "/bin/sh" || rx[1].Params["incident_linked"] != "true" {
		t.Fatalf("params = %v", rx[1].Params)
	}
	if len(f) != 1 || f[0].Evidence["contained"] != "handled 2" {
		t.Fatalf("the finding should say what was contained: %+v", f)
	}
	// Still failing: the same targets are not handed over again.
	if rx, _ := reflexRun(t, r, st, spec); len(rx) != 0 {
		t.Fatalf("repeated reflex: %s", pids(rx))
	}
	// Without contain the monitor only reports.
	fakeProc(t, root, 11, 1, "/bin/sh", "S")
	spec.Contain = false
	if rx, _ := reflexRun(t, r, st, spec); len(rx) != 0 {
		t.Fatalf("contain off still acted: %s", pids(rx))
	}
}

func TestContainSocketsSparesTheService(t *testing.T) {
	root := t.TempDir()
	fakeProc(t, root, 1, 0, "/usr/bin/node", "S")
	fakeProc(t, root, 20, 1, "/usr/bin/node", "S")
	self, _ := os.Executable()
	self, _ = filepath.EvalSymlinks(self)
	fakeProc(t, root, 30, 0, self, "S") // kodeblue as a sidecar in the same namespace
	net := filepath.Join(root, "proc", "1", "net")
	_ = os.MkdirAll(net, 0o755)
	for pid, inode := range map[int]string{1: "102", 20: "103", 30: "104"} {
		fd := filepath.Join(root, "proc", fmt.Sprint(pid), "fd")
		_ = os.MkdirAll(fd, 0o755)
		_ = os.Symlink("socket:["+inode+"]", filepath.Join(fd, "3"))
	}
	row := func(local, remote, st, inode string) string {
		return fmt.Sprintf("   0: %s %s %s 00000000:00000000 00:00000000 00000000  1000        0 %s 1 0000000000000000 100 0 0 10 0\n", local, remote, st, inode)
	}
	tcp := "  sl  local_address rem_address   st\n" +
		row("0200A8C0:9C40", "0900A8C0:115C", "01", "102") + // the service itself to 192.168.0.9:4444
		row("0200A8C0:9C41", "0900A8C0:115D", "02", "103") + // its child to 192.168.0.9:4445
		row("0200A8C0:9C42", "0A00A8C0:01BB", "01", "104") // kodeblue to its hub, 192.168.0.10:443
	_ = os.WriteFile(filepath.Join(net, "tcp"), []byte(tcp), 0o644)
	r, st := newRunner(t, root)
	spec := Spec{ID: "app-out", Description: "d", Rationale: "r", Kind: "sockets", Severity: "high", ProcessExe: "/usr/bin/node", NoOutbound: true, ConsecutiveFailures: 1, Contain: true}
	rx, f := reflexRun(t, r, st, spec)
	if pids(rx) != "kill_process:20" {
		t.Fatalf("want only the child killed, got %s", pids(rx))
	}
	if len(f) != 1 || !strings.Contains(f[0].Evidence["output"], "192.168.0.9:4444") {
		t.Fatalf("the service's own connection must still be reported: %+v", f)
	}
	if strings.Contains(f[0].Evidence["output"], "192.168.0.10") {
		t.Fatalf("kodeblue's own connection is not the service's: %s", f[0].Evidence["output"])
	}
}

func TestContainQuarantinesNewFiles(t *testing.T) {
	root := t.TempDir()
	fakeProc(t, root, 42, 0, "/usr/bin/node", "S")
	app := filepath.Join(root, "proc", "42", "root", "tmp")
	_ = os.MkdirAll(app, 0o777)
	_ = os.WriteFile(filepath.Join(app, "old.txt"), []byte("x"), 0o644)
	r, st := newRunner(t, root)
	spec := Spec{ID: "app-tmp", Description: "d", Rationale: "r", Kind: "file", Severity: "high", Paths: []string{"/proc/{pid:/usr/bin/node}/root/tmp"}, Fast: true, Contain: true}
	if rx, _ := reflexRun(t, r, st, spec); len(rx) != 0 {
		t.Fatalf("baseline acted: %s", pids(rx))
	}
	_ = os.WriteFile(filepath.Join(app, "x.js"), []byte("payload"), 0o644)
	_ = os.WriteFile(filepath.Join(app, "old.txt"), []byte("changed"), 0o644)
	_ = os.Mkdir(filepath.Join(app, "sub"), 0o755)
	rx, _ := reflexRun(t, r, st, spec)
	if pids(rx) != "quarantine_file:/proc/42/root/tmp/x.js" {
		t.Fatalf("want only the new regular file quarantined, got %s", pids(rx))
	}
}

func TestContainNeedsATarget(t *testing.T) {
	s := Spec{ID: "web", Description: "d", Rationale: "r", Kind: "http", Severity: "high", URL: "http://127.0.0.1/", Contain: true}
	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "contain") {
		t.Fatalf("contain on an http monitor: %v", err)
	}
	s = Spec{ID: "app", Description: "d", Rationale: "r", Kind: "process", Severity: "high", ProcessExe: "/usr/bin/node", Contain: true}
	if err := s.Validate(); err == nil {
		t.Fatal("contain on a process monitor without no_children should be refused")
	}
}

// A real zombie has no executable and no command line; it must still be
// recognised as one (not dropped like a kernel thread) so the output can
// say it was ignored.
func TestNoChildrenCountsRealZombies(t *testing.T) {
	root := t.TempDir()
	fakeProc(t, root, 1, 0, "/usr/bin/node", "S")
	z := filepath.Join(root, "proc", "40")
	_ = os.MkdirAll(z, 0o755)
	_ = os.WriteFile(filepath.Join(z, "status"), []byte("Name:\tnode\nState:\tZ (zombie)\nPPid:\t1\nUid:\t1000\t1000\t1000\t1000\n"), 0o644)
	r, st := newRunner(t, root)
	spec := Spec{ID: "app-rce", Description: "d", Rationale: "r", Kind: "process", Severity: "high", ProcessExe: "/usr/bin/node", NoChildren: true}
	if ok, out := run(t, r, st, spec); !ok || !strings.Contains(out, "ignored 1 zombie(s)") {
		t.Fatalf("got ok=%v %s", ok, out)
	}
}
