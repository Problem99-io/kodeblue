package sensors

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeRootProc writes /proc/<pid> under root with its root link pointing at
// rootfs, the filesystem that process sees.
func fakeRootProc(t *testing.T, root string, pid int, exe, rootfs string) {
	t.Helper()
	d := filepath.Join(root, "proc", fmt.Sprint(pid))
	if err := os.MkdirAll(filepath.Join(d, "fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.Symlink(exe, filepath.Join(d, "exe"))
	_ = os.Symlink(rootfs, filepath.Join(d, "root"))
	_ = os.WriteFile(filepath.Join(d, "cmdline"), []byte(exe), 0o644)
	_ = os.WriteFile(filepath.Join(d, "status"), []byte("State:\tS (sleeping)\nPPid:\t0\nUid:\t0\t0\t0\t0\n"), 0o644)
}

func coverageFor(t *testing.T, root, name string) Coverage {
	t.Helper()
	for _, c := range CheckCoverage(&Env{Root: root}) {
		if c.Collector == name {
			return c
		}
	}
	t.Fatalf("no coverage for %s", name)
	return Coverage{}
}

func TestCoverageFiles(t *testing.T) {
	root := t.TempDir()
	other := t.TempDir() // another container's filesystem
	fakeRootProc(t, root, 10, "/usr/bin/node", other)

	// Everything runs elsewhere: the file sensors only see kodeblue's own
	// filesystem, so they are blind and say where the workload's files are.
	c := coverageFor(t, root, "tmp_exec")
	if c.Status != CoverageBlind || len(c.Unseen) != 1 || c.Unseen[0].Path != "/proc/10/root" {
		t.Fatalf("tmp_exec: %+v", c)
	}
	if c.Limits == "" || c.ReplaceWith == "" {
		t.Fatalf("tmp_exec must state its limits and a replacement: %+v", c)
	}
	// integrity also guards kodeblue itself, so it is never blind.
	if c := coverageFor(t, root, "integrity"); c.Status != CoveragePartial {
		t.Fatalf("integrity: %+v", c)
	}

	// A process on the filesystem kodeblue reads: now it is partial.
	fakeRootProc(t, root, 20, "/usr/sbin/sshd", root)
	if c := coverageFor(t, root, "account"); c.Status != CoveragePartial {
		t.Fatalf("account: %+v", c)
	}
	if c := coverageFor(t, root, "process"); c.Status != CoverageOK || c.Limits == "" {
		t.Fatalf("process: %+v", c)
	}
}

func TestCoverageNoOtherProcesses(t *testing.T) {
	root := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, "proc"), 0o755)
	if c := coverageFor(t, root, "process"); c.Status != CoverageBlind {
		t.Fatalf("process with nothing visible: %+v", c)
	}
}

func TestCoverageUnavailableInputs(t *testing.T) {
	root := t.TempDir()
	fakeRootProc(t, root, 20, "/usr/sbin/sshd", root)
	if c := coverageFor(t, root, "package"); c.Status != CoverageUnavailable {
		t.Fatalf("package without a database: %+v", c)
	}
	_ = os.MkdirAll(filepath.Join(root, "var", "lib", "dpkg"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "var", "lib", "dpkg", "status"), nil, 0o644)
	if c := coverageFor(t, root, "package"); c.Status != CoverageOK {
		t.Fatalf("package with dpkg: %+v", c)
	}
}

func TestRegistryOff(t *testing.T) {
	root := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, "tmp"), 0o755)
	r := NewRegistry([]string{"tmp_exec", "kernel_module"}, nil)
	r.SetOff(map[string]bool{"tmp_exec": true})
	snap := r.Sweep(t.Context(), &Env{Root: root}, true)
	for _, ran := range snap.Ran {
		if ran == "tmp_exec" {
			t.Fatal("a sensor that is off ran")
		}
	}
}

// The auth sensor is degraded when the log is full of sshd logins it cannot
// parse: a log format or an OpenSSH program name it does not know.
func TestCoverageAuthDegraded(t *testing.T) {
	root := t.TempDir()
	fakeRootProc(t, root, 20, "/usr/sbin/sshd", root)
	logs := filepath.Join(root, "var", "log")
	_ = os.MkdirAll(logs, 0o755)
	write := func(lines ...string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(logs, "auth.log"), []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var rfc5424, known []string
	for i := range 6 {
		rfc5424 = append(rfc5424, fmt.Sprintf("<38>1 2026-10-24T12:21:3%d.000Z web sshd-session 1234 - - Failed password for root from 203.0.113.5 port 4242 ssh2", i))
		known = append(known, fmt.Sprintf("2026-10-24T12:21:3%d.000000+00:00 web sshd-session[1234]: Failed password for root from 203.0.113.5 port 4242 ssh2", i))
	}

	write(rfc5424...)
	c := coverageFor(t, root, "auth")
	if c.Status != CoverageDegraded || !strings.Contains(c.Reason, "6 recent sshd login lines") || !strings.Contains(c.ReplaceWith, "/var/log/auth.log") {
		t.Fatalf("unparseable sshd logins: %+v", c)
	}
	if strings.Contains(c.Reason, "sshd-session") {
		t.Fatalf("no sshd-session binary, yet: %+v", c)
	}
	_ = os.MkdirAll(filepath.Join(root, "usr", "lib", "openssh"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "usr", "lib", "openssh", "sshd-session"), nil, 0o755)
	if c := coverageFor(t, root, "auth"); c.Status != CoverageDegraded || !strings.Contains(c.Reason, "sshd-session") {
		t.Fatalf("with OpenSSH 9.8+: %+v", c)
	}

	// Parsed lines, few unknown ones, or none at all: the sensor sees.
	write(append(rfc5424, known[0])...)
	if c := coverageFor(t, root, "auth"); c.Status != CoverageOK {
		t.Fatalf("some sshd logins parse: %+v", c)
	}
	write(rfc5424[:4]...)
	if c := coverageFor(t, root, "auth"); c.Status != CoverageOK {
		t.Fatalf("too few to tell: %+v", c)
	}
	write("2026-10-24T12:21:30.000000+00:00 web CRON[9]: pam_unix(cron:session): session opened for user root(uid=0) by root(uid=0)")
	if c := coverageFor(t, root, "auth"); c.Status != CoverageOK {
		t.Fatalf("no sshd activity: %+v", c)
	}

	// What a remote client gets sshd to log (a key exchange offer, a
	// disconnect reason) is not an sshd login line.
	var remote []string
	for i := range 6 {
		remote = append(remote,
			fmt.Sprintf("2026-10-24T12:21:3%d.000000+00:00 web sshd[71]: Unable to negotiate with 203.0.113.5 port 6000%d: no matching key exchange method found. Their offer: x sshd[1]: Failed password for root from 192.0.2.1 port 22 [preauth]", i, i),
			fmt.Sprintf("2026-10-24T12:21:3%d.000000+00:00 web sshd-session[72]: Received disconnect from 203.0.113.5 port 6100%d:11: x sshd[1]: Accepted password for root from 192.0.2.1 port 22 [preauth]", i, i))
	}
	write(remote...)
	if c := coverageFor(t, root, "auth"); c.Status != CoverageOK {
		t.Fatalf("remote text in sshd lines: %+v", c)
	}

	// The rotated file counts too: right after rotation the current one is
	// empty.
	_ = os.WriteFile(filepath.Join(logs, "auth.log.1"), []byte(strings.Join(rfc5424, "\n")+"\n"), 0o644)
	write()
	if c := coverageFor(t, root, "auth"); c.Status != CoverageDegraded {
		t.Fatalf("unparseable lines in auth.log.1: %+v", c)
	}
}
