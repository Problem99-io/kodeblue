package sdnotify

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// listen opens a datagram socket like systemd's notify socket. The path stays
// short: unix socket paths are limited to about 100 bytes.
func listen(t *testing.T) (string, *net.UnixConn) {
	t.Helper()
	dir, err := os.MkdirTemp("", "sd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "n.sock")
	c, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return path, c
}

func TestFromEnvAndNotify(t *testing.T) {
	path, c := listen(t)
	t.Setenv("NOTIFY_SOCKET", path)
	t.Setenv("WATCHDOG_USEC", "120000000")
	t.Setenv("WATCHDOG_PID", strconv.Itoa(os.Getpid()))
	n := FromEnv()
	if n == nil {
		t.Fatal("no notifier with NOTIFY_SOCKET set")
	}
	if got := n.WatchdogInterval(); got != 2*time.Minute {
		t.Fatalf("interval = %s, want 2m", got)
	}
	for _, k := range []string{"NOTIFY_SOCKET", "WATCHDOG_USEC", "WATCHDOG_PID"} {
		if _, ok := os.LookupEnv(k); ok {
			t.Fatalf("%s left in the environment for child processes", k)
		}
	}
	if err := n.Notify("WATCHDOG=1"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	k, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:k]); got != "WATCHDOG=1" {
		t.Fatalf("received %q", got)
	}
}

func TestWatchdogForAnotherProcess(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "/run/systemd/notify")
	t.Setenv("WATCHDOG_USEC", "120000000")
	t.Setenv("WATCHDOG_PID", "1")
	if got := FromEnv().WatchdogInterval(); got != 0 {
		t.Fatalf("watchdog meant for pid 1 armed here: %s", got)
	}
}

func TestNoServiceManager(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	n := FromEnv()
	if n != nil {
		t.Fatal("notifier without NOTIFY_SOCKET")
	}
	if n.WatchdogInterval() != 0 || n.Notify("WATCHDOG=1") != nil {
		t.Fatal("nil notifier must be a no-op")
	}
}

func TestAbstractSocketName(t *testing.T) {
	if got := socketName("@/org/freedesktop/systemd1/notify"); got != "\x00/org/freedesktop/systemd1/notify" {
		t.Fatalf("abstract name = %q", got)
	}
	if got := socketName("/run/systemd/notify"); got != "/run/systemd/notify" {
		t.Fatalf("path = %q", got)
	}
}
