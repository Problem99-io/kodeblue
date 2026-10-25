package daemon

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/config"
	"github.com/Problem99-io/kodeblue/internal/blue/sdnotify"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

func TestWatchdogPingsOnlyWhileTheLoopKeepsItsPromise(t *testing.T) {
	// A notify socket like systemd's, on a short path (unix socket paths
	// are limited to about 100 bytes).
	sockDir, err := os.MkdirTemp("", "sd")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(sockDir)
	sock := filepath.Join(sockDir, "n.sock")
	srv, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sock, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	t.Setenv("NOTIFY_SOCKET", sock)
	t.Setenv("WATCHDOG_USEC", "300000") // pings every 100ms
	t.Setenv("WATCHDOG_PID", "")

	dir := t.TempDir()
	cfg := config.Default()
	cfg.Server.StateDir = dir
	st, err := store.Open(filepath.Join(dir, "kb.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	d := New(cfg, st, slog.Default())
	d.Systemd = sdnotify.FromEnv()

	// ping waits up to wait for one datagram; "" when none arrived.
	buf := make([]byte, 64)
	ping := func(wait time.Duration) string {
		_ = srv.SetReadDeadline(time.Now().Add(wait))
		n, err := srv.Read(buf)
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return ""
		}
		if err != nil {
			t.Fatal(err)
		}
		return string(buf[:n])
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.expectProgress(time.Hour)
	go d.watchdog(ctx)

	if got := ping(2 * time.Second); got != "WATCHDOG=1" {
		t.Fatalf("healthy loop: got %q, want WATCHDOG=1", got)
	}

	// The loop misses its deadline: the pings stop, so systemd restarts us.
	d.progressBy.Store(0)
	for ping(250*time.Millisecond) != "" { // drain pings already sent
	}
	if got := ping(500 * time.Millisecond); got != "" {
		t.Fatalf("stalled loop still pinged: %q", got)
	}
	deadline := time.Now().Add(2 * time.Second)
	for !journaled(st, "watchdog.stalled") {
		if time.Now().After(deadline) {
			t.Fatal("stall not journaled")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// The loop comes back before systemd acts: pings resume.
	d.expectProgress(time.Hour)
	if got := ping(2 * time.Second); got != "WATCHDOG=1" {
		t.Fatalf("recovered loop: got %q, want WATCHDOG=1", got)
	}
}

func journaled(st *store.Store, action string) bool {
	for _, e := range st.JournalSince(time.Time{}, 100) {
		if e.Action == action {
			return true
		}
	}
	return false
}

func TestWatchdogOffWithoutSystemd(t *testing.T) {
	d := &Daemon{}
	done := make(chan struct{})
	go func() { d.watchdog(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("watchdog kept running with no systemd watchdog configured")
	}
}

// The unit is what brings kodeblue back. WatchdogSec= and the pings above
// only work together: a unit with one and a binary without the other kills
// kodeblue every two minutes, or never restarts a hung one.
func TestUnitRecoversKodeblue(t *testing.T) {
	b, err := os.ReadFile("../../../deploy/kodeblue.service")
	if err != nil {
		t.Fatal(err)
	}
	unit := string(b)
	for _, want := range []string{
		"\nRestart=always\n",
		"\nStartLimitIntervalSec=0\n",
		"\nWatchdogSec=2min\n",
		"\nNotifyAccess=main\n",
		"\nOOMScoreAdjust=-900\n",
		"\nWants=kodeblue-respond.socket\n",
		"\nWantedBy=multi-user.target\n",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("deploy/kodeblue.service lacks %q", strings.TrimSpace(want))
		}
	}
}
