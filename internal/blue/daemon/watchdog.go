package daemon

import (
	"context"
	"time"
)

const (
	// loopGrace is how long one pass of the main loop may take beyond its
	// wait: a sweep, routing, steering a session. Generous on purpose: a
	// false restart interrupts running investigations.
	loopGrace = 10 * time.Minute
	// Triage runs on its own worker, not the main loop, so its model calls
	// never need to extend the main loop's deadline.
)

// expectProgress records that the main loop will be back within d. While
// that holds, the watchdog keeps telling systemd kodeblue is alive.
func (d *Daemon) expectProgress(within time.Duration) {
	d.progressBy.Store(time.Now().Add(within).UnixNano())
}

// watchdog pings the systemd watchdog (WatchdogSec= in kodeblue.service)
// while the main loop keeps its promise. A crash or kill is already covered
// by Restart=always; this covers a kodeblue that is still running but no
// longer sweeping (a wedged sensor, a deadlock). It stops pinging, systemd
// sends SIGABRT (the Go runtime writes every goroutine's stack to the
// journal) and starts kodeblue again.
func (d *Daemon) watchdog(ctx context.Context) {
	every := d.Systemd.WatchdogInterval() / 3
	if every <= 0 {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	stalled := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if time.Now().UnixNano() < d.progressBy.Load() {
			if err := d.Systemd.Notify("WATCHDOG=1"); err != nil {
				d.log.Warn("systemd watchdog ping failed", "error", err)
			}
			stalled = false
			continue
		}
		if !stalled {
			stalled = true
			d.log.Error("main loop stalled: withholding the systemd watchdog ping so kodeblue is restarted")
			// The store may be what is stuck: never block on it here.
			go d.st.Journal("kodeblue", "watchdog.stalled", "main loop missed its deadline; systemd will restart kodeblue")
		}
	}
}
