// Package sdnotify speaks the part of systemd's notify protocol
// (sd_notify(3)) kodeblue needs: the service watchdog. Without systemd, or
// with no WatchdogSec= in the unit, it does nothing.
package sdnotify

import (
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Notifier sends state lines to the service manager.
type Notifier struct {
	addr     string
	interval time.Duration
}

// FromEnv reads the notify socket and watchdog interval systemd passed and
// removes them from the environment, so processes kodeblue spawns (the
// engine, agent tools) cannot use or see them. It returns nil when kodeblue
// does not run under a service manager that listens.
func FromEnv() *Notifier {
	addr := os.Getenv("NOTIFY_SOCKET")
	usec := os.Getenv("WATCHDOG_USEC")
	pid := os.Getenv("WATCHDOG_PID")
	for _, k := range []string{"NOTIFY_SOCKET", "WATCHDOG_USEC", "WATCHDOG_PID"} {
		_ = os.Unsetenv(k)
	}
	if addr == "" {
		return nil
	}
	n := &Notifier{addr: addr}
	if v, err := strconv.ParseInt(usec, 10, 64); err == nil && v > 0 && (pid == "" || pid == strconv.Itoa(os.Getpid())) {
		n.interval = time.Duration(v) * time.Microsecond
	}
	return n
}

// WatchdogInterval is the unit's WatchdogSec=: systemd kills and restarts
// the service when no WATCHDOG=1 arrives within it. Zero when off.
func (n *Notifier) WatchdogInterval() time.Duration {
	if n == nil {
		return 0
	}
	return n.interval
}

// Notify sends one state line, e.g. "WATCHDOG=1".
func (n *Notifier) Notify(state string) error {
	if n == nil {
		return nil
	}
	c, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: socketName(n.addr), Net: "unixgram"})
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = c.Write([]byte(state))
	return err
}

// socketName maps systemd's "@name" notation for an abstract socket to the
// leading NUL the kernel expects.
func socketName(addr string) string {
	if strings.HasPrefix(addr, "@") {
		return "\x00" + addr[1:]
	}
	return addr
}
