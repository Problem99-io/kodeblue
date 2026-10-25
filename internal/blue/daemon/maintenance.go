package daemon

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/detect"
	"github.com/Problem99-io/kodeblue/internal/blue/notify"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

// maxMaintenance is the longest maintenance window, the CLI's own limit.
const maxMaintenance = 24 * time.Hour

// maintenanceKey records the window as last enforced, for `kodeblue status`.
// It lives in the store, which the kodeblue user can write as easily as the
// file itself, so the daemon never relies on it to lengthen a window or to
// skip an announcement: its first-seen time can only make a window shorter.
const maintenanceKey = "maintenance_window"

// maintenanceWindow is the maintenance-until file as the daemon enforces it.
type maintenanceWindow struct {
	Written string    `json:"written,omitempty"` // the file's content
	ModTime int64     `json:"mtime,omitempty"`   // the file's mtime (unix)
	Seen    int64     `json:"seen,omitempty"`    // when the daemon first saw this content
	Until   time.Time `json:"until"`             // the end the daemon enforces; zero: no window
	// Tamper says why the file is not what `kodeblue maintenance` writes.
	Tamper string `json:"tamper,omitempty"`
	// Open is set once the window was announced as open (informational).
	Open bool `json:"open,omitempty"`
}

func (w maintenanceWindow) active(now time.Time) bool { return now.Before(w.Until) }

// maintenance reads the maintenance-until file. The kodeblue user can write
// it (and its mtime), so its content is not trusted: a window ends at most
// 24 h after the file was written, counted from the earliest of its mtime,
// when this daemon process first saw that content, and the first sight the
// store recorded. Touching the file does not restart the 24 h; only new
// content does, and every change is announced. Anything longer is clamped
// and reported as tampering.
//
// Limit: a daemon restart forgets its first sight, so the kodeblue user can
// restart kodeblue and wipe the store's record to start a forged window's
// 24 h again. Each restart announces the open window (and the tampering)
// afresh, so that cannot happen silently.
func (d *Daemon) maintenance(now time.Time) maintenanceWindow {
	path := d.cfg.MaintenanceFile()
	fi, err := os.Stat(path)
	if err != nil {
		return maintenanceWindow{}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return maintenanceWindow{}
	}
	w := maintenanceWindow{Written: strings.TrimSpace(string(b)), ModTime: fi.ModTime().Unix()}
	d.maintMu.Lock()
	if d.maintWritten != w.Written || d.maintSeen.IsZero() {
		d.maintWritten, d.maintSeen = w.Written, now
	}
	seen := d.maintSeen
	d.maintMu.Unlock()
	var rec maintenanceWindow
	if json.Unmarshal([]byte(d.st.Get(maintenanceKey)), &rec) == nil && rec.Written == w.Written && rec.Seen > 0 && rec.Seen < seen.Unix() {
		seen = time.Unix(rec.Seen, 0) // only ever earlier: forging it cannot lengthen a window
	}
	w.Seen = seen.Unix()
	until, err := time.Parse(time.RFC3339, w.Written)
	if err != nil {
		return w // not a window
	}
	written := fi.ModTime()
	if seen.Before(written) {
		written = seen
	}
	limit := written.Add(maxMaintenance)
	w.Until = until
	switch {
	case fi.ModTime().After(now.Add(time.Minute)):
		w.Tamper = "its mtime " + fi.ModTime().UTC().Format(time.RFC3339) + " is in the future"
	case until.After(limit.Add(time.Minute)):
		// The CLI writes now+duration, so a little over 24 h after the mtime is
		// only clock skew between writing and stat; more is not the CLI.
		w.Tamper = fmt.Sprintf("it asks for a window until %s, %s after it was written (max 24h)",
			until.UTC().Format(time.RFC3339), approx(until.Sub(written)))
	}
	if until.After(limit) {
		w.Until = limit
	}
	return w
}

func (d *Daemon) mode() detect.Mode {
	if d.maintenance(time.Now()).active(time.Now()) {
		return detect.ModeMaintenance
	}
	return detect.ModeDetect
}

// announceMaintenance posts every change to the maintenance window: opened,
// extended or shortened, ended, and a file that `kodeblue maintenance` did
// not write. Windows absorb non-critical changes, so one opened by an
// attacker must not go unnoticed: the Slack channel and the hub both see it.
func (d *Daemon) announceMaintenance() {
	now := time.Now()
	cur := d.maintenance(now)
	// What was announced lives in memory: a fresh process announces an open
	// window (and any tampering) again rather than trust the store.
	prev, started := d.maintPrev, !d.maintChecked
	d.maintChecked = true
	was, is := prev.Open, cur.active(now)
	cur.Open = is
	d.maintPrev = cur
	if b, _ := json.Marshal(cur); string(b) != d.st.Get(maintenanceKey) {
		_ = d.st.Set(maintenanceKey, string(b))
	}
	until := cur.Until.UTC().Format(time.RFC3339)
	if cur.Tamper != "" && (cur.Written != prev.Written || prev.Tamper == "") {
		d.log.Error("maintenance file tampered with", "why", cur.Tamper, "content", cur.Written, "enforced_until", until)
		d.st.Journal("kodeblue", "maintenance.tamper", cur.Tamper+"; enforced until "+until)
		d.announce("maintenance", "high", "Maintenance window file was not written by kodeblue maintenance",
			"The maintenance-until file is not what `kodeblue maintenance` writes: "+cur.Tamper+". kodeblue enforces at most 24h from when the file was written, so the window ends "+until+
				". The file is writable by the kodeblue user: if nobody did this by hand, treat it as tampering.")
	}
	switch {
	case is && !was:
		reason := "no reason recorded"
		for _, j := range d.st.JournalSince(now.Add(-2*time.Hour), 200) {
			if j.Action == "maintenance.on" {
				reason = j.Detail // newest first
				break
			}
		}
		title := "Maintenance window opened until " + until
		if started {
			title = "Maintenance window open until " + until + " (kodeblue started during it)"
		}
		d.log.Warn("maintenance window open", "until", until, "reason", reason, "at_start", started)
		d.st.Journal("kodeblue", "maintenance.open", "until "+until)
		d.announce("maintenance", "medium", title,
			"Non-critical changes are absorbed into the baseline until then (journaled; open findings are never absorbed). "+reason+"\nIf nobody planned this, treat it as tampering.")
	case is && was && !cur.Until.Equal(prev.Until):
		verb := "extended"
		if cur.Until.Before(prev.Until) {
			verb = "shortened"
		}
		d.log.Warn("maintenance window "+verb, "until", until, "was", prev.Until.UTC().Format(time.RFC3339))
		d.st.Journal("kodeblue", "maintenance."+verb, "until "+until)
		d.announce("maintenance", "medium", "Maintenance window "+verb+" until "+until,
			"It was to end "+prev.Until.UTC().Format(time.RFC3339)+". Non-critical changes are absorbed into the baseline until then.\nIf nobody planned this, treat it as tampering.")
	case !is && was:
		how := "ran out"
		if cur.Written == "" {
			how = "was closed"
		}
		d.log.Info("maintenance window ended", "how", how)
		d.st.Journal("kodeblue", "maintenance.end", how)
		d.announce("maintenance", "info", "Maintenance window ended", "The window "+how+"; detection is back to normal.")
	}
}

// approx renders a long duration in days, a short one in hours and minutes.
func approx(d time.Duration) string {
	if d >= 48*time.Hour {
		return fmt.Sprintf("%.0f days", d.Hours()/24)
	}
	return d.Round(time.Minute).String()
}

// Maintenance returns the end of the maintenance window the daemon enforces
// (RFC 3339), or "" when none is open (hub status).
func (d *Daemon) Maintenance() string {
	now := time.Now()
	if w := d.maintenance(now); w.active(now) {
		return w.Until.UTC().Format(time.RFC3339)
	}
	return ""
}

// MaintenanceStatus is the maintenance window the daemon enforces for a
// maintenance-until file with content written (for `kodeblue status`): its
// end, and why the file was clamped, if it was. ok is false until the daemon
// has seen that content.
func MaintenanceStatus(st *store.Store, written string) (until time.Time, tamper string, ok bool) {
	var w maintenanceWindow
	if json.Unmarshal([]byte(st.Get(maintenanceKey)), &w) != nil || w.Written == "" || w.Written != written {
		return time.Time{}, "", false
	}
	return w.Until, w.Tamper, true
}

func (d *Daemon) announce(kind, severity, title, body string) {
	d.nudgeHub()
	d.slack.Async(notify.Message{Server: d.cfg.Server.Name, Kind: kind, Severity: severity, Title: title, Body: body}, nil)
}
