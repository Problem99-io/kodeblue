package detect

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/sensors"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
	"github.com/Problem99-io/kodeblue/internal/blue/upgrade"
)

// Options tune the detector's noise controls.
type Options struct {
	// DebounceSweeps: a non-instant state change must be observed in this many
	// consecutive sweeps before it becomes a finding. Transient things
	// (a short-lived build process, a port held during a restart) never do.
	DebounceSweeps int
	// RealertAfter: a fingerprint that already produced a finding is not
	// re-reported (only counted) until this long after it was last touched.
	RealertAfter time.Duration
	// ForgetGoneAfter: baseline items absent this long are forgotten instead
	// of reported as gone forever.
	ForgetGoneAfter time.Duration
	// BruteForceThreshold failures from one IP within BruteForceWindow make a
	// (low) brute-force finding; any later success from it is critical.
	BruteForceThreshold int
	BruteForceWindow    time.Duration
	// SelfExes are kodeblue's own binaries. Their processes, sockets and
	// connections (to the model endpoint) are not findings.
	SelfExes []string
}

func DefaultOptions() Options {
	return Options{DebounceSweeps: 2, RealertAfter: 24 * time.Hour, ForgetGoneAfter: 7 * 24 * time.Hour, BruteForceThreshold: 20, BruteForceWindow: 10 * time.Minute}
}

// Detector holds the in-memory view used between sweeps.
type Detector struct {
	opts  Options
	st    *store.Store
	env   *sensors.Env
	mu    sync.Mutex
	sweep int
	// pending[fingerprint] = consecutive runs of its collector that saw it
	pending  map[string]*pendingFP
	failures map[string][]time.Time // ip -> failure times
	self     map[string]bool        // exact paths of kodeblue's own binaries
	selfIDs  []fileID               // device+inode of kodeblue's own binaries
	collErr  map[string]string      // collector -> last journaled error
}

// fileID identifies a file by device and inode, so an attacker cannot pass a
// path off as kodeblue's binary with a bind mount or a separate mount
// namespace: the real file behind /proc/<pid>/exe has a different inode.
type fileID struct{ dev, ino uint64 }

func statID(path string) (fileID, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return fileID{}, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fileID{}, false
	}
	return fileID{dev: uint64(st.Dev), ino: uint64(st.Ino)}, true
}

// pkgTrust is the package version and checksum-list digest we last trusted for
// a package. A later checksum-list change under the same version is tampering
// (root rewrote /var/lib/dpkg/info/*.md5sums to make a trojan "verify").
type pkgTrust struct{ ver, digest string }

type pendingFP struct {
	runs      int
	collector string
	lastSweep int
}

// pendingStaleSweeps drops debounce state for a collector that stopped
// running altogether (turned off, or failing every time).
const pendingStaleSweeps = 100

// sshKeysLearnedKey records when learning first read the authorized keys.
const sshKeysLearnedKey = "ssh_keys_learned_at"

func New(st *store.Store, env *sensors.Env, opts Options) *Detector {
	if opts.DebounceSweeps < 1 {
		opts.DebounceSweeps = 1
	}
	self := map[string]bool{}
	var selfIDs []fileID
	for _, exe := range opts.SelfExes {
		if !filepath.IsAbs(exe) {
			continue
		}
		self[filepath.Clean(exe)] = true
		real := exe
		if r, err := filepath.EvalSymlinks(exe); err == nil {
			self[r] = true
			real = r
		}
		if env != nil {
			if id, ok := statID(env.Path(real)); ok {
				selfIDs = append(selfIDs, id)
			}
		}
	}
	return &Detector{opts: opts, st: st, env: env, pending: map[string]*pendingFP{}, failures: map[string][]time.Time{}, self: self, selfIDs: selfIDs, collErr: map[string]string{}}
}

// Mode controls what the detector does with changes.
type Mode int

const (
	// ModeLearn absorbs everything into the baseline, but still reports the
	// handful of things that are never legitimate (pre-existing compromise).
	ModeLearn Mode = iota
	// ModeDetect reports changes.
	ModeDetect
	// ModeMaintenance absorbs non-critical changes (operator-declared window).
	ModeMaintenance
)

// Result of processing one snapshot.
type Result struct {
	New      []*store.Finding // freshly created findings (need routing)
	Absorbed int              // changes absorbed into the baseline silently
	Allowed  int              // changes matched by an allow rule
	Bumped   int              // repeat observations of already-reported things
	Pending  int              // changes waiting for debounce confirmation
}

type change struct {
	kind ChangeKind
	item sensors.Item
	prev string
}

// Process diffs snap against the baseline and returns new findings.
func (d *Detector) Process(snap sensors.Snapshot, mode Mode) (Result, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sweep++
	var res Result
	base, err := d.st.Baseline()
	if err != nil {
		return res, err
	}
	rules := d.st.AllowRules()
	ran := map[string]bool{}
	for _, c := range snap.Ran {
		ran[c] = true
	}
	d.st.BumpCollectorRuns(snap.Ran)
	d.journalCollectorErrors(snap.Errors, ran)

	var changes []change
	var touch []string
	present := map[string]bool{}
	for _, it := range snap.Items {
		id := it.ID()
		present[id] = true
		b, ok := base[id]
		switch {
		case !ok:
			changes = append(changes, change{kind: ChangeNew, item: it})
		case b.Value != it.Value:
			changes = append(changes, change{kind: ChangeChanged, item: it, prev: b.Value})
		default:
			touch = append(touch, id)
		}
	}
	_ = d.st.TouchBaseline(touch)
	now := time.Now()
	for id, b := range base {
		if !ran[b.Collector] || present[id] {
			continue
		}
		if now.Sub(b.LastSeen) > d.opts.ForgetGoneAfter {
			_ = d.st.DeleteBaseline(id)
			d.st.Journal("detector", "baseline.forget", id+" (absent since "+b.LastSeen.Format(time.RFC3339)+")")
			continue
		}
		if DisappearanceMatters[b.Collector] {
			changes = append(changes, change{kind: ChangeGone, item: sensors.Item{Collector: b.Collector, Key: b.Key, Value: b.Value, Attrs: b.Attrs}, prev: b.Value})
		}
	}

	recentPkgs := map[string]bool{}
	for _, p := range d.env.Pkg.RecentActivity(d.env, now.Add(-2*time.Hour)) {
		recentPkgs[p] = true
	}
	// pkgMoved reports whether the package database itself records a change
	// to pkg since the baseline: a version different from the baselined one,
	// or (not baselined yet) a fresh install the package log also shows. A
	// checksum match alone proves nothing: root can rewrite
	// /var/lib/dpkg/info/*.md5sums together with the binary.
	pkgMoved := func(pkg string) bool {
		if b, ok := base["package|"+pkg]; ok {
			cur := d.env.Pkg.Version(pkg)
			return cur != "" && packageVersion(b.Value) != cur
		}
		return recentPkgs[pkg]
	}
	// packageExplains decides whether a package-verified change to pkg's files
	// is a real upgrade (absorb) or tampering (alert), independently of the
	// package collector's slow cadence. It trusts a change only when the
	// package version advanced since we last trusted it; a checksum-list
	// digest that changes while the version stays put is tampering, so a
	// trojan planted inside the window after a genuine upgrade is still caught.
	trust := map[string]pkgTrust{}
	var trustDirty []store.BaselineItem
	packageExplains := func(pkg string) bool {
		cur, curD := d.env.Pkg.Version(pkg), d.env.Pkg.SumsDigest(pkg)
		tr, ok := trust[pkg]
		if !ok {
			if b, had := base["pkgtrust|"+pkg]; had {
				v, dg, _ := strings.Cut(b.Value, "\x00")
				tr, ok = pkgTrust{v, dg}, true
				trust[pkg] = tr
			}
		}
		record := func(nv, nd string) {
			trust[pkg] = pkgTrust{nv, nd}
			trustDirty = append(trustDirty, store.BaselineItem{ID: "pkgtrust|" + pkg, Collector: "pkgtrust", Key: pkg, Value: nv + "\x00" + nd})
		}
		switch {
		case !ok:
			// First time we see this package: nothing to compare against, so
			// fall back to the version/activity signal and remember it.
			record(cur, curD)
			return pkgMoved(pkg)
		case cur != "" && cur != tr.ver:
			// A new version shipped new bytes and a new checksum list together.
			record(cur, curD)
			return true
		case curD != tr.digest:
			// Same version, different checksum list: md5sums was rewritten
			// outside a package transaction. Do not update trust.
			return false
		default:
			return pkgMoved(pkg)
		}
	}

	// The keys in authorized_keys at install are the admins' (cloud images put
	// the provisioning key in root's), so they are learned, not reported as an
	// attack, and the "now watching" message lists root's for a human to
	// review. Only the first learning sweep may do this, and it closes the
	// window whether or not the key collector ran: a key that appears later,
	// while learning goes on or after it, or that a failing collector first
	// reads later, is reported as usual. A store that already has keys never
	// reopens it. Seeding login history runs no collector and is not a sweep.
	firstKeys := false
	if mode == ModeLearn && len(snap.Ran) > 0 && d.st.Get(sshKeysLearnedKey) == "" {
		_ = d.st.Set(sshKeysLearnedKey, now.UTC().Format(time.RFC3339))
		firstKeys = ran["ssh_key"]
		for _, b := range base {
			if b.Collector == "ssh_key" {
				firstKeys = false
			}
		}
	}

	seenFP := map[string]bool{}
	var absorb []store.BaselineItem
	for _, ch := range changes {
		if pkg := ch.item.Attrs["package"]; pkg != "" && ch.item.Attrs["package_verified"] == "true" && !packageExplains(pkg) {
			// The bytes match the package's checksum list, but no package
			// upgrade explains why they changed (and the checksum list itself
			// may have been forged): score it as an unverified change.
			attrs := make(map[string]string, len(ch.item.Attrs)+1)
			for k, val := range ch.item.Attrs {
				attrs[k] = val
			}
			attrs["package_verified"] = "unexplained"
			attrs["package_note"] = "matches the package checksum list, but package " + pkg + " was not upgraded in the package database"
			ch.item.Attrs = attrs
		}
		v := scoreChange(ch.kind, ch.item, ch.prev)
		if d.isSelf(ch.item) {
			v = Verdict{}
		} else if d.isSelfUpgrade(ch.item) {
			d.st.Journal("detector", "absorb.upgrade", v.Title+" (pid "+ch.item.Attrs["pid"]+" in "+ch.item.Attrs["unit"]+")")
			v = Verdict{}
		}
		bi := store.BaselineItem{ID: ch.item.ID(), Collector: ch.item.Collector, Key: ch.item.Key, Value: ch.item.Value, Attrs: ch.item.Attrs}
		if v.Rule == "" || v.Severity == SevInfo {
			if ch.kind != ChangeGone {
				absorb = append(absorb, bi)
				res.Absorbed++
				if v.Rule != "" {
					d.st.Journal("detector", "absorb", v.Title)
				}
			}
			continue
		}
		evidence := map[string]string{"change": string(ch.kind)}
		for k, val := range ch.item.Attrs {
			evidence[k] = val
		}
		if ch.item.Value != "" {
			evidence["value"] = ch.item.Value
		}
		if ch.prev != "" && ch.kind == ChangeChanged {
			evidence["previous_value"] = ch.prev
		}
		// A package that was just installed/upgraded explains config drift
		// in files it owns. Lower one level and say why — but only when the
		// package database agrees (a dpkg.log line is trivially forged), and
		// never for protected detections.
		if pkg := ch.item.Attrs["package"]; pkg != "" && recentPkgs[pkg] && pkgMoved(pkg) && v.Severity != SevCritical && !v.Protected {
			v.Severity = lower(v.Severity)
			evidence["explained_by"] = "package " + pkg + " was installed/upgraded in the last 2h"
		}
		if firstKeys && v.Rule == "ssh_key.added" {
			bi.Note = "present when learning started (an admin's key)"
			absorb = append(absorb, bi)
			res.Absorbed++
			d.st.Journal("detector", "absorb.preexisting", v.Title)
			continue
		}
		if mode == ModeLearn && !(v.Instant && v.Protected) {
			absorb = append(absorb, bi)
			res.Absorbed++
			continue
		}
		if mode == ModeMaintenance && v.Severity != SevCritical && !d.st.ItemUnsettled(ch.item.ID()) {
			// Planned work is absorbed — but never something an open or
			// confirmed finding is about (an attacker's file must not become
			// "normal" because someone upgraded a package mid-incident).
			absorb = append(absorb, bi)
			res.Absorbed++
			d.st.Journal("detector", "absorb.maintenance", v.Title)
			continue
		}
		if r := matchAllow(rules, ch.item, v.Rule); r != nil && !(v.Protected && r.CreatedBy != "operator") {
			d.st.HitAllowRule(r.ID)
			if ch.kind != ChangeGone {
				bi.Note = fmt.Sprintf("allowed by rule #%d: %s", r.ID, r.Reason)
				absorb = append(absorb, bi)
			}
			res.Allowed++
			continue
		}
		// The fingerprint deliberately omits the item value: an attacker who
		// rewrites a dropped file every sweep must not get a fresh identity
		// each time (which would reset debounce and re-alert forever). Rule +
		// item + change kind is the stable identity; the value is evidence.
		fp := fingerprint(v.Rule, ch.item.ID(), ch.kind, "")
		seenFP[fp] = true
		if !v.Instant && mode == ModeDetect {
			p := d.pending[fp]
			if p == nil {
				p = &pendingFP{collector: ch.item.Collector}
				d.pending[fp] = p
			}
			p.runs++
			p.lastSweep = d.sweep
			if p.runs < d.opts.DebounceSweeps {
				res.Pending++
				continue
			}
		}
		if d.repeat(fp) {
			res.Bumped++
			continue
		}
		f := &store.Finding{
			Fingerprint: fp, Collector: ch.item.Collector, Rule: v.Rule, Severity: v.Severity, Title: v.Title,
			Detail:   describe(ch, v),
			Evidence: evidence, ItemID: ch.item.ID(), Value: ch.item.Value,
		}
		if v.Protected {
			f.Evidence["protected"] = "true"
		}
		if mode == ModeLearn {
			f.Evidence["preexisting"] = "true (found during learning — may predate kodeblue)"
		}
		if err := d.st.AddFinding(f); err != nil {
			return res, err
		}
		// Low severity: record for the digest and absorb so it does not
		// repeat; no model is spent on it individually.
		if f.Severity == SevLow && ch.kind != ChangeGone {
			absorb = append(absorb, bi)
		}
		res.New = append(res.New, f)
	}
	// Debounce counts runs of the collector, not sweeps: state resets only
	// when the fingerprint's collector ran and did not see it. Collectors
	// that skip sweeps (tmp_exec, suid, package…) must still confirm.
	for fp, p := range d.pending {
		if !seenFP[fp] && (ran[p.collector] || d.sweep-p.lastSweep > pendingStaleSweeps) {
			delete(d.pending, fp)
		}
	}
	if len(absorb) > 0 {
		src := "learned"
		if mode == ModeDetect {
			src = "auto"
		}
		if err := d.st.UpsertBaseline(absorb, src); err != nil {
			return res, err
		}
	}
	if len(trustDirty) > 0 {
		_ = d.st.UpsertBaseline(trustDirty, "pkgtrust")
	}

	evFindings, err := d.processEvents(snap.Events, mode)
	if err != nil {
		return res, err
	}
	res.New = append(res.New, evFindings...)
	return res, nil
}

// isSelf reports whether a process-derived item is kodeblue's own binary. The
// executable is parsed out of the key and compared exactly: a copy at
// /dev/shm/usr/local/bin/kodeblue, a memfd named after it, or a deleted
// (replaced) executable is not kodeblue.
func (d *Detector) isSelf(it sensors.Item) bool {
	exe := itemExe(it)
	if exe == "" || it.Attrs["deleted"] == "true" || it.Attrs["suspicious_location"] != "" {
		return false
	}
	if !filepath.IsAbs(exe) || strings.HasPrefix(exe, "/memfd:") || strings.HasSuffix(exe, " (deleted)") {
		return false
	}
	// When the live process is reachable, identity is decided by the real
	// file behind /proc/<pid>/exe (device+inode), not the path string. A bind
	// mount or a separate mount namespace can make an impostor's path read as
	// kodeblue's, but os.Stat resolves the symlink to the actual mapped file,
	// whose inode differs.
	if pid := it.Attrs["pid"]; pid != "" && len(d.selfIDs) > 0 {
		id, ok := statID(d.env.Path("/proc/" + pid + "/exe"))
		if !ok {
			return false // our own process is always statable; a foreign one is not us
		}
		for _, s := range d.selfIDs {
			if s == id {
				return true
			}
		}
		return false
	}
	return d.self[exe]
}

// isSelfUpgrade reports whether a root process running from a replaced
// (deleted) kodeblue binary is kodeblue's own upgrade: `kodeblue upgrade` in
// its transient unit, whose installer swaps the binary under it. Only root
// can start a process in that system unit (the root helper does, for a
// checked newer release), so a deleted kodeblue anywhere else is reported.
func (d *Detector) isSelfUpgrade(it sensors.Item) bool {
	exe := itemExe(it)
	return it.Collector == "process" && it.Attrs["deleted"] == "true" && it.Attrs["suspicious_location"] == "" &&
		d.self[exe] && it.Key == exe+"@root" && it.Attrs["unit"] == upgrade.Unit+".service"
}

// itemExe extracts the executable path from the key of a process, cpu_hog
// (exe@user), listener (proto/port/exposure/exe) or outbound (exe->port) item.
func itemExe(it sensors.Item) string {
	switch it.Collector {
	case "process", "cpu_hog":
		if i := strings.LastIndex(it.Key, "@"); i > 0 {
			return it.Key[:i]
		}
	case "listener":
		if parts := strings.SplitN(it.Key, "/", 4); len(parts) == 4 {
			return parts[3]
		}
	case "outbound":
		if i := strings.LastIndex(it.Key, "->"); i > 0 {
			return it.Key[:i]
		}
	}
	return ""
}

// journalCollectorErrors records a collector failing or returning a partial
// result (and recovering), once per distinct error, so a degraded sensor is
// visible instead of only quietly reporting less.
func (d *Detector) journalCollectorErrors(errs map[string]string, ran map[string]bool) {
	for c, e := range errs {
		if d.collErr[c] != e {
			d.collErr[c] = e
			d.st.Journal("detector", "collector.degraded", c+": "+e)
		}
	}
	for c := range d.collErr {
		if _, failing := errs[c]; !failing && ran[c] {
			delete(d.collErr, c)
			d.st.Journal("detector", "collector.recovered", c)
		}
	}
}

// rememberEvents keeps a short rolling window of auth events for triage, so
// a model judging "new cron file" can see that alice just sudo-tee'd it.
func (d *Detector) rememberEvents(events []sensors.Event) {
	if len(events) == 0 {
		return
	}
	type ev struct {
		Time    string `json:"time"`
		Kind    string `json:"kind"`
		Message string `json:"line"`
	}
	var cur []ev
	_ = json.Unmarshal([]byte(d.st.Get("recent_auth_events")), &cur)
	for _, e := range events {
		if e.Kind == "login_failure" || e.Kind == "login_invalid_user" {
			continue // brute-force noise is summarised by its own finding
		}
		msg := e.Message
		if len(msg) > 220 {
			msg = msg[:220]
		}
		cur = append(cur, ev{Time: e.Time.UTC().Format(time.RFC3339), Kind: e.Kind, Message: msg})
	}
	cut := time.Now().Add(-2 * time.Hour)
	var keep []ev
	for _, e := range cur {
		if t, err := time.Parse(time.RFC3339, e.Time); err == nil && t.After(cut) {
			keep = append(keep, e)
		}
	}
	if len(keep) > 30 {
		keep = keep[len(keep)-30:]
	}
	b, _ := json.Marshal(keep)
	_ = d.st.Set("recent_auth_events", string(b))
}

// isSelfEvent recognises kodeblue's own privileged plumbing in the auth log.
func isSelfEvent(ev sensors.Event) bool {
	a := ev.Attrs
	switch ev.Kind {
	case "sudo":
		return a["user"] == "kodeblue" && strings.Contains(a["command"], "kodeblue respond exec")
	case "su_session":
		return a["user"] == "kodeblue" && a["by"] == "root"
	}
	return false
}

// repeat reports whether fingerprint already produced a finding recently and
// counts the observation instead of creating a new one.
func (d *Detector) repeat(fp string) bool {
	if f := d.st.OpenFinding(fp); f != nil {
		d.st.BumpFinding(f.ID)
		return true
	}
	if f := d.st.LastFinding(fp); f != nil && time.Since(f.UpdatedAt) < d.opts.RealertAfter {
		d.st.BumpFinding(f.ID)
		return true
	}
	return false
}

var suspiciousSudo = regexp.MustCompile(`(?i)(chmod\s+[0-7]*[4-7][0-7]{3}|chmod\s+[ug]?\+s|/tmp/|/dev/shm/|base64\s+-d|curl[^|]*\|\s*(ba)?sh|wget[^|]*\|\s*(ba)?sh|useradd|usermod|visudo|/etc/sudoers|authorized_keys|nc\s+-e|ncat|socat|python[0-9.]*\s+-c|perl\s+-e|insmod|modprobe|setcap|chattr|history\s+-c|unset\s+HISTFILE|/etc/shadow|ld\.so\.preload|iptables\s+-F)`)

func (d *Detector) processEvents(events []sensors.Event, mode Mode) ([]*store.Finding, error) {
	var out []*store.Finding
	var known []store.BaselineItem
	base, _ := d.st.Baseline()
	isKnown := func(key string) bool { _, ok := base["auth_known|"+key]; return ok }
	now := time.Now()
	// item, when set, is the baseline entry a benign verdict (triage, an
	// incident, or an operator ack) teaches; until then it stays unknown.
	emit := func(rule, sev, title, subject string, ev sensors.Event, protected bool, item ...string) error {
		fp := fingerprint(rule, subject, "event", "")
		if rule == "auth.bruteforce" || rule == "auth.sudo_failure" {
			fp = fingerprint(rule, subject, "event", now.Format("2006-01-02"))
		}
		if d.repeat(fp) {
			return nil
		}
		evd := map[string]string{"log_line": ev.Message, "time": ev.Time.Format(time.RFC3339)}
		for k, v := range ev.Attrs {
			evd[k] = v
		}
		if protected {
			evd["protected"] = "true"
		}
		f := &store.Finding{Fingerprint: fp, Collector: "auth", Rule: rule, Severity: sev, Title: title, Detail: ev.Message, Evidence: evd}
		if len(item) > 0 {
			f.ItemID = item[0]
		}
		if err := d.st.AddFinding(f); err != nil {
			return err
		}
		out = append(out, f)
		return nil
	}
	d.rememberEvents(events)
	for _, ev := range events {
		a := ev.Attrs
		if isSelfEvent(ev) {
			continue
		}
		switch ev.Kind {
		case "login_failure", "login_invalid_user":
			ip := a["ip"]
			ts := append(d.failures[ip], ev.Time)
			cut := 0
			for cut < len(ts) && ev.Time.Sub(ts[cut]) > d.opts.BruteForceWindow {
				cut++
			}
			d.failures[ip] = ts[cut:]
			if len(d.failures[ip]) >= d.opts.BruteForceThreshold && mode != ModeLearn {
				if err := emit("auth.bruteforce", SevLow, fmt.Sprintf("SSH brute force from %s (%d failures in %s)", ip, len(d.failures[ip]), d.opts.BruteForceWindow), ip, ev, false); err != nil {
					return out, err
				}
			}
		case "login_success":
			user, ip := a["user"], a["ip"]
			key := "login/" + user + "@" + ip
			prefixKey := "login/" + user + "@" + ipPrefix(ip)
			recentFails := len(d.failures[ip])
			learn := func() {
				known = append(known, store.BaselineItem{ID: "auth_known|" + key, Collector: "auth_known", Key: key}, store.BaselineItem{ID: "auth_known|" + prefixKey, Collector: "auth_known", Key: prefixKey})
			}
			if mode == ModeLearn {
				learn()
				continue
			}
			// A source is learned only when nothing about the login was
			// suspicious. Flagged logins are learned once judged benign, so an
			// attacker's first login never makes its IP "known".
			switch {
			case recentFails >= 5:
				if err := emit("auth.success_after_bruteforce", SevCritical, fmt.Sprintf("Successful login for %s from %s after %d recent failures", user, ip, recentFails), user+"@"+ip, ev, true, "auth_known|"+key); err != nil {
					return out, err
				}
			case isKnown(key), isKnown(prefixKey):
				// Known source, or the same /24 (/48) as one: DHCP churn.
				learn()
			default:
				sev := SevMedium
				if user == "root" {
					sev = SevHigh
				}
				if err := emit("auth.new_login_source", sev, fmt.Sprintf("First login for %s from %s (%s)", user, ip, a["method"]), user+"@"+ip, ev, false, "auth_known|"+key); err != nil {
					return out, err
				}
			}
		case "sudo":
			key := "sudo/" + a["user"] + "->" + a["as"]
			learnSudo := store.BaselineItem{ID: "auth_known|" + key, Collector: "auth_known", Key: key}
			if mode == ModeLearn || isKnown(key) {
				known = append(known, learnSudo)
			}
			if mode == ModeLearn {
				continue
			}
			if suspiciousSudo.MatchString(a["command"]) {
				if err := emit("auth.sudo_suspicious_command", SevHigh, fmt.Sprintf("%s ran a sensitive command via sudo: %s", a["user"], a["command"]), a["user"]+":"+hashShort(a["command"]), ev, false); err != nil {
					return out, err
				}
			} else if !isKnown(key) {
				sev := SevMedium
				for _, g := range []string{"sudo", "wheel", "admin"} {
					if _, ok := base["account|group/"+g+"/"+a["user"]]; ok {
						sev = SevLow // an established sudoer using sudo is expected
					}
				}
				if sev == SevLow {
					known = append(known, learnSudo)
				}
				if err := emit("auth.sudo_new_user", sev, fmt.Sprintf("%s used sudo (as %s) for the first time", a["user"], a["as"]), a["user"], ev, false, learnSudo.ID); err != nil {
					return out, err
				}
			}
		case "sudo_failure":
			if mode != ModeLearn {
				if err := emit("auth.sudo_failure", SevLow, fmt.Sprintf("sudo failure for %s: %s", a["user"], a["reason"]), a["user"], ev, false); err != nil {
					return out, err
				}
			}
		case "user_added":
			if mode != ModeLearn {
				if err := emit("auth.user_added", SevHigh, fmt.Sprintf("Account created: %s (uid %s)", a["user"], a["uid"]), a["user"], ev, true); err != nil {
					return out, err
				}
			}
		case "group_added":
			if mode != ModeLearn && privileged(a["group"]) {
				if err := emit("auth.privileged_group_added", SevHigh, fmt.Sprintf("%s added to group %s", a["user"], a["group"]), a["user"]+"/"+a["group"], ev, true); err != nil {
					return out, err
				}
			}
		case "password_changed":
			if mode != ModeLearn {
				if err := emit("auth.password_changed", SevMedium, "Password changed for "+a["user"], a["user"]+"/"+ev.Time.Format("2006-01-02T15"), ev, false); err != nil {
					return out, err
				}
			}
		case "su_session":
			key := "su/" + a["by"] + "->" + a["user"]
			known = append(known, store.BaselineItem{ID: "auth_known|" + key, Collector: "auth_known", Key: key})
			if mode != ModeLearn && !isKnown(key) && a["by"] != "" && a["by"] != "root" {
				if err := emit("auth.su_new", SevLow, fmt.Sprintf("%s switched to %s with su for the first time", a["by"], a["user"]), key, ev, false); err != nil {
					return out, err
				}
			}
		}
	}
	if len(known) > 0 {
		_ = d.st.UpsertBaseline(known, "auth")
	}
	// Bound memory for IPs that went quiet.
	for ip, ts := range d.failures {
		if len(ts) == 0 || now.Sub(ts[len(ts)-1]) > d.opts.BruteForceWindow {
			delete(d.failures, ip)
		}
	}
	return out, nil
}

func privileged(group string) bool {
	switch group {
	case "root", "sudo", "wheel", "adm", "docker", "lxd", "disk", "shadow":
		return true
	}
	return false
}

// ipPrefix is the /24 (IPv4) or /48 (IPv6) network of a login source, as a
// baseline key: "203.0.113.0/24", "2001:db8:abcd::/48". The address is
// parsed, so every spelling of one network ("2001:db8::1", "2001:db8:0:5::1",
// "2001:0db8::2") gives the same key, and an IPv4-mapped address counts as
// IPv4. A value that is not an address is returned as is.
func ipPrefix(ip string) string {
	addr := net.ParseIP(ip)
	if addr == nil {
		return ip
	}
	bits, size := 48, 128
	if v4 := addr.To4(); v4 != nil {
		addr, bits, size = v4, 24, 32
	}
	mask := net.CIDRMask(bits, size)
	return (&net.IPNet{IP: addr.Mask(mask), Mask: mask}).String()
}

func lower(sev string) string {
	switch sev {
	case SevHigh:
		return SevMedium
	case SevMedium:
		return SevLow
	}
	return sev
}

func fingerprint(rule, id string, kind ChangeKind, value string) string {
	h := sha256.Sum256([]byte(rule + "\x00" + id + "\x00" + string(kind) + "\x00" + value))
	return hex.EncodeToString(h[:12])
}

func hashShort(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:6])
}

func describe(ch change, v Verdict) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s [%s] %s: %s", strings.ToUpper(v.Severity), v.Rule, ch.kind, ch.item.Key)
	if ch.kind == ChangeChanged {
		fmt.Fprintf(&b, " (value %s -> %s)", ch.prev, ch.item.Value)
	}
	return b.String()
}

// matchAllow returns the first allow rule matching the item, if any.
func matchAllow(rules []store.AllowRule, it sensors.Item, rule string) *store.AllowRule {
	for i := range rules {
		r := &rules[i]
		if r.Collector != "*" && r.Collector != it.Collector {
			continue
		}
		if r.Rule != "" && r.Rule != rule {
			continue
		}
		if !Glob(r.KeyPattern, it.Key) {
			continue
		}
		if r.ValuePattern != "" && !Glob(r.ValuePattern, it.Value) {
			continue
		}
		return r
	}
	return nil
}

var globCache sync.Map

// Glob matches s against a pattern where * matches any run of characters
// (including '/') and ? matches one.
func Glob(pattern, s string) bool {
	if pattern == s || pattern == "*" {
		return true
	}
	if re, ok := globCache.Load(pattern); ok {
		return re.(*regexp.Regexp).MatchString(s)
	}
	var b strings.Builder
	b.WriteString("^")
	for _, r := range pattern {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return false
	}
	globCache.Store(pattern, re)
	return re.MatchString(s)
}

// GlobBreadth estimates how much a pattern matches: the number of literal
// characters. Allow rules proposed by models must stay narrow.
func GlobBreadth(pattern string) int {
	return len(strings.NewReplacer("*", "", "?", "").Replace(pattern))
}

// CheckAllowPattern reports why a key pattern a model proposed is too broad to
// become an allow rule, or nil. Beyond a literal anchor, a path pattern must
// name files, not a directory: "/etc/cron.d/*" or "/usr/local/bin/*" would
// let an attacker's next drop in a persistence or exec location through. Its
// final component needs a literal file-name prefix, and since * also matches
// '/', that prefix must not be the start of an existing subdirectory's name
// ("/usr/local/bin*" is "/usr/local/bin/*"). env may be nil (no such check).
func CheckAllowPattern(env *sensors.Env, pattern string) error {
	p := strings.TrimSpace(pattern)
	switch {
	case p == "":
		return fmt.Errorf("empty pattern")
	case strings.HasPrefix(p, "*") || strings.HasPrefix(p, "?"):
		return fmt.Errorf("pattern %q starts with a wildcard", p)
	case GlobBreadth(p) < 8:
		return fmt.Errorf("pattern %q keeps fewer than 8 literal characters", p)
	case strings.Contains(p, "/../") || strings.HasSuffix(p, "/..") || strings.Contains(p, "\x00"):
		return fmt.Errorf("pattern %q contains a parent-directory element or NUL", p)
	}
	if !strings.HasPrefix(p, "/") {
		return nil
	}
	// A path pattern must anchor to at least one fully literal directory
	// before any wildcard, so "/*/kworkerd" (any first-level directory) or
	// "/*/cron-update" cannot slip a drop into a persistence/exec location.
	comps := strings.Split(p, "/")
	firstWild := -1
	for i, c := range comps {
		if strings.ContainsAny(c, "*?") {
			firstWild = i
			break
		}
	}
	if firstWild >= 0 {
		literalDir := false
		for i := 1; i < firstWild; i++ {
			if comps[i] != "" {
				literalDir = true
				break
			}
		}
		if !literalDir {
			return fmt.Errorf("pattern %q wildcards the first directory: keep a literal directory before any wildcard", p)
		}
	}
	slash := strings.LastIndex(p, "/")
	dir, name := p[:slash], p[slash+1:]
	wi := strings.IndexAny(name, "*?")
	if wi < 0 {
		return nil // literal file name; wildcards only in directories above it
	}
	if strings.ContainsAny(dir, "*?") {
		return fmt.Errorf("pattern %q wildcards both a directory and the file name", p)
	}
	if wi < 3 {
		return fmt.Errorf("pattern %q covers a whole directory: keep at least 3 literal characters of the file name", p)
	}
	if env != nil {
		prefix := name[:wi]
		entries, _ := os.ReadDir(env.Path(dir))
		for _, e := range entries {
			if e.IsDir() && strings.HasPrefix(e.Name(), prefix) {
				return fmt.Errorf("pattern %q also matches everything under %s/%s", p, dir, e.Name())
			}
		}
	}
	return nil
}
