// Package monitor evaluates agent-authored monitors: small declarative checks
// the learner and reviewer create for what matters on *this* server (nginx is
// up, the app's admin endpoint is not exposed, the payments log has no auth
// errors spike). They run inside the daemon on a schedule and cost no tokens;
// only a confirmed failure becomes a finding.
package monitor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/hostexec"
	"github.com/Problem99-io/kodeblue/internal/blue/sensors"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

// Spec is the on-disk/JSON shape of a monitor.
type Spec struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Rationale   string `json:"rationale"`
	// Kind: command | file | log | http | process | port | sockets
	//
	// Paths, argv and the log path may name a process as {pid:<exe>} (for
	// example /proc/{pid:/usr/bin/node}/root/tmp): it is replaced by the PID of
	// the oldest running process with that executable, so the monitor keeps
	// working when the process restarts. That is how a monitor reaches a
	// workload kodeblue's sensors cannot see (another container's files or
	// network).
	Kind            string `json:"kind"`
	IntervalSeconds int    `json:"interval_seconds,omitempty"`
	Severity        string `json:"severity"`
	// ConsecutiveFailures before a finding (default 2) — the debounce that
	// keeps a single slow health check from paging anyone.
	ConsecutiveFailures int `json:"consecutive_failures,omitempty"`

	// command
	Argv          []string `json:"argv,omitempty"`
	ExpectExit    *int     `json:"expect_exit,omitempty"`
	ExpectMatch   string   `json:"expect_match,omitempty"`
	ExpectNoMatch string   `json:"expect_no_match,omitempty"`
	ValueRegex    string   `json:"value_regex,omitempty"` // first capture group parsed as number
	MaxValue      *float64 `json:"max_value,omitempty"`
	MinValue      *float64 `json:"min_value,omitempty"`
	ExpectStable  bool     `json:"expect_stable,omitempty"` // alert when output changes

	// file: a path may be a directory; then any new, removed or changed
	// entry in it (3 levels deep) is a change.
	Paths []string `json:"paths,omitempty"`
	Fast  bool     `json:"fast,omitempty"` // checked every few seconds, not every interval

	// log: Path may be a directory; then the most recently written file in
	// it (whose name matches FilePattern, when set) is followed, so a log
	// that rotates into a new name every day keeps being read. GroupBy is a
	// regex whose first capture group says who a line is about (a client
	// address, a user name): Threshold then counts per group, so one noisy
	// client cannot hide in a busy log. NewValues alerts the first time a
	// group value shows up in a matching line; values already in the log
	// when the monitor starts count as known, unless KnownValues lists the
	// known ones (an empty list: none), so a client the learner cannot
	// account for is not grandfathered in.
	Path          string    `json:"path,omitempty"`
	Pattern       string    `json:"pattern,omitempty"`
	Threshold     int       `json:"threshold,omitempty"`
	WindowSeconds int       `json:"window_seconds,omitempty"`
	FilePattern   string    `json:"file_pattern,omitempty"`
	GroupBy       string    `json:"group_by,omitempty"`
	NewValues     bool      `json:"new_values,omitempty"`
	KnownValues   *[]string `json:"known_values,omitempty"`

	// http
	URL          string `json:"url,omitempty"`
	ExpectStatus int    `json:"expect_status,omitempty"`

	// process: at least MinCount (default 1) and at most MaxCount (0 = no
	// limit) processes run ProcessExe. NoChildren fails when one of them has a
	// child process whose executable is not in AllowChildren: a service that
	// starts programs it never starts is how code execution through it shows.
	// sockets: ProcessExe picks the network namespace to read (empty =
	// kodeblue's own).
	ProcessExe    string   `json:"process_exe,omitempty"`
	MinCount      int      `json:"min_count,omitempty"`
	MaxCount      int      `json:"max_count,omitempty"`
	NoChildren    bool     `json:"no_children,omitempty"`
	AllowChildren []string `json:"allow_children,omitempty"`

	// sockets: ListenPorts is the exact set of TCP ports that should be
	// listening (empty = not checked). NoOutbound fails on any TCP connection
	// opened or being opened from this namespace (not an inbound connection to
	// one of its listeners) to an address outside AllowRemotes (IPs or CIDRs;
	// loopback is always allowed). Private addresses count: a connection to a
	// LAN host is still a connection the service should not make.
	ListenPorts  []int    `json:"listen_ports,omitempty"`
	NoOutbound   bool     `json:"no_outbound,omitempty"`
	AllowRemotes []string `json:"allow_remotes,omitempty"`

	// port
	Port  int    `json:"port,omitempty"`
	Proto string `json:"proto,omitempty"`

	// Contain makes the monitor act the moment it fails, before any agent
	// reads the finding: a process monitor with no_children kills the
	// unexpected processes (and what they started), a sockets monitor with
	// no_outbound kills the process holding the connection unless it is the
	// service itself, and a file monitor quarantines new files in its
	// directories. Each action goes through the response policy like an
	// agent's: off only journals what would have happened, recommend files a
	// request for approval, contain runs it. Contain monitors are checked on
	// every monitor tick.
	Contain bool `json:"contain,omitempty"`
}

// A Reflex is a containment action a failing monitor asks for on its own.
type Reflex struct {
	Action string
	Params map[string]string
	Why    string
}

var idRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)

// Validate checks a spec, compiling regexes and validating commands against
// the read-only allowlist.
func (s *Spec) Validate() error {
	if !idRe.MatchString(s.ID) {
		return errors.New("id must be lowercase letters, digits and dashes (2-63 chars)")
	}
	if strings.TrimSpace(s.Description) == "" || strings.TrimSpace(s.Rationale) == "" {
		return errors.New("description and rationale are required")
	}
	switch s.Severity {
	case "low", "medium", "high", "critical":
	default:
		return errors.New("severity must be low|medium|high|critical")
	}
	if s.IntervalSeconds == 0 {
		s.IntervalSeconds = 300
	}
	// Process and socket checks only read /proc and log checks only the
	// lines written since the last run, so they may run often.
	minInterval := 30
	if s.Kind == "process" || s.Kind == "sockets" || s.Kind == "log" {
		minInterval = 10
	}
	if s.IntervalSeconds < minInterval {
		return fmt.Errorf("interval_seconds must be >= %d for %s monitors", minInterval, s.Kind)
	}
	if s.ConsecutiveFailures == 0 {
		s.ConsecutiveFailures = 2
	}
	for _, re := range []string{s.ExpectMatch, s.ExpectNoMatch, s.ValueRegex, s.Pattern} {
		if re != "" {
			if _, err := regexp.Compile(re); err != nil {
				return fmt.Errorf("bad regex %q: %v", re, err)
			}
		}
	}
	for _, p := range append(append(append([]string{}, s.Argv...), s.Paths...), s.Path) {
		if err := checkNoFixedPID(p); err != nil {
			return err
		}
	}
	switch s.Kind {
	case "command":
		if err := hostexec.Validate(s.Argv); err != nil {
			return err
		}
		if s.ExpectExit == nil && s.ExpectMatch == "" && s.ExpectNoMatch == "" && s.MaxValue == nil && s.MinValue == nil && !s.ExpectStable {
			return errors.New("command monitor needs at least one expectation (expect_exit, expect_match, expect_no_match, max_value/min_value with value_regex, expect_stable)")
		}
		if (s.MaxValue != nil || s.MinValue != nil) && s.ValueRegex == "" {
			return errors.New("max_value/min_value need value_regex with one capture group")
		}
	case "file":
		if len(s.Paths) == 0 {
			return errors.New("file monitor needs paths")
		}
		for _, p := range s.Paths {
			if !strings.HasPrefix(p, "/") || hostexec.IsSecretPath(p) {
				return fmt.Errorf("path %q must be absolute and not a secret path", p)
			}
		}
	case "log":
		if s.NewValues && s.Threshold == 0 {
			s.Threshold = 1
		}
		if s.Path == "" || s.Pattern == "" || s.Threshold < 1 {
			return errors.New("log monitor needs path, pattern and threshold >= 1")
		}
		// Matching lines reach findings and monitor_test's output, so a log
		// monitor may not read a secret. The file it resolves to is checked
		// again before every read (logFile), for directories and {pid:…}.
		if hostexec.IsSecretPath(s.Path) {
			return fmt.Errorf("path %q is a secret path", s.Path)
		}
		if s.WindowSeconds == 0 {
			s.WindowSeconds = 300
		}
		if err := validLogRegexes(*s); err != nil {
			return err
		}
	case "http":
		u, err := url.Parse(s.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return errors.New("http monitor needs an http(s) url")
		}
		if err := localOnly(u.Hostname()); err != nil {
			return err
		}
		if s.ExpectStatus == 0 {
			s.ExpectStatus = 200
		}
	case "process":
		if s.ProcessExe == "" {
			return errors.New("process monitor needs process_exe")
		}
		if s.MinCount == 0 {
			s.MinCount = 1
		}
		if s.MaxCount != 0 && s.MaxCount < s.MinCount {
			return errors.New("max_count must be >= min_count")
		}
	case "port":
		if s.Port <= 0 || s.Port > 65535 {
			return errors.New("port monitor needs port")
		}
		if s.Proto == "" {
			s.Proto = "tcp"
		}
	case "sockets":
		if len(s.ListenPorts) == 0 && !s.NoOutbound {
			return errors.New("sockets monitor needs listen_ports or no_outbound")
		}
		for _, port := range s.ListenPorts {
			if port <= 0 || port > 65535 {
				return fmt.Errorf("listen_ports: %d is not a port", port)
			}
		}
		if _, err := parseRemotes(s.AllowRemotes); err != nil {
			return err
		}
	default:
		return errors.New("kind must be command|file|log|http|process|port|sockets")
	}
	if s.Contain {
		switch {
		case s.Kind == "process" && s.NoChildren, s.Kind == "sockets" && s.NoOutbound, s.Kind == "file":
		default:
			return errors.New("contain works on process monitors with no_children, sockets monitors with no_outbound and file monitors")
		}
	}
	return nil
}

// localOnly keeps http monitors from becoming an exfiltration channel: they
// may only reach this host or private addresses.
func localOnly(host string) error {
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("cannot resolve %s: %v", host, err)
	}
	for _, ip := range ips {
		if !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()) {
			return fmt.Errorf("http monitors may only target this host or private addresses (%s is %s)", host, ip)
		}
	}
	return nil
}

// Runner evaluates monitors on their schedule.
type Runner struct {
	st   *store.Store
	env  *sensors.Env
	run  sync.Mutex // one RunDue at a time: the sweep and the monitor loop both call it
	mu   sync.Mutex
	fail map[string]int
	logs map[string][]time.Time

	reMu sync.Mutex
	res  map[string]*regexp.Regexp

	// Containment targets the last eval found (guarded by run), the hook that
	// acts on them, and when each target was last handed to it.
	targets []Reflex
	reflex  func(Spec, *store.Finding, []Reflex) string
	tried   map[string]time.Time
}

func NewRunner(st *store.Store, env *sensors.Env) *Runner {
	return &Runner{st: st, env: env, fail: map[string]int{}, logs: map[string][]time.Time{}, res: map[string]*regexp.Regexp{}, tried: map[string]time.Time{}}
}

// OnReflex sets what a failing contain monitor does with its targets. The
// hook returns a summary of what happened, which goes into the finding.
func (r *Runner) OnReflex(fn func(Spec, *store.Finding, []Reflex) string) {
	r.run.Lock()
	defer r.run.Unlock()
	r.reflex = fn
}

// fresh drops targets handed to the hook in the last ten minutes, so a
// monitor that keeps failing does not ask for the same action every tick.
func (r *Runner) fresh(in []Reflex) []Reflex {
	now := time.Now()
	for k, t := range r.tried {
		if now.Sub(t) > 10*time.Minute {
			delete(r.tried, k)
		}
	}
	var out []Reflex
	for _, x := range in {
		k := x.Action + "|" + x.Params["pid"] + "|" + x.Params["expect_exe"] + "|" + x.Params["path"]
		if _, ok := r.tried[k]; ok {
			continue
		}
		r.tried[k] = now
		out = append(out, x)
	}
	return out
}

// re compiles a monitor pattern once. Specs are validated when saved, so
// an error means a spec that was edited by hand.
func (r *Runner) re(pattern string) (*regexp.Regexp, error) {
	r.reMu.Lock()
	defer r.reMu.Unlock()
	if re, ok := r.res[pattern]; ok {
		return re, nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("bad pattern /%s/: %w", pattern, err)
	}
	r.res[pattern] = re
	return re, nil
}

// Specs returns all enabled specs.
func (r *Runner) Specs() []Spec {
	var out []Spec
	for _, row := range r.st.Monitors(false) {
		var s Spec
		if json.Unmarshal(row.Spec, &s) == nil {
			out = append(out, s)
		}
	}
	return out
}

// FastPaths returns the file paths monitors asked to be watched quickly.
func (r *Runner) FastPaths() []string {
	var out []string
	for _, s := range r.Specs() {
		if s.Kind == "file" && s.Fast {
			if paths, err := r.expandAll(s.Paths); err == nil {
				out = append(out, paths...)
			}
		}
	}
	return out
}

// RunDue evaluates every monitor whose interval elapsed (or all if force),
// returning new findings for confirmed failures. Recoveries close the open
// finding automatically.
func (r *Runner) RunDue(ctx context.Context, force bool) []*store.Finding {
	r.run.Lock()
	defer r.run.Unlock()
	var out []*store.Finding
	for _, row := range r.st.Monitors(false) {
		var s Spec
		if err := json.Unmarshal(row.Spec, &s); err != nil {
			continue
		}
		if s.IntervalSeconds <= 0 {
			s.IntervalSeconds = 300
		}
		// Fast file monitors run on every sweep: the fast watcher wakes a
		// sweep the moment one of their paths changes.
		fast := s.Kind == "file" && s.Fast || s.Contain
		if !force && !fast && time.Since(row.LastRun) < time.Duration(s.IntervalSeconds)*time.Second {
			continue
		}
		r.targets = nil
		ok, output := r.eval(ctx, s)
		r.st.RecordMonitorRun(s.ID, ok, output)
		fp := "monitor:" + s.ID
		r.mu.Lock()
		if ok {
			r.fail[s.ID] = 0
			r.mu.Unlock()
			if f := r.st.OpenFinding(fp); f != nil && f.Status == "digest" {
				_ = r.st.SetFindingStatus(f.ID, "closed", "recovered", "monitor passing again", 0)
			}
			if s.condition() {
				r.clear(s, fp)
			}
			continue
		}
		r.fail[s.ID]++
		n := r.fail[s.ID]
		r.mu.Unlock()
		if row.LastOK && s.condition() {
			// A new failure streak. Which finding reported the streak is kept
			// in the store, so a restart does not make the failure look new.
			_ = r.st.Set(streakKey(s.ID), "")
		}
		need := s.ConsecutiveFailures
		if need <= 0 {
			need = 2
		}
		if n < need {
			continue
		}
		var targets []Reflex
		if s.Contain && r.reflex != nil {
			targets = r.fresh(r.targets)
		}
		if f := r.st.OpenFinding(fp); f != nil {
			r.st.BumpFinding(f.ID)
			if len(targets) > 0 {
				r.reflex(s, f, targets)
			}
			if s.condition() && !r.sameStreak(s.ID, f) {
				_ = r.st.Set(streakKey(s.ID), strconv.FormatInt(f.ID, 10))
			}
			continue
		}
		if s.condition() {
			// Still the failure reported when this streak began (or, after a
			// restart, one whose incident waits for a human). Its verdict
			// stands until the monitor passes again: one incident, not a new
			// one (and a new session) every interval.
			if f := r.st.LastFinding(fp); f != nil && (n > need || r.sameStreak(s.ID, f) || len(r.waiting(fp)) > 0) {
				r.st.BumpFinding(f.ID)
				continue
			}
		}
		title := "Monitor alert: "
		if s.condition() {
			title = "Monitor failing: "
		}
		f := &store.Finding{
			Fingerprint: fp, Collector: "monitor", Rule: "monitor." + s.ID, Severity: s.Severity,
			Title:    title + s.Description,
			Detail:   fmt.Sprintf("%s failed %d consecutive checks. Rationale: %s", s.ID, n, s.Rationale),
			Evidence: map[string]string{"output": truncate(output, 1500), "kind": s.Kind, "monitor_id": s.ID},
		}
		if len(targets) > 0 {
			f.Evidence["contained"] = truncate(r.reflex(s, f, targets), 1500)
		}
		if err := r.st.AddFinding(f); err == nil {
			out = append(out, f)
			if s.condition() {
				_ = r.st.Set(streakKey(s.ID), strconv.FormatInt(f.ID, 10))
			}
		}
	}
	return out
}

// condition reports whether a failure is a standing condition that lasts
// until someone fixes it (a service is down, a file that should be gone is
// still there). The other monitors report events: a change, a log burst, a
// child process, an outbound connection. Those pass again on the next check
// while what they saw still needs looking at.
func (s Spec) condition() bool {
	switch s.Kind {
	case "command":
		return !s.ExpectStable
	case "http", "port":
		return true
	case "process":
		return !s.NoChildren
	case "sockets":
		return !s.NoOutbound
	}
	return false
}

// waiting returns the incidents holding the monitor's findings that are
// left for a human.
func (r *Runner) waiting(fp string) []store.Incident {
	return r.st.Incidents(`WHERE status='needs_human' AND id IN (SELECT incident_id FROM findings WHERE fingerprint=?) ORDER BY id`, fp)
}

func streakKey(id string) string { return "monitor_streak_finding:" + id }

// sameStreak reports whether f reported the monitor's current failure streak.
func (r *Runner) sameStreak(id string, f *store.Finding) bool {
	return r.st.Get(streakKey(id)) == strconv.FormatInt(f.ID, 10)
}

// clear resolves the incidents a condition monitor opened once the
// condition is gone, so they do not stay open saying the monitor fails. An
// incident that also holds anything else stays for a human.
func (r *Runner) clear(s Spec, fp string) {
	open := r.waiting(fp)
	if len(open) == 0 {
		return
	}
	rows := map[string]store.MonitorRow{}
	for _, m := range r.st.Monitors(false) {
		rows[m.ID] = m
	}
	passing := func(g store.Finding) bool {
		m, ok := rows[g.Evidence["monitor_id"]]
		var gs Spec
		return g.Collector == "monitor" && ok && m.LastOK && json.Unmarshal(m.Spec, &gs) == nil && gs.condition()
	}
next:
	for _, in := range open {
		for _, g := range r.st.FindingsForIncident(in.ID) {
			if !passing(g) {
				continue next
			}
		}
		in.Status = "resolved"
		in.Summary = fmt.Sprintf("Cleared %s: monitor %s passes again. %s", time.Now().UTC().Format(time.RFC3339), s.ID, in.Summary)
		if err := r.st.UpdateIncident(&in); err == nil {
			r.st.Journal("kodeblue", "incident.cleared", fmt.Sprintf("#%d: monitor %s passes again", in.ID, s.ID))
		}
	}
}

// eval runs one check. Its output reaches findings, the hub and the model,
// so it gets host_exec's redaction whatever the kind read.
func (r *Runner) eval(ctx context.Context, s Spec) (bool, string) {
	ok, out := r.evalKind(ctx, s)
	return ok, hostexec.Redact(out)
}

func (r *Runner) evalKind(ctx context.Context, s Spec) (bool, string) {
	switch s.Kind {
	case "command":
		argv, err := r.expandAll(s.Argv)
		if err != nil {
			return false, err.Error()
		}
		res, err := hostexec.Run(ctx, argv, 20*time.Second, 32*1024)
		if err != nil {
			return false, "error: " + err.Error()
		}
		out := res.Stdout
		if s.ExpectExit != nil && res.ExitCode != *s.ExpectExit {
			return false, fmt.Sprintf("exit %d (expected %d): %s", res.ExitCode, *s.ExpectExit, truncate(out+res.Stderr, 800))
		}
		if s.ExpectMatch != "" {
			re, err := r.re(s.ExpectMatch)
			if err != nil {
				return false, err.Error()
			}
			if !re.MatchString(out) {
				return false, "expected match /" + s.ExpectMatch + "/ not found: " + truncate(out, 800)
			}
		}
		if s.ExpectNoMatch != "" {
			re, err := r.re(s.ExpectNoMatch)
			if err != nil {
				return false, err.Error()
			}
			if loc := re.FindStringIndex(out); loc != nil && loc[1] > loc[0] {
				// The whole line: a pattern like "." matches one character.
				return false, "forbidden match /" + s.ExpectNoMatch + "/: " + truncate(lineAt(out, loc), 400)
			}
		}
		if s.ValueRegex != "" && (s.MaxValue != nil || s.MinValue != nil) {
			re, err := r.re(s.ValueRegex)
			if err != nil {
				return false, err.Error()
			}
			m := re.FindStringSubmatch(out)
			if len(m) < 2 {
				return false, "value_regex did not match: " + truncate(out, 400)
			}
			v, err := strconv.ParseFloat(strings.TrimSpace(m[1]), 64)
			if err != nil {
				return false, "value not numeric: " + m[1]
			}
			if s.MaxValue != nil && v > *s.MaxValue {
				return false, fmt.Sprintf("value %v > max %v", v, *s.MaxValue)
			}
			if s.MinValue != nil && v < *s.MinValue {
				return false, fmt.Sprintf("value %v < min %v", v, *s.MinValue)
			}
		}
		if s.ExpectStable {
			h := hashStr(out)
			key := "monitor_hash:" + s.ID
			prev := r.st.Get(key)
			if prev == "" {
				_ = r.st.Set(key, h)
			} else if prev != h {
				// Report once, then accept the new output as the reference.
				_ = r.st.Set(key, h)
				r.mu.Lock()
				r.fail[s.ID] = s.ConsecutiveFailures - 1
				r.mu.Unlock()
				return false, "output changed: " + truncate(out, 1000)
			}
		}
		return true, truncate(out, 300)
	case "file":
		var changed []string
		for _, p := range s.Paths {
			real, err := r.expand(p)
			if err != nil {
				return false, err.Error()
			}
			h, listing := r.fileState(r.env.Path(real))
			key := "monitor_file:" + s.ID + ":" + p
			prev := r.st.Get(key)
			prevListing := r.st.Get(key + ":ls")
			_ = r.st.Set(key+":ls", listing)
			// Before directories were listed, a directory hashed as
			// "unreadable"; the first listing is a baseline, not a change.
			if prev == "" || prev == "unreadable" && strings.HasPrefix(h, "dir:") {
				_ = r.st.Set(key, h)
				continue
			}
			if prev != h {
				_ = r.st.Set(key, h)
				what := p
				if d := diffListings(splitLines(prevListing), splitLines(listing)); d != "" {
					what += " (" + d + ")"
				}
				// Show what was written, so a grown log is judged by its new
				// lines, not by the fact that it grew.
				if a := appended(r.env.Path(real), splitLines(prevListing), splitLines(listing)); a != "" {
					what += "; " + a
				}
				changed = append(changed, what)
				for _, rel := range newFiles(splitLines(prevListing), splitLines(listing)) {
					r.targets = append(r.targets, Reflex{
						Action: "quarantine_file", Params: map[string]string{"path": real + "/" + rel},
						Why: fmt.Sprintf("new file %s appeared in %s", rel, p),
					})
				}
			}
		}
		if len(changed) > 0 {
			r.mu.Lock()
			r.fail[s.ID] = s.ConsecutiveFailures - 1 // file changes are instant
			r.mu.Unlock()
			return false, "changed: " + strings.Join(changed, ", ")
		}
		return true, "unchanged"
	case "log":
		return r.evalLog(s)
	case "http":
		u, _ := url.Parse(s.URL)
		if err := localOnly(u.Hostname()); err != nil {
			return false, err.Error()
		}
		c := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, s.URL, nil)
		resp, err := c.Do(req)
		if err != nil {
			return false, "request failed: " + err.Error()
		}
		resp.Body.Close()
		if resp.StatusCode != s.ExpectStatus {
			return false, fmt.Sprintf("status %d (expected %d)", resp.StatusCode, s.ExpectStatus)
		}
		return true, resp.Status
	case "process":
		ok, out, t := r.evalProcess(s)
		r.targets = t
		return ok, out
	case "sockets":
		ok, out, t := r.evalSockets(s)
		r.targets = t
		return ok, out
	case "port":
		reg := sensors.NewRegistry([]string{"listener"}, nil)
		snap := reg.Sweep(ctx, r.env, true)
		prefix := fmt.Sprintf("%s/%d/", s.Proto, s.Port)
		for _, it := range snap.Items {
			if strings.HasPrefix(it.Key, prefix) {
				return true, it.Key
			}
		}
		return false, fmt.Sprintf("nothing listening on %s/%d", s.Proto, s.Port)
	}
	return false, "unknown kind"
}

func hashStr(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:12])
}

// fileState hashes a file, or for a directory its listing, which it also
// returns so a change can say which entries are new, changed or removed.
func (r *Runner) fileState(p string) (hash, listing string) {
	if st, err := os.Stat(p); err == nil && st.IsDir() && !hostexec.IsSecretPath(p) {
		ls := strings.Join(dirListing(p), "\n")
		return "dir:" + hashStr(ls), ls
	}
	return hashPath(p), ""
}

// lineAt returns the line(s) of s holding the match at loc.
func lineAt(s string, loc []int) string {
	start := strings.LastIndexByte(s[:loc[0]], '\n') + 1
	end := len(s)
	if i := strings.IndexByte(s[loc[1]:], '\n'); i >= 0 {
		end = loc[1] + i
	}
	return s[start:end]
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func hashPath(p string) string {
	if hostexec.IsSecretPath(p) {
		return "secret"
	}
	f, err := os.Open(p)
	if err != nil {
		return "missing"
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "unreadable"
	}
	return hex.EncodeToString(h.Sum(nil)[:12])
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
