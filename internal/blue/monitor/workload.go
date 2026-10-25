package monitor

import (
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Problem99-io/kodeblue/internal/blue/hostexec"
	"github.com/Problem99-io/kodeblue/internal/blue/sensors"
)

var pidRefRe = regexp.MustCompile(`\{pid:([^}]+)\}`)

// fixedPIDRe finds /proc/<pid>/ for a PID other than 1: such a monitor breaks
// the first time that process restarts. PID 1 (init, or a container's main
// process) does not change.
var fixedPIDRe = regexp.MustCompile(`/proc/([0-9]+)(/|$)`)

func checkNoFixedPID(s string) error {
	for _, m := range fixedPIDRe.FindAllStringSubmatch(s, -1) {
		if m[1] != "1" {
			return fmt.Errorf("%s names process %s by PID, which changes when it restarts: write /proc/{pid:<exe>}/… instead", s, m[1])
		}
	}
	return nil
}

// expand replaces each {pid:<exe>} in s with the PID of the oldest running
// process with that executable.
func (r *Runner) expand(s string) (string, error) {
	if !strings.Contains(s, "{pid:") {
		return s, nil
	}
	procs, err := sensors.Processes(r.env)
	if err != nil {
		return "", err
	}
	var missing string
	out := pidRefRe.ReplaceAllStringFunc(s, func(m string) string {
		exe := pidRefRe.FindStringSubmatch(m)[1]
		if pid := oldest(procs, exe); pid > 0 {
			return fmt.Sprint(pid)
		}
		missing = exe
		return m
	})
	if missing != "" {
		return "", fmt.Errorf("no running process %s", missing)
	}
	return out, nil
}

func (r *Runner) expandAll(in []string) ([]string, error) {
	out := make([]string, len(in))
	for i, s := range in {
		e, err := r.expand(s)
		if err != nil {
			return nil, err
		}
		out[i] = e
	}
	return out, nil
}

// oldest is the lowest PID running exe (the service, not a worker it forked).
func oldest(procs []sensors.Process, exe string) int {
	best := 0
	for _, p := range procs {
		if exeOf(p) == exe && p.State != "Z" && (best == 0 || p.PID < best) {
			best = p.PID
		}
	}
	return best
}

// exeOf names a process the way the process sensor does: its executable,
// or comm:<name> when the executable cannot be read.
func exeOf(p sensors.Process) string {
	if p.Exe == "" {
		return "comm:" + p.Comm
	}
	return p.Exe
}

func parseRemotes(in []string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, r := range in {
		r = strings.TrimSpace(r)
		if !strings.Contains(r, "/") {
			ip := net.ParseIP(r)
			if ip == nil {
				return nil, fmt.Errorf("allow_remotes: %q is not an IP or CIDR", r)
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			r = fmt.Sprintf("%s/%d", ip, bits)
		}
		_, n, err := net.ParseCIDR(r)
		if err != nil {
			return nil, fmt.Errorf("allow_remotes: %q is not an IP or CIDR", r)
		}
		out = append(out, n)
	}
	return out, nil
}

// evalProcess counts the processes running s.ProcessExe and, with
// NoChildren, looks for children they should not have.
func (r *Runner) evalProcess(s Spec) (bool, string, []Reflex) {
	procs, err := sensors.Processes(r.env)
	if err != nil {
		return false, "cannot list processes: " + err.Error(), nil
	}
	mine := map[int]bool{}
	for _, p := range procs {
		if exeOf(p) == s.ProcessExe && p.State != "Z" {
			mine[p.PID] = true
		}
	}
	n := len(mine)
	if n < s.MinCount {
		return false, fmt.Sprintf("%s: %d running (need %d)", s.ProcessExe, n, s.MinCount), nil
	}
	if s.MaxCount > 0 && n > s.MaxCount {
		return false, fmt.Sprintf("%s: %d running (at most %d expected)", s.ProcessExe, n, s.MaxCount), nil
	}
	if s.NoChildren {
		allowed := map[string]bool{}
		for _, a := range s.AllowChildren {
			allowed[a] = true
		}
		// The service is each process whose parent is not itself running
		// ProcessExe. Any child of it counts, the same program included: a
		// service re-executing its own interpreter is how code execution
		// through it often looks. Workers it legitimately forks go in
		// allow_children (its own executable, for a forking server).
		roots := map[int]bool{}
		for _, p := range procs {
			if mine[p.PID] && !mine[p.PPID] {
				roots[p.PID] = true
			}
		}
		own := sensors.OwnProcesses(procs)
		var bad []string
		var targets []Reflex
		live, zombies, mine := 0, 0, 0
		for _, p := range procs {
			if !roots[p.PPID] {
				continue
			}
			switch {
			case p.State == "Z":
				zombies++
				continue
			case own[p.PID]:
				mine++
				continue
			}
			live++
			if allowed[exeOf(p)] {
				continue
			}
			bad = append(bad, fmt.Sprintf("pid %d (parent %d) %s: %s", p.PID, p.PPID, p.Exe, truncate(p.Cmdline, 200)))
			// What it started goes first, so nothing it spawned is left
			// running with a new parent.
			why := fmt.Sprintf("%s (pid %d) started %s (pid %d): %s", s.ProcessExe, p.PPID, p.Exe, p.PID, truncate(p.Cmdline, 200))
			for _, d := range descendants(procs, p.PID) {
				targets = append(targets, killReflex(d, "started by "+why))
			}
			targets = append(targets, killReflex(p, why))
		}
		if len(bad) > 0 {
			return false, fmt.Sprintf("%s started %d unexpected process(es): %s", s.ProcessExe, len(bad), strings.Join(bad, "; ")), targets
		}
		// Say what was ignored, so whoever writes allow_children sees that
		// zombies and kodeblue's own processes need no entry.
		return true, fmt.Sprintf("%d running; %d live child process(es), all allowed; ignored %d zombie(s) and %d of kodeblue's own", n, live, zombies, mine), nil
	}
	return true, fmt.Sprintf("%d running", n), nil
}

// descendants lists every live process below pid, deepest first.
func descendants(procs []sensors.Process, pid int) []sensors.Process {
	kids := map[int][]sensors.Process{}
	for _, p := range procs {
		kids[p.PPID] = append(kids[p.PPID], p)
	}
	var out []sensors.Process
	var walk func(int, int)
	walk = func(pid, depth int) {
		if depth > 32 {
			return
		}
		for _, c := range kids[pid] {
			walk(c.PID, depth+1)
			if c.State != "Z" {
				out = append(out, c)
			}
		}
	}
	walk(pid, 0)
	return out
}

// killReflex asks to kill p. The monitor's own evidence names the process,
// which is what lets the helper kill even a packaged program (a shell).
func killReflex(p sensors.Process, why string) Reflex {
	return Reflex{
		Action: "kill_process",
		Params: map[string]string{"pid": fmt.Sprint(p.PID), "expect_exe": p.Exe, "incident_linked": "true"},
		Why:    why,
	}
}

// evalSockets checks the listeners and connections of one network namespace.
func (r *Runner) evalSockets(s Spec) (bool, string, []Reflex) {
	procs, err := sensors.Processes(r.env)
	if err != nil {
		return false, "cannot list processes: " + err.Error(), nil
	}
	var socks []sensors.Socket
	where := "kodeblue's network namespace"
	service := 0
	if s.ProcessExe != "" {
		pid := oldest(procs, s.ProcessExe)
		if pid == 0 {
			return false, "no running process " + s.ProcessExe, nil
		}
		service = pid
		socks = sensors.SocketsOf(r.env, pid)
		where = fmt.Sprintf("the network namespace of %s (pid %d)", s.ProcessExe, pid)
	} else {
		socks = sensors.SocketsOf(r.env, os.Getpid())
	}
	// kodeblue's own sockets are not the service's when it shares the
	// service's network namespace (a sidecar): its links to the hub and the
	// model API, and the engine's local API on a random port. Nor is the
	// resolver Docker serves on a random port from outside the container.
	owners := sensors.SocketOwners(r.env, procs)
	own := sensors.OwnProcesses(procs)
	ours := func(k sensors.Socket) bool {
		o, ok := owners[k.Inode]
		return ok && own[o.PID]
	}
	listening := map[int]bool{}
	for _, k := range socks {
		if k.Proto == "tcp" && k.State == "0A" && !ours(k) && k.LocalIP.String() != sensors.DockerDNS {
			listening[k.LocalPort] = true
		}
	}
	var problems []string
	if len(s.ListenPorts) > 0 {
		want := map[int]bool{}
		for _, p := range s.ListenPorts {
			want[p] = true
			if !listening[p] {
				problems = append(problems, fmt.Sprintf("nothing listening on tcp/%d", p))
			}
		}
		var extra []int
		for p := range listening {
			if !want[p] {
				extra = append(extra, p)
			}
		}
		sort.Ints(extra)
		for _, p := range extra {
			problems = append(problems, fmt.Sprintf("unexpected listener on tcp/%d", p))
		}
	}
	var targets []Reflex
	if s.NoOutbound {
		allow, _ := parseRemotes(s.AllowRemotes)
		for _, k := range socks {
			// 01 established, 02 SYN sent: a connection made or being made.
			if k.Proto != "tcp" || (k.State != "01" && k.State != "02") || k.RemoteIP == nil || ours(k) {
				continue
			}
			if listening[k.LocalPort] || k.RemoteIP.IsLoopback() || inNets(k.RemoteIP, allow) {
				continue
			}
			state := "connected to"
			if k.State == "02" {
				state = "connecting to"
			}
			o, ok := owners[k.Inode]
			who := "unknown process"
			if ok && o.Exe != "" {
				who = fmt.Sprintf("%s (pid %d)", o.Exe, o.PID)
			}
			problem := fmt.Sprintf("%s %s %s:%d", who, state, k.RemoteIP, k.RemotePort)
			problems = append(problems, problem)
			// Killing the service itself (or init) would take the server
			// down; that is a decision for the responder.
			if ok && o.Exe != "" && o.PID > 1 && o.PID != service {
				for _, d := range descendants(procs, o.PID) {
					targets = append(targets, killReflex(d, "started by "+problem))
				}
				targets = append(targets, killReflex(o, problem))
			}
		}
	}
	if len(problems) > 0 {
		return false, "in " + where + ": " + strings.Join(problems, "; "), targets
	}
	return true, fmt.Sprintf("%d listeners as expected, no unexpected connections", len(listening)), nil
}

func inNets(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// dirListing lists a directory tree (3 levels, 2000 entries) as
// "path size mode mtime" lines, so any new, removed or changed entry changes
// the listing.
func dirListing(root string) []string {
	var out []string
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || path == root {
			return nil
		}
		rel := strings.TrimPrefix(path, root+"/")
		if d.IsDir() && strings.Count(rel, "/") >= 2 {
			return filepath.SkipDir
		}
		if len(out) >= 2000 {
			return filepath.SkipAll
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		out = append(out, fmt.Sprintf("%s\t%d\t%o\t%d", rel, info.Size(), info.Mode(), info.ModTime().UnixNano()))
		return nil
	})
	sort.Strings(out)
	return out
}

// newFiles lists the regular files in cur that were not in prev.
func newFiles(prev, cur []string) []string {
	old := map[string]bool{}
	for _, l := range prev {
		n, _, _ := strings.Cut(l, "\t")
		old[n] = true
	}
	var out []string
	for _, l := range cur {
		f := strings.Split(l, "\t")
		if len(f) != 4 || old[f[0]] {
			continue
		}
		mode, err := strconv.ParseUint(f[2], 8, 32)
		if err != nil || fs.FileMode(mode)&fs.ModeType != 0 {
			continue
		}
		out = append(out, f[0])
	}
	return out
}

// appended returns the text added to files in root that grew between two
// listings (the tail of it, up to 1200 bytes in all), as "appended to
// <name>: <text>" parts.
func appended(root string, prev, cur []string) string {
	old := map[string][]string{}
	for _, l := range prev {
		f := strings.Split(l, "\t")
		if len(f) == 4 {
			old[f[0]] = f
		}
	}
	var parts []string
	budget := 1200
	for _, l := range cur {
		f := strings.Split(l, "\t")
		p, ok := old[f[0]]
		if len(f) != 4 || !ok || budget <= 0 {
			continue
		}
		mode, err := strconv.ParseUint(f[2], 8, 32)
		if err != nil || fs.FileMode(mode)&fs.ModeType != 0 {
			continue
		}
		before, err1 := strconv.ParseInt(p[1], 10, 64)
		after, err2 := strconv.ParseInt(f[1], 10, 64)
		if err1 != nil || err2 != nil || after <= before {
			continue
		}
		from := before
		if after-from > int64(budget) {
			from = after - int64(budget)
		}
		full := filepath.Join(root, f[0])
		if hostexec.IsSecretPath(full) {
			continue
		}
		b, err := readRange(full, from, after-from)
		if err != nil || len(b) == 0 {
			continue
		}
		budget -= len(b)
		text := hostexec.Redact(strings.TrimSpace(string(b)))
		if from > before {
			text = "… " + text
		}
		parts = append(parts, "appended to "+f[0]+": "+text)
	}
	return strings.Join(parts, "; ")
}

func readRange(path string, off, n int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b := make([]byte, n)
	k, err := f.ReadAt(b, off)
	if k > 0 {
		return b[:k], nil
	}
	return nil, err
}

// diffListings names what was added, removed or changed between listings.
func diffListings(prev, cur []string) string {
	name := func(l string) string { n, _, _ := strings.Cut(l, "\t"); return n }
	old := map[string]string{}
	for _, l := range prev {
		old[name(l)] = l
	}
	var added, changed []string
	seen := map[string]bool{}
	for _, l := range cur {
		n := name(l)
		seen[n] = true
		switch p, ok := old[n]; {
		case !ok:
			added = append(added, n)
		case p != l:
			changed = append(changed, n)
		}
	}
	var removed []string
	for n := range old {
		if !seen[n] {
			removed = append(removed, n)
		}
	}
	sort.Strings(removed)
	var parts []string
	for _, g := range []struct {
		label string
		names []string
	}{{"new", added}, {"changed", changed}, {"removed", removed}} {
		if len(g.names) == 0 {
			continue
		}
		if len(g.names) > 10 {
			g.names = append(g.names[:10], fmt.Sprintf("… %d more", len(g.names)-10))
		}
		parts = append(parts, g.label+": "+strings.Join(g.names, ", "))
	}
	return strings.Join(parts, "; ")
}
