package sensors

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
)

// Coverage says how much of the server one sensor can see from where kodeblue
// runs. A sensor reads one network namespace (kodeblue's) and one filesystem
// (the configured root); processes whose network or root differ are invisible
// to it. Agents use the report to cover the gaps with monitors.
type Coverage struct {
	Collector string `json:"collector"`
	// Status is ok, partial (sees some of the server), blind (sees none of
	// what runs here besides kodeblue), degraded (its input shows activity
	// it cannot parse) or unavailable (its input does not exist on this
	// server).
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
	// Limits is what the sensor never sees, by design, wherever it runs.
	Limits string `json:"limits,omitempty"`
	// ReplaceWith says which monitors cover what the sensor misses.
	ReplaceWith string `json:"replace_with,omitempty"`
	// Unseen lists, one per network namespace or root, the processes whose
	// sockets or files this sensor cannot see.
	Unseen []Unseen `json:"unseen,omitempty"`
}

// Unseen is a group of processes sharing a network namespace or root that a
// sensor cannot see, named by its lowest-PID process.
type Unseen struct {
	PID       int    `json:"pid"`
	Exe       string `json:"exe"`
	Cmdline   string `json:"cmdline,omitempty"`
	Processes int    `json:"processes"`
	// Path is where the group can still be reached: /proc/<pid>/root for
	// files, /proc/<pid>/net for sockets.
	Path string `json:"path"`
}

// Coverage status values.
const (
	CoverageOK          = "ok"
	CoveragePartial     = "partial"
	CoverageBlind       = "blind"
	CoverageDegraded    = "degraded"
	CoverageUnavailable = "unavailable"
)

// CollectorNames lists every collector, in registry order.
func CollectorNames() []string { return NewRegistry(nil, nil).Names() }

// view is what kodeblue can and cannot see of the other processes.
type view struct {
	others        int // processes that are not kodeblue's own
	exeUnreadable int
	fdUnreadable  int
	netOwn        int
	netForeign    []Unseen
	rootOwn       int
	rootForeign   []Unseen
}

// CheckCoverage reports, per collector, how much of the server it sees.
func CheckCoverage(env *Env) []Coverage {
	v := look(env)
	var out []Coverage
	for _, name := range CollectorNames() {
		out = append(out, coverageOf(name, env, v))
	}
	return out
}

func look(env *Env) view {
	var v view
	procs, err := readProcs(env)
	if err != nil {
		return v
	}
	own := OwnProcesses(procs)
	selfNet, _ := os.Readlink("/proc/self/ns/net")
	rootID, rootOK := fileID(env.Path("/"))

	nets := map[string]*Unseen{}
	roots := map[string]*Unseen{}
	group := func(m map[string]*Unseen, key string, p Process, sub string) {
		u := m[key]
		if u == nil {
			u = &Unseen{PID: p.PID}
			m[key] = u
		}
		u.Processes++
		if p.PID <= u.PID {
			u.PID, u.Exe, u.Cmdline, u.Path = p.PID, p.Exe, p.Cmdline, fmt.Sprintf("/proc/%d/%s", p.PID, sub)
		}
	}
	for _, p := range procs {
		if own[p.PID] || p.State == "Z" {
			continue
		}
		v.others++
		if p.Exe == "" {
			v.exeUnreadable++
		}
		base := env.Path(fmt.Sprintf("/proc/%d", p.PID))
		if _, err := os.ReadDir(filepath.Join(base, "fd")); err != nil {
			v.fdUnreadable++
		}
		if ns, err := os.Readlink(filepath.Join(base, "ns", "net")); err == nil && selfNet != "" {
			if ns == selfNet {
				v.netOwn++
			} else {
				group(nets, ns, p, "net")
			}
		}
		if id, ok := fileID(filepath.Join(base, "root")); ok && rootOK {
			if id == rootID {
				v.rootOwn++
			} else {
				group(roots, id, p, "root")
			}
		}
	}
	v.netForeign = sortedUnseen(nets)
	v.rootForeign = sortedUnseen(roots)
	return v
}

// OwnProcesses is kodeblue itself and everything it started (engine, MCP
// server, commands): those are never what the sensors are there to watch.
// When kodeblue shares a container's PID namespace, its orphans are
// re-parented to the container's PID 1, so checks on a service's children
// must leave these out.
func OwnProcesses(procs []Process) map[int]bool {
	self, err := os.Executable()
	if err != nil {
		return map[int]bool{os.Getpid(): true}
	}
	if real, err := filepath.EvalSymlinks(self); err == nil {
		self = real
	}
	own := map[int]bool{os.Getpid(): true}
	children := map[int][]int{}
	for _, p := range procs {
		children[p.PPID] = append(children[p.PPID], p.PID)
		if p.Exe == self {
			own[p.PID] = true
		}
	}
	queue := make([]int, 0, len(own))
	for pid := range own {
		queue = append(queue, pid)
	}
	for len(queue) > 0 {
		pid := queue[0]
		queue = queue[1:]
		for _, c := range children[pid] {
			if !own[c] {
				own[c] = true
				queue = append(queue, c)
			}
		}
	}
	return own
}

func fileID(path string) (string, bool) {
	st, err := os.Stat(path)
	if err != nil {
		return "", false
	}
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return "", false
	}
	return fmt.Sprintf("%d:%d", s.Dev, s.Ino), true
}

func sortedUnseen(m map[string]*Unseen) []Unseen {
	out := make([]Unseen, 0, len(m))
	for _, u := range m {
		out = append(out, *u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	return out
}

// split turns "own vs foreign" counts into a status.
func split(own int, foreign []Unseen) string {
	switch {
	case len(foreign) == 0:
		return CoverageOK
	case own == 0:
		return CoverageBlind
	}
	return CoveragePartial
}

func unseenSummary(foreign []Unseen, what string) string {
	n := 0
	for _, u := range foreign {
		n += u.Processes
	}
	return fmt.Sprintf("%d processes in %d other %s are invisible to it (see unseen)", n, len(foreign), what)
}

// pidRef is how a monitor names a process that may restart with a new PID.
func pidRef(u Unseen) string {
	if u.Exe == "" {
		return fmt.Sprint(u.PID)
	}
	return "{pid:" + u.Exe + "}"
}

func rootExample(foreign []Unseen) string {
	if len(foreign) == 0 {
		return "/proc/{pid:<exe>}/root"
	}
	return "/proc/" + pidRef(foreign[0]) + "/root"
}

func coverageOf(name string, env *Env, v view) Coverage {
	c := Coverage{Collector: name, Status: CoverageOK}
	if v.others == 0 && name != "kernel_module" {
		c.Status = CoverageBlind
		c.Reason = "kodeblue sees no processes but its own: it runs in its own PID namespace, so it cannot tell what this server runs"
		c.ReplaceWith = "monitors cannot replace this: run kodeblue on the host, or share the workload's PID namespace with kodeblue's container"
		return c
	}
	root := rootExample(v.rootForeign)
	files := func(replace string) {
		c.Status = split(v.rootOwn, v.rootForeign)
		if c.Status != CoverageOK {
			c.Reason = "it reads the filesystem at " + env.Path("/") + "; " + unseenSummary(v.rootForeign, "filesystems")
			c.ReplaceWith = replace
			c.Unseen = v.rootForeign
		}
	}
	nets := func(replace string) {
		c.Status = split(v.netOwn, v.netForeign)
		if c.Status != CoverageOK {
			c.Reason = "it reads kodeblue's own network namespace; " + unseenSummary(v.netForeign, "network namespaces")
			c.ReplaceWith = replace
			c.Unseen = v.netForeign
		}
		if v.fdUnreadable > 0 && c.Status == CoverageOK {
			c.Status = CoveragePartial
			c.Reason = fmt.Sprintf("it cannot read the open files of %d processes, so it cannot tell which program owns their sockets (kodeblue lacks CAP_SYS_PTRACE / CAP_DAC_READ_SEARCH)", v.fdUnreadable)
		}
	}

	switch name {
	case "process", "cpu_hog":
		c.Limits = "One item per program and user: another instance of a program that already runs (a service re-executing its own interpreter, a new worker) is not new. Processes that start and exit between sweeps are usually missed."
		c.ReplaceWith = "process monitors on each service with no_children (allow_children for helpers it legitimately starts) or max_count, at a short interval_seconds"
		if name == "cpu_hog" {
			c.Limits, c.ReplaceWith = "", ""
		}
		if v.exeUnreadable > 0 {
			c.Status = CoveragePartial
			c.Reason = fmt.Sprintf("the executables of %d processes are unreadable (kodeblue lacks CAP_SYS_PTRACE, or /proc is mounted with hidepid)", v.exeUnreadable)
		}
	case "listener":
		nets("a sockets monitor per unseen namespace: process_exe of a process in it and listen_ports with the ports it should have open")
	case "outbound":
		c.Limits = "Only established TCP connections to public addresses: connections to private or LAN addresses, UDP and connection attempts are not reported."
		nets("a sockets monitor per unseen namespace with no_outbound and allow_remotes (the addresses the service may reach)")
		if c.Status == CoverageOK {
			c.ReplaceWith = "a sockets monitor with no_outbound and allow_remotes on services that should never open connections, to also catch private destinations and attempts"
		}
	case "account":
		files("file monitors (fast) on " + root + "/etc/passwd, /etc/group and /etc/sudoers.d")
	case "ssh_key":
		files("file monitors (fast) on the .ssh directories under " + root + " (/root/.ssh, /home/*/.ssh)")
	case "persistence":
		files("file monitors on the cron and init directories under " + root + " (/etc/cron.d, /etc/crontab, /var/spool/cron, /etc/systemd/system, /etc/init.d)")
	case "integrity":
		files("file monitors on the workload's own binaries and application code under " + root)
		// It also hashes kodeblue's own binaries and config: tamper
		// protection that matters wherever kodeblue runs, so never blind.
		if c.Status == CoverageBlind {
			c.Status = CoveragePartial
			c.Reason += "; it still guards kodeblue's own binaries and config, so it stays on"
		}
	case "suid":
		files(`a command monitor ["find","` + root + `/<app dir>","-xdev","-perm","-4000","-type","f"] with expect_no_match "."`)
	case "package":
		files("a file monitor on the package database under " + root + " (/var/lib/dpkg/status, /lib/apk/db/installed or /var/lib/rpm)")
		if c.Status == CoverageOK && !exists(env.Path("/var/lib/dpkg/status")) && !exists(env.Path("/lib/apk/db/installed")) && !exists(env.Path("/var/lib/rpm")) {
			c.Status, c.Reason = CoverageUnavailable, "no dpkg, apk or rpm database on this filesystem"
		}
	case "tmp_exec":
		c.Limits = "Only files with an execute bit: a script or payload run by an interpreter (sh x, node x.js, python x.py) is not reported."
		files("a file monitor with fast: true on the directories " + root + "/tmp, /var/tmp and /dev/shm (any new, changed or removed file)")
		if c.Status == CoverageOK {
			c.ReplaceWith = "a file monitor with fast: true on /tmp, /var/tmp and /dev/shm, to also catch non-executable files"
		}
	case "auth":
		files("log monitors on the workload's auth or application logs under " + root)
		if c.Status == CoverageOK && !exists(env.Path("/var/log/auth.log")) && !exists(env.Path("/var/log/secure")) && !hasJournal(env) {
			c.Status, c.Reason = CoverageUnavailable, "no /var/log/auth.log, /var/log/secure or systemd journal"
			c.ReplaceWith = "log monitors on the application's own logs, if it writes any"
		}
		if c.Status == CoverageOK || c.Status == CoveragePartial {
			if src, why := authParseGap(env); why != "" {
				c.Status, c.Reason = CoverageDegraded, why
				c.ReplaceWith = "write " + src + " in a format kodeblue reads (rsyslog's default file formats, or journalctl short-iso); until then a log monitor on it whose pattern is anchored at the start of the line through the sshd program field. Never match \"Failed\" or \"Accepted\" anywhere in a line: a remote client can get sshd to log that text"
			}
		}
	case "container":
		if !onPath("docker") && !onPath("podman") {
			c.Status, c.Reason = CoverageUnavailable, "no docker or podman CLI on kodeblue's PATH"
		}
	case "kernel_module":
		if !exists(env.Path("/proc/modules")) {
			c.Status, c.Reason = CoverageUnavailable, "/proc/modules is not readable"
		}
	}
	return c
}

var (
	// reSSHDProg and reSSHDLogin loosely match an sshd login line in any
	// log format and under any sshd program name: what the auth sensor
	// should have parsed. The program field is the line's first sshd word
	// (what a remote client gets sshd to log comes after it), and the
	// login keyword must start its message.
	reSSHDProg  = regexp.MustCompile(`\bsshd[\w-]*`)
	reSSHDLogin = regexp.MustCompile(`^(?:\[\d+\])?(?::| \d+ - -)? +(?:message repeated \d+ times: \[ ?)?(?:Accepted \S+ for |Failed \S+ for |Invalid user )`)
)

// sshdLoginLine reports whether line looks like an sshd login line.
func sshdLoginLine(line string) bool {
	loc := reSSHDProg.FindStringIndex(line)
	return loc != nil && reSSHDLogin.MatchString(line[loc[1]:])
}

// authParseGap looks at the recent auth log for sshd login lines the auth
// sensor cannot parse (a program name or log format it does not know). It
// returns where it looked and, when some are there and none parse, why the
// sensor is degraded.
func authParseGap(env *Env) (string, string) {
	lines, src := recentAuthLines(env)
	seen, parsed := 0, 0
	for _, l := range lines {
		if !sshdLoginLine(l) {
			continue
		}
		seen++
		if len(parseAuthLines([]string{l})) > 0 {
			parsed++
		}
	}
	if seen < 5 || parsed > 0 {
		return src, ""
	}
	why := fmt.Sprintf("%s holds %d recent sshd login lines and kodeblue parses none of them, so it misses logins and brute force", src, seen)
	for _, p := range []string{"/usr/lib/openssh/sshd-session", "/usr/libexec/openssh/sshd-session", "/usr/lib/ssh/sshd-session", "/usr/libexec/sshd-session"} {
		if exists(env.Path(p)) {
			why += " (OpenSSH 9.8 or later is installed: it logs as sshd-session)"
			break
		}
	}
	return src, why
}

// recentAuthLines is the end of the log the auth sensor reads (the current
// file and the one rotated before it, or a week of the auth facilities in
// the journal) and where it came from.
func recentAuthLines(env *Env) ([]string, string) {
	const window = 2 << 20
	for _, path := range []string{"/var/log/auth.log", "/var/log/secure"} {
		if !exists(env.Path(path)) {
			continue
		}
		cur := tailOf(env.Path(path), window)
		var old []byte
		if len(cur) < window {
			old = tailOf(env.Path(path+".1"), window-len(cur))
		}
		return strings.Split(string(old)+string(cur), "\n"), path
	}
	if !onPath("journalctl") {
		return nil, "the journal"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// By facility, not identifier: a program name kodeblue does not know
	// is what this looks for.
	out, err := exec.CommandContext(ctx, "journalctl", "--no-pager", "-o", "short-iso", "--since", "-7d", "-n", "5000", "SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10").Output()
	if err != nil {
		return nil, "the journal"
	}
	return strings.Split(string(out), "\n"), "the journal"
}

// tailOf is the last n bytes of a file, from its first full line.
func tailOf(path string, n int) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil
	}
	off := max(st.Size()-int64(n), 0)
	b := make([]byte, st.Size()-off)
	k, _ := f.ReadAt(b, off)
	b = b[:k]
	if off > 0 {
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			b = b[i+1:]
		}
	}
	return b
}

func hasJournal(env *Env) bool {
	return onPath("journalctl") && (exists(env.Path("/var/log/journal")) || exists(env.Path("/run/log/journal")))
}

func onPath(bin string) bool {
	_, err := exec.LookPath(bin)
	return err == nil
}

// DisabledKey is the store key holding the sensors agents turned off.
const DisabledKey = "disabled_sensors"

// DisabledSensor records a sensor turned off because it could not see the
// workload, and the monitors that now cover for it.
type DisabledSensor struct {
	Reason     string   `json:"reason"`
	ReplacedBy []string `json:"replaced_by"`
	By         string   `json:"by"`
	At         string   `json:"at"`
}

// ParseDisabled reads the DisabledKey value; anything unreadable means none.
func ParseDisabled(raw string) map[string]DisabledSensor {
	out := map[string]DisabledSensor{}
	if raw != "" {
		_ = json.Unmarshal([]byte(raw), &out)
	}
	return out
}
