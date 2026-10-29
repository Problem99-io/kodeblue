package sensors

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Process is what kodeblue knows about one running process.
type Process struct {
	PID     int
	PPID    int
	UID     string
	User    string
	Exe     string
	Comm    string
	Cmdline string
	Deleted bool
	State   string // first letter of the State: line: R, S, Z…
}

func readProcs(env *Env) ([]Process, error) { return listProcs(env, false) }

// listProcs reads /proc. Kernel threads are left out; zombies too unless
// keepZombies (they have no executable or command line either).
func listProcs(env *Env, keepZombies bool) ([]Process, error) {
	entries, err := os.ReadDir(env.Path("/proc"))
	if err != nil {
		return nil, err
	}
	users := loadUserNames(env)
	var out []Process
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		base := env.Path(filepath.Join("/proc", e.Name()))
		p := Process{PID: pid}
		if exe, err := os.Readlink(filepath.Join(base, "exe")); err == nil {
			p.Exe = exe
			if strings.HasSuffix(exe, " (deleted)") {
				p.Deleted = true
				p.Exe = strings.TrimSuffix(exe, " (deleted)")
			}
		}
		if b, err := os.ReadFile(filepath.Join(base, "cmdline")); err == nil {
			p.Cmdline = strings.TrimSpace(strings.ReplaceAll(string(b), "\x00", " "))
			if len(p.Cmdline) > 400 {
				p.Cmdline = p.Cmdline[:400]
			}
		}
		if b, err := os.ReadFile(filepath.Join(base, "comm")); err == nil {
			p.Comm = strings.TrimSpace(string(b))
		}
		if b, err := os.ReadFile(filepath.Join(base, "status")); err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				switch {
				case strings.HasPrefix(line, "State:"):
					if f := strings.Fields(strings.TrimPrefix(line, "State:")); len(f) > 0 {
						p.State = f[0]
					}
				case strings.HasPrefix(line, "PPid:"):
					p.PPID, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "PPid:")))
				case strings.HasPrefix(line, "Uid:"):
					f := strings.Fields(strings.TrimPrefix(line, "Uid:"))
					if len(f) > 0 {
						p.UID = f[0]
					}
				}
			}
		}
		p.User = users[p.UID]
		if p.User == "" {
			p.User = "uid:" + p.UID
		}
		// Kernel threads have no exe and no cmdline; skip them.
		if p.Exe == "" && p.Cmdline == "" && !(keepZombies && p.State == "Z") {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}

// processCollector reports one item per distinct (executable, user). PIDs and
// arguments are attributes, never identity, so restarts and workers do not
// look like new things.
type processCollector struct{}

func (processCollector) Name() string { return "process" }
func (processCollector) Every() int   { return 1 }

func (processCollector) Collect(ctx context.Context, env *Env) ([]Item, []Event, error) {
	procs, err := readProcs(env)
	if err != nil {
		return nil, nil, err
	}
	var items []Item
	for _, p := range procs {
		exe := p.Exe
		if exe == "" {
			// Unreadable exe (no permission or zombie) — fall back to comm so
			// the item is still stable.
			exe = "comm:" + p.Comm
		}
		attrs := map[string]string{
			"pid":     strconv.Itoa(p.PID),
			"ppid":    strconv.Itoa(p.PPID),
			"cmdline": p.Cmdline,
			"comm":    p.Comm,
		}
		if p.Deleted {
			attrs["deleted"] = "true"
			// Which service runs it: kodeblue's own upgrade replaces the
			// binary its `kodeblue upgrade` process runs from.
			if unit := systemUnit(readCgroup(env.Path(filepath.Join("/proc", strconv.Itoa(p.PID))))); unit != "" {
				attrs["unit"] = unit
			}
		}
		if loc := suspiciousExeLocation(p.Exe); loc != "" {
			attrs["suspicious_location"] = loc
		}
		if pkg := env.Pkg.Owner(p.Exe); pkg != "" {
			attrs["package"] = pkg
		}
		items = append(items, Item{Key: exe + "@" + p.User, Attrs: attrs})
	}
	return items, nil, nil
}

func suspiciousExeLocation(exe string) string {
	switch {
	case exe == "":
		return ""
	case strings.HasPrefix(exe, "/memfd:"):
		return "memfd"
	case strings.HasPrefix(exe, "/tmp/"), strings.HasPrefix(exe, "/var/tmp/"), strings.HasPrefix(exe, "/dev/shm/"), strings.HasPrefix(exe, "/run/user/"):
		return "world-writable dir"
	case strings.Contains(exe, "/."):
		return "hidden path"
	}
	return ""
}

// Socket is a parsed /proc/net/{tcp,udp}[6] row.
type Socket struct {
	Proto      string
	LocalIP    net.IP
	LocalPort  int
	RemoteIP   net.IP
	RemotePort int
	State      string
	Inode      string
}

func readSockets(env *Env) []Socket {
	return readSocketsIn(env.Path("/proc/net"))
}

// Processes lists the processes kodeblue can see, zombies included (State
// "Z"), kernel threads excluded.
func Processes(env *Env) ([]Process, error) { return listProcs(env, true) }

// SocketsOf reads the sockets of the network namespace process pid lives in,
// which may not be kodeblue's own (a container's, for example).
func SocketsOf(env *Env, pid int) []Socket {
	return readSocketsIn(env.Path(fmt.Sprintf("/proc/%d/net", pid)))
}

// SocketOwners maps socket inode to the process holding it.
func SocketOwners(env *Env, procs []Process) map[string]Process { return inodeOwners(env, procs) }

func readSocketsIn(dir string) []Socket {
	var out []Socket
	for _, proto := range []string{"tcp", "tcp6", "udp", "udp6"} {
		f, err := os.Open(filepath.Join(dir, proto))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		first := true
		for sc.Scan() {
			if first {
				first = false
				continue
			}
			fields := strings.Fields(sc.Text())
			if len(fields) < 10 {
				continue
			}
			lip, lport := parseHexAddr(fields[1])
			rip, rport := parseHexAddr(fields[2])
			out = append(out, Socket{
				Proto: strings.TrimSuffix(proto, "6"), LocalIP: lip, LocalPort: lport,
				RemoteIP: rip, RemotePort: rport, State: fields[3], Inode: fields[9],
			})
		}
		f.Close()
	}
	return out
}

func parseHexAddr(s string) (net.IP, int) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return nil, 0
	}
	port, _ := strconv.ParseInt(parts[1], 16, 32)
	raw, err := hex.DecodeString(parts[0])
	if err != nil {
		return nil, int(port)
	}
	// /proc/net stores addresses as host-endian 32-bit words.
	ip := make(net.IP, len(raw))
	for i := 0; i+4 <= len(raw); i += 4 {
		ip[i], ip[i+1], ip[i+2], ip[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
	}
	if v4 := ip.To4(); v4 != nil {
		return v4, int(port)
	}
	return ip, int(port)
}

// inodeOwners maps Socket inode -> process.
func inodeOwners(env *Env, procs []Process) map[string]Process {
	out := map[string]Process{}
	for _, p := range procs {
		fdDir := env.Path(fmt.Sprintf("/proc/%d/fd", p.PID))
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			out[strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")] = p
		}
	}
	return out
}

// listenerCollector reports listening TCP sockets and bound UDP sockets,
// keyed by protocol, port, exposure and owning executable.
type listenerCollector struct{}

func (listenerCollector) Name() string { return "listener" }
func (listenerCollector) Every() int   { return 1 }

func (listenerCollector) Collect(ctx context.Context, env *Env) ([]Item, []Event, error) {
	procs, err := readProcs(env)
	if err != nil {
		return nil, nil, err
	}
	owners := inodeOwners(env, procs)
	own := OwnProcesses(procs)
	var items []Item
	for _, s := range readSockets(env) {
		listening := (s.Proto == "tcp" && s.State == "0A") || (s.Proto == "udp" && s.State == "07" && s.RemotePort == 0)
		if o, ok := owners[s.Inode]; !listening || ok && own[o.PID] {
			// kodeblue's own sockets (the engine's local API, on a random
			// port) are not the server's.
			continue
		}
		exposure := "public"
		if s.LocalIP != nil && s.LocalIP.IsLoopback() {
			exposure = "loopback"
		}
		owner := owners[s.Inode]
		exe := owner.Exe
		if exe == "" {
			exe = "unknown"
		}
		items = append(items, Item{
			Key:   fmt.Sprintf("%s/%d/%s/%s", s.Proto, s.LocalPort, exposure, exe),
			Attrs: map[string]string{"address": s.LocalIP.String(), "pid": strconv.Itoa(owner.PID), "user": owner.User, "cmdline": owner.Cmdline},
		})
	}
	return items, nil, nil
}

// outboundCollector reports which executables hold established connections to
// non-private addresses, keyed by executable and remote port (not remote IP,
// which churns for anything behind a CDN).
type outboundCollector struct{}

func (outboundCollector) Name() string { return "outbound" }
func (outboundCollector) Every() int   { return 1 }

func (outboundCollector) Collect(ctx context.Context, env *Env) ([]Item, []Event, error) {
	procs, err := readProcs(env)
	if err != nil {
		return nil, nil, err
	}
	owners := inodeOwners(env, procs)
	own := OwnProcesses(procs)
	listenPorts := map[int]bool{}
	sockets := readSockets(env)
	for _, s := range sockets {
		if s.Proto == "tcp" && s.State == "0A" {
			listenPorts[s.LocalPort] = true
		}
	}
	seen := map[string]Item{}
	for _, s := range sockets {
		if s.Proto != "tcp" || s.State != "01" || s.RemoteIP == nil {
			continue
		}
		if s.RemoteIP.IsLoopback() || s.RemoteIP.IsPrivate() || s.RemoteIP.IsLinkLocalUnicast() {
			continue
		}
		// Inbound connections to our own listeners are not outbound.
		if listenPorts[s.LocalPort] {
			continue
		}
		owner, ok := owners[s.Inode]
		if ok && own[owner.PID] {
			// kodeblue's own links to the hub and the model API: agents
			// reading the baseline would take them for the server's.
			continue
		}
		exe := owner.Exe
		if exe == "" {
			exe = "unknown"
		}
		key := fmt.Sprintf("%s->%d", exe, s.RemotePort)
		it, ok := seen[key]
		if !ok {
			it = Item{Key: key, Attrs: map[string]string{"remotes": "", "user": owner.User, "cmdline": owner.Cmdline}}
		}
		r := s.RemoteIP.String()
		if !strings.Contains(it.Attrs["remotes"], r) && strings.Count(it.Attrs["remotes"], ",") < 5 {
			if it.Attrs["remotes"] != "" {
				it.Attrs["remotes"] += ","
			}
			it.Attrs["remotes"] += r
		}
		seen[key] = it
	}
	items := make([]Item, 0, len(seen))
	for _, it := range seen {
		items = append(items, it)
	}
	return items, nil, nil
}
