package sensors

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Service is one thing this server runs to serve something, or can start on
// its own: a systemd unit, a daemon, the processes of a container, a unit
// systemd starts on the first connection. The learner gets the whole list,
// so a service never goes unmonitored because nobody looked for it.
type Service struct {
	Name string `json:"name"`
	Unit string `json:"unit,omitempty"`
	// State is running (its processes are up), enabled (it starts at boot
	// but is not running now) or socket (systemd holds its socket and starts
	// it on the first connection).
	State string   `json:"state"`
	Exes  []string `json:"exes,omitempty"`
	PID   int      `json:"pid,omitempty"` // its lowest PID, when running
	Users []string `json:"users,omitempty"`
	// Container is the container id, when its processes run in one.
	Container string `json:"container,omitempty"`
	Listen    []Port `json:"listen,omitempty"`
	// Root and Net are the /proc paths that still reach the service when it
	// lives in another filesystem or network namespace than kodeblue.
	Root    string   `json:"root,omitempty"`
	Net     string   `json:"net,omitempty"`
	FoundBy []string `json:"found_by"`
	Note    string   `json:"note,omitempty"`

	foreignRoot, foreignNet bool
}

// Port is a socket a service listens on.
type Port struct {
	Proto   string `json:"proto"`
	Port    int    `json:"port"`
	Address string `json:"address,omitempty"`
}

// Public reports whether the service listens on TCP on an address other
// hosts can reach.
func (s Service) Public() bool {
	for _, p := range s.Listen {
		if p.Proto == "tcp" && !isLoopback(p.Address) {
			return true
		}
	}
	return false
}

func isLoopback(addr string) bool {
	return strings.HasPrefix(addr, "127.") || addr == "::1" || addr == "localhost"
}

// Service states.
const (
	ServiceRunning = "running"
	ServiceEnabled = "enabled"
	ServiceSocket  = "socket"
)

// unitDirs are where systemd looks for unit files, highest priority first.
var unitDirs = []string{"/etc/systemd/system", "/run/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"}

// containerRe finds a container id in a cgroup path: docker, podman,
// containerd and CRI-O scopes, and the cgroupfs layout (/docker/<id>).
var containerRe = regexp.MustCompile(`(?:docker-|libpod-|cri-containerd-|crio-|/docker/|/libpod/)([0-9a-f]{12,64})`)

// shells are commands, not services: a shell whose parent is outside
// kodeblue's PID namespace is a `docker exec` or nsenter session.
var shells = map[string]bool{"sh": true, "bash": true, "dash": true, "ash": true, "zsh": true, "ksh": true, "mksh": true, "fish": true, "busybox": true}

// dockerDNS is the address of the resolver Docker serves inside every
// container on a user-defined network, from dockerd outside it.
const DockerDNS = "127.0.0.11"

// DiscoverServices lists the services this server runs or can start: every
// process that owns a listening socket, runs in a system unit, a container
// or as a daemon of PID 1, plus the units enabled to start at boot or on a
// connection that are not running now. kodeblue's own processes are left out.
func DiscoverServices(env *Env) []Service {
	procs, _ := readProcs(env)
	own := OwnProcesses(procs)
	selfNet, _ := os.Readlink("/proc/self/ns/net")
	rootID, rootOK := fileID(env.Path("/"))

	byKey := map[string]*Service{}
	var keys []string
	add := func(key, name string) *Service {
		s := byKey[key]
		if s == nil {
			s = &Service{Name: name, State: ServiceRunning}
			byKey[key] = s
			keys = append(keys, key)
		}
		return s
	}

	svcOf := map[int]*Service{} // pid -> service
	nsPID := map[string]int{}   // foreign network namespace -> a pid in it
	nsSvc := map[string]*Service{}
	initPIDs := map[int]bool{}
	for _, p := range procs {
		if own[p.PID] || p.State == "Z" {
			continue
		}
		base := env.Path(fmt.Sprintf("/proc/%d", p.PID))
		cg := readCgroup(base)
		unit := systemUnit(cg)
		container := ""
		if m := containerRe.FindStringSubmatch(cg); m != nil {
			container = m[1][:12]
		}
		ns, _ := os.Readlink(filepath.Join(base, "ns", "net"))
		foreignNet := ns != "" && selfNet != "" && ns != selfNet
		rid, ok := fileID(filepath.Join(base, "root"))
		foreignRoot := ok && rootOK && rid != rootID
		if (p.PID == 1 && !foreignRoot) || filepath.Base(p.Exe) == "pause" {
			// init itself is not a service; the sockets it holds belong to
			// socket-activated units (matched below). A pod's pause process
			// only holds its namespaces.
			initPIDs[p.PID] = true
			continue
		}

		var s *Service
		switch {
		case container != "":
			s = add("container:"+container, "container "+container)
			s.Container = container
		case foreignRoot:
			s = add("root:"+rid, "")
		case unit != "":
			s = add("unit:"+unit, strings.TrimSuffix(unit, ".service"))
			s.Unit = unit
		case (p.PPID == 1 || p.PPID == 0) && !shells[filepath.Base(p.Exe)]:
			s = add(exeKey(p))
		default:
			// A command or a child of a service; it becomes one below if it
			// owns a listening socket.
			continue
		}
		join(s, p, "process")
		s.foreignRoot = s.foreignRoot || foreignRoot
		s.foreignNet = s.foreignNet || foreignNet
		if foreignNet {
			if q, ok := nsPID[ns]; !ok || p.PID < q {
				nsPID[ns] = p.PID
				nsSvc[ns] = s
			}
		}
		svcOf[p.PID] = s
	}

	// Listening sockets, in kodeblue's network namespace and every other one
	// a service lives in. Inodes are unique across namespaces.
	owners := inodeOwners(env, procs)
	type nsSockets struct {
		socks []Socket
		svc   *Service // who a socket nobody owns belongs to
	}
	all := []nsSockets{{socks: readSockets(env)}}
	for ns, pid := range nsPID {
		all = append(all, nsSockets{socks: SocketsOf(env, pid), svc: nsSvc[ns]})
	}
	seen := map[string]bool{}
	var initPorts []Port
	for _, group := range all {
		for _, sk := range group.socks {
			listening := (sk.Proto == "tcp" && sk.State == "0A") || (sk.Proto == "udp" && sk.State == "07" && sk.RemotePort == 0)
			if !listening || seen[sk.Inode] {
				continue
			}
			seen[sk.Inode] = true
			port := Port{Proto: sk.Proto, Port: sk.LocalPort, Address: sk.LocalIP.String()}
			owner, known := owners[sk.Inode]
			switch {
			case known && own[owner.PID]:
				continue
			case known && initPIDs[owner.PID]:
				initPorts = append(initPorts, port)
				continue
			}
			s := group.svc
			if known {
				if s = svcOf[owner.PID]; s == nil {
					s = add(exeKey(owner))
					join(s, owner, "listener")
					svcOf[owner.PID] = s
				}
			} else if s == nil && port.Address == DockerDNS {
				s = add("docker-dns", "docker-dns")
				s.Note = "Docker's embedded DNS resolver; dockerd serves it from outside this container"
			} else if s == nil {
				s = add(fmt.Sprintf("port:%s/%d", sk.Proto, sk.LocalPort), fmt.Sprintf("unknown %s/%d", sk.Proto, sk.LocalPort))
				s.Note = "no process kodeblue can see holds this socket: kodeblue lacks CAP_SYS_PTRACE / CAP_DAC_READ_SEARCH, or the owner runs outside kodeblue's PID namespace"
			}
			addPort(s, port)
			addSource(s, "listener")
		}
	}

	// Units enabled to start at boot or on a connection.
	running := map[string]*Service{}
	for _, s := range byKey {
		if s.Unit != "" {
			running[s.Unit] = s
		}
	}
	for _, u := range enabledUnits(env) {
		switch {
		case strings.HasSuffix(u.name, ".socket"):
			svcName := u.service
			if svcName == "" {
				svcName = strings.TrimSuffix(u.name, ".socket") + ".service"
			}
			var held []Port
			for _, p := range u.ports {
				if i := portIndex(initPorts, p); i >= 0 {
					held = append(held, initPorts[i])
					initPorts = append(initPorts[:i], initPorts[i+1:]...)
				}
			}
			if s := running[svcName]; s != nil {
				for _, p := range held {
					addPort(s, p)
				}
				addSource(s, "socket unit")
				continue
			}
			s := add("unit:"+svcName, strings.TrimSuffix(svcName, ".service"))
			s.Unit, s.State = svcName, ServiceSocket
			s.Listen = append(s.Listen, held...)
			if len(held) == 0 {
				s.Listen = append(s.Listen, u.ports...)
			}
			if exe := unitExe(env, svcName); exe != "" {
				s.Exes = []string{exe}
			}
			s.Note = u.name + " is enabled: systemd starts this service on the first connection"
			addSource(s, "socket unit")
		case running[u.name] == nil:
			if u.oneshot {
				continue // a boot task, not something that keeps running
			}
			s := add("unit:"+u.name, strings.TrimSuffix(u.name, ".service"))
			s.Unit, s.State = u.name, ServiceEnabled
			if u.exe != "" {
				s.Exes = []string{u.exe}
			}
			s.Note = "enabled to start at boot, not running now"
			addSource(s, "unit file")
		}
	}
	for _, p := range initPorts {
		s := add(fmt.Sprintf("init:%s/%d", p.Proto, p.Port), fmt.Sprintf("socket-activated %s/%d", p.Proto, p.Port))
		s.State = ServiceSocket
		addPort(s, p)
		s.Note = "init holds this socket and starts a program on the first connection; kodeblue found no enabled unit for it"
		addSource(s, "listener")
	}
	for _, n := range sysvServices(env) {
		if byKey["exe:"+n] == nil && !hasName(byKey, n) {
			s := add("rc:"+n, n)
			s.State, s.Note = ServiceEnabled, "init script enabled to start at boot; kodeblue cannot tell whether it runs now unless it appears as running"
			addSource(s, "init script")
		}
	}

	out := make([]Service, 0, len(keys))
	for _, k := range keys {
		s := byKey[k]
		if s.Name == "" {
			s.Name = filepath.Base(firstOr(s.Exes, "unknown")) + " (other filesystem)"
		}
		if s.foreignRoot {
			s.Root = fmt.Sprintf("/proc/%d/root", s.PID)
		}
		if s.foreignNet {
			s.Net = fmt.Sprintf("/proc/%d/net", s.PID)
		}
		sort.Slice(s.Listen, func(i, j int) bool {
			if s.Listen[i].Proto != s.Listen[j].Proto {
				return s.Listen[i].Proto > s.Listen[j].Proto // tcp first
			}
			return s.Listen[i].Port < s.Listen[j].Port
		})
		out = append(out, *s)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if a, b := stateRank(out[i].State), stateRank(out[j].State); a != b {
			return a < b
		}
		if a, b := out[i].Public(), out[j].Public(); a != b {
			return a
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func stateRank(s string) int {
	switch s {
	case ServiceRunning:
		return 0
	case ServiceSocket:
		return 1
	}
	return 2
}

// exeKey groups processes without a unit or container by executable.
func exeKey(p Process) (string, string) {
	if p.Exe == "" {
		return "comm:" + p.Comm, p.Comm
	}
	return "exe:" + p.Exe, filepath.Base(p.Exe)
}

func join(s *Service, p Process, source string) {
	if s.PID == 0 || p.PID < s.PID {
		s.PID = p.PID
	}
	if p.Exe != "" && !contains(s.Exes, p.Exe) && len(s.Exes) < 8 {
		s.Exes = append(s.Exes, p.Exe)
	}
	if p.User != "" && !contains(s.Users, p.User) && len(s.Users) < 8 {
		s.Users = append(s.Users, p.User)
	}
	addSource(s, source)
}

func addPort(s *Service, p Port) {
	for _, q := range s.Listen {
		if q.Proto == p.Proto && q.Port == p.Port && q.Address == p.Address {
			return
		}
	}
	s.Listen = append(s.Listen, p)
}

func addSource(s *Service, src string) {
	if !contains(s.FoundBy, src) {
		s.FoundBy = append(s.FoundBy, src)
	}
}

func portIndex(ps []Port, p Port) int {
	for i, q := range ps {
		if q.Proto == p.Proto && q.Port == p.Port {
			return i
		}
	}
	return -1
}

func hasName(m map[string]*Service, name string) bool {
	for _, s := range m {
		if s.Name == name {
			return true
		}
		for _, e := range s.Exes {
			if filepath.Base(e) == name {
				return true
			}
		}
	}
	return false
}

func contains(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

func firstOr(l []string, d string) string {
	if len(l) > 0 {
		return l[0]
	}
	return d
}

func readCgroup(procDir string) string {
	b, err := os.ReadFile(filepath.Join(procDir, "cgroup"))
	if err != nil {
		return ""
	}
	return string(b)
}

// systemUnit is the system service a process runs in, from its cgroup:
// the last *.service under system.slice. Units of a user's own systemd
// (user@<uid>.service and below) are not system services.
func systemUnit(cgroup string) string {
	for _, line := range strings.Split(cgroup, "\n") {
		_, path, ok := strings.Cut(line, "::")
		if !ok {
			if i := strings.LastIndex(line, ":"); i >= 0 {
				path = line[i+1:]
			}
		}
		if !strings.Contains(path, "system.slice/") {
			continue
		}
		unit := ""
		for _, seg := range strings.Split(path, "/") {
			if strings.HasSuffix(seg, ".service") {
				unit = seg
			}
		}
		if unit != "" {
			return unit
		}
	}
	return ""
}

type unitFile struct {
	name    string
	oneshot bool
	exe     string
	service string // a socket unit's Service=
	ports   []Port
}

// enabledUnits lists the services and sockets enabled in /etc/systemd/system
// (links in *.wants and *.requires directories).
func enabledUnits(env *Env) []unitFile {
	dirs, _ := filepath.Glob(env.Path("/etc/systemd/system/*.wants"))
	req, _ := filepath.Glob(env.Path("/etc/systemd/system/*.requires"))
	seen := map[string]bool{}
	var out []unitFile
	for _, d := range append(dirs, req...) {
		entries, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range entries {
			n := e.Name()
			if seen[n] || !(strings.HasSuffix(n, ".service") || strings.HasSuffix(n, ".socket")) {
				continue
			}
			seen[n] = true
			out = append(out, readUnit(env, n))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

func readUnit(env *Env, name string) unitFile {
	u := unitFile{name: name}
	path := ""
	for _, d := range unitDirs {
		if p := env.Path(filepath.Join(d, name)); exists(p) {
			path = p
			break
		}
		// An instance (getty@tty1.service) is described by its template.
		if at := strings.Index(name, "@"); at > 0 {
			if p := env.Path(filepath.Join(d, name[:at+1]+filepath.Ext(name))); exists(p) {
				path = p
				break
			}
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return u
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.TrimSpace(k) {
		case "Type":
			u.oneshot = v == "oneshot"
		case "ExecStart":
			if u.exe == "" {
				if f := strings.Fields(strings.TrimLeft(v, "@-:+!")); len(f) > 0 && strings.HasPrefix(f[0], "/") {
					u.exe = f[0]
				}
			}
		case "Service":
			u.service = v
		case "ListenStream", "ListenDatagram":
			proto := "tcp"
			if k == "ListenDatagram" {
				proto = "udp"
			}
			addr := ""
			pv := v
			if i := strings.LastIndex(v, ":"); i >= 0 {
				addr, pv = strings.Trim(v[:i], "[]"), v[i+1:]
			}
			if n, err := strconv.Atoi(pv); err == nil {
				u.ports = append(u.ports, Port{Proto: proto, Port: n, Address: addr})
			}
		}
	}
	return u
}

func unitExe(env *Env, name string) string { return readUnit(env, name).exe }

// sysvServices lists init scripts enabled at boot on servers that do not run
// systemd (OpenRC runlevels, SysV rc directories).
func sysvServices(env *Env) []string {
	if exists(env.Path("/run/systemd/system")) {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(n string) {
		if n != "" && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	for _, lvl := range []string{"default", "boot"} {
		entries, _ := os.ReadDir(env.Path("/etc/runlevels/" + lvl))
		for _, e := range entries {
			add(e.Name())
		}
	}
	for _, rc := range []string{"/etc/rc2.d", "/etc/rc3.d", "/etc/rc5.d"} {
		entries, _ := os.ReadDir(env.Path(rc))
		for _, e := range entries {
			if n := e.Name(); len(n) > 3 && n[0] == 'S' {
				add(strings.TrimLeft(n[1:], "0123456789"))
			}
		}
	}
	sort.Strings(out)
	return out
}
