// Package services checks that every service the server runs, or can start,
// is covered by monitors, and opens a coverage case for each one that is
// not. A gap nobody is told about is a gap an attacker gets for free, so a
// service kodeblue cannot watch well enough always ends up in front of a
// human: the learner opens the case with its explanation, and kodeblue opens
// one itself for any gap the learner left without a word.
package services

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Problem99-io/kodeblue/internal/blue/monitor"
	"github.com/Problem99-io/kodeblue/internal/blue/sensors"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

// Checks a service may need.
const (
	Health   = "health"   // it is up
	Exec     = "exec"     // code execution through it (unexpected children)
	Network  = "network"  // its listeners and the connections it makes
	Files    = "files"    // files dropped where it can write
	Requests = "requests" // attacks in its request log
	Start    = "start"    // a service that is not running starts
)

// Check is one thing a service needs watched, and what watches it.
type Check struct {
	Check string `json:"check"`
	// Need says what covers it, for whoever has to create the monitor.
	Need string   `json:"need"`
	By   []string `json:"covered_by,omitempty"`
}

// Result is a service with the checks it needs and what covers them.
type Result struct {
	sensors.Service
	// Role is workload (what the server is for) or system (OS plumbing that
	// the process and integrity sensors already watch).
	Role    string   `json:"role"`
	Checks  []Check  `json:"checks"`
	Missing []string `json:"missing,omitempty"`
	// Case is the open coverage case about this service, if any.
	Case int64 `json:"case,omitempty"`
	// Vulns counts its open vulnerabilities by severity.
	Vulns map[string]int `json:"open_vulnerabilities,omitempty"`
}

// Covered reports whether every check the service needs has a monitor or a
// sensor behind it.
func (r Result) Covered() bool { return len(r.Missing) == 0 }

// Inventory is every service found and how well each is covered.
type Inventory struct {
	Services []Result `json:"services"`
	// Blind is set when kodeblue cannot see the server's processes at all,
	// so the list is necessarily incomplete.
	Blind string `json:"blind,omitempty"`
}

// Gaps lists the services that miss a check.
func (inv Inventory) Gaps() []Result {
	var out []Result
	for _, r := range inv.Services {
		if !r.Covered() {
			out = append(out, r)
		}
	}
	return out
}

// Context is what Assess compares the services against.
type Context struct {
	Monitors []monitor.Spec
	Coverage []sensors.Coverage
	Off      map[string]sensors.DisabledSensor
	// TapDir is kodeblue's request log directory; TapPorts the ports the
	// request tap records (none when it does not run).
	TapDir   string
	TapPorts []int
}

// Take discovers the services and assesses them against the monitors and
// sensors in st.
func Take(env *sensors.Env, st *store.Store, tapDir string) Inventory {
	c := Context{
		Monitors: Specs(st),
		Coverage: sensors.CheckCoverage(env),
		Off:      sensors.ParseDisabled(st.Get(sensors.DisabledKey)),
		TapDir:   tapDir,
	}
	var tap struct {
		Status string `json:"status"`
		Ports  []int  `json:"ports"`
	}
	// The daemon keeps the request tap's state under this key (TapStatusKey).
	if json.Unmarshal([]byte(st.Get("request_tap")), &tap) == nil && tap.Status == "ok" {
		c.TapPorts = tap.Ports
	}
	inv := Assess(sensors.DiscoverServices(env), c)
	inv.Attach(st)
	return inv
}

// Attach fills in each service's open coverage case and vulnerability
// counts from st.
func (inv *Inventory) Attach(st *store.Store) {
	open := openCases(st)
	vulns := st.VulnerabilityCounts()
	for i := range inv.Services {
		inv.Services[i].Case = 0
		if in, ok := open[inv.Services[i].Name]; ok {
			inv.Services[i].Case = in.ID
		}
		inv.Services[i].Vulns = vulns[inv.Services[i].Name]
	}
}

// InventoryKey holds the last inventory the daemon took, for the hub.
const InventoryKey = "service_inventory"

// Specs decodes the enabled monitors in st.
func Specs(st *store.Store) []monitor.Spec {
	var out []monitor.Spec
	for _, row := range st.Monitors(false) {
		var s monitor.Spec
		if json.Unmarshal(row.Spec, &s) == nil {
			out = append(out, s)
		}
	}
	return out
}

// systemNames are OS services the process and integrity sensors already
// watch; they need monitors of their own only when they listen publicly.
var systemNames = []string{
	"systemd", "dbus", "dbus-daemon", "dbus-broker", "polkit", "polkitd", "getty", "agetty", "serial-getty", "user", "accounts-daemon",
	"udisks2", "udisksd", "upower", "upowerd", "ModemManager", "NetworkManager", "wpa_supplicant", "multipathd", "irqbalance", "thermald",
	"snapd", "unattended-upgrades", "packagekit", "packagekitd", "rtkit-daemon", "chrony", "chronyd", "ntp", "ntpd", "cron", "crond",
	"rsyslog", "rsyslogd", "syslog-ng", "atd", "qemu-guest-agent", "qemu-ga", "open-vm-tools", "vmtoolsd", "cloud-init", "networkd-dispatcher",
	"lvm2-monitor", "blk-availability", "ufw", "apparmor", "auditd", "haveged", "acpid", "smartd", "fwupd", "colord", "avahi-daemon",
	"cups", "cupsd", "bluetooth", "bluetoothd", "containerd-shim", "containerd-shim-runc-v2", "dhclient", "udhcpc", "networking", "ifup",
	"docker-dns", "amazon-ssm-agent", "google-guest-agent", "waagent", "walinuxagent", "hv-kvp-daemon", "fail2ban", "fail2ban-server", "tuned",
}

// loginNames are remote login services: starting shells is their job, so
// no_children cannot watch them; the auth sensor watches the logins instead.
var loginNames = []string{"sshd", "ssh", "dropbear", "sshd-session"}

func names(s sensors.Service) []string {
	out := []string{s.Name, strings.TrimSuffix(s.Unit, ".service")}
	if i := strings.Index(out[1], "@"); i > 0 {
		out = append(out, out[1][:i])
	}
	for _, e := range s.Exes {
		out = append(out, filepath.Base(e))
	}
	return out
}

func isOneOf(s sensors.Service, list []string) bool {
	for _, n := range names(s) {
		if n == "" {
			continue
		}
		if slices.Contains(list, n) || strings.HasPrefix(n, "systemd-") && slices.Contains(list, "systemd") {
			return true
		}
	}
	return false
}

// Assess says, per service, which checks it needs and what covers them.
func Assess(svcs []sensors.Service, c Context) Inventory {
	var inv Inventory
	sensorOn := map[string]bool{}
	for _, cv := range c.Coverage {
		_, off := c.Off[cv.Collector]
		sensorOn[cv.Collector] = !off && (cv.Status == sensors.CoverageOK || cv.Status == sensors.CoveragePartial)
		if cv.Collector == "process" && cv.Status == sensors.CoverageBlind {
			inv.Blind = cv.Reason + ". " + cv.ReplaceWith
		}
	}
	for _, s := range svcs {
		r := Result{Service: s, Role: "workload"}
		if isOneOf(s, systemNames) && !s.Public() {
			r.Role = "system"
		}
		var need []string
		switch {
		case s.State != sensors.ServiceRunning:
			if r.Role == "workload" {
				need = []string{Start}
			}
		case s.Public():
			need = []string{Health, Exec, Network, Files}
			if tapped(s, c.TapPorts) {
				need = append(need, Requests)
			}
		case r.Role == "workload":
			need = []string{Health}
		}
		for _, n := range need {
			ch := Check{Check: n, Need: needText(n, s)}
			ch.By = coveredBy(n, s, c, sensorOn)
			if len(ch.By) == 0 {
				r.Missing = append(r.Missing, n)
			}
			r.Checks = append(r.Checks, ch)
		}
		inv.Services = append(inv.Services, r)
	}
	return inv
}

func tapped(s sensors.Service, ports []int) bool {
	if s.Net != "" {
		return false // the tap records kodeblue's own network namespace
	}
	for _, p := range s.Listen {
		if p.Proto == "tcp" && slices.Contains(ports, p.Port) {
			return true
		}
	}
	return false
}

func exeRef(s sensors.Service) string {
	if len(s.Exes) == 0 {
		return "<exe>"
	}
	return s.Exes[0]
}

func needText(check string, s sensors.Service) string {
	exe := exeRef(s)
	switch check {
	case Health:
		return fmt.Sprintf("a process monitor on %s, a port or http monitor on one of its ports, or a sockets monitor with its listen_ports", exe)
	case Exec:
		return fmt.Sprintf("a process monitor on %s with no_children (allow_children for the helpers it legitimately starts)", exe)
	case Network:
		return fmt.Sprintf("a sockets monitor with process_exe %s and listen_ports and/or no_outbound with allow_remotes", exe)
	case Files:
		if s.Root != "" {
			return fmt.Sprintf("a file monitor (fast) on its writable directories as it sees them: /proc/{pid:%s}/root/tmp, …", exe)
		}
		return "a file monitor (fast) on the directories it can write: /tmp, /var/tmp, /dev/shm and its upload or cache directories"
	case Requests:
		return "log monitors (attack text, error bursts, logins) on kodeblue's request log or the service's own access log"
	case Start:
		return fmt.Sprintf("the process sensor (it reports a program that was not running), or a process or command monitor on %s", exe)
	}
	return ""
}

// coveredBy lists the monitors (by id) and sensors (sensor:<name>) that
// cover check for s.
func coveredBy(check string, s sensors.Service, c Context, sensorOn map[string]bool) []string {
	var by []string
	ownExe := func(exe string) bool { return slices.Contains(s.Exes, exe) }
	ownPort := func(port int) bool {
		for _, p := range s.Listen {
			if p.Port == port {
				return true
			}
		}
		return false
	}
	inRoot := func(p string) bool {
		for _, e := range s.Exes {
			if strings.HasPrefix(p, "/proc/{pid:"+e+"}/root/") {
				return true
			}
		}
		return false
	}
	for _, m := range c.Monitors {
		ok := false
		switch check {
		case Health:
			switch m.Kind {
			case "process":
				ok = ownExe(m.ProcessExe)
			case "port":
				ok = s.Net == "" && ownPort(m.Port)
			case "http":
				ok = ownPort(urlPort(m.URL))
			case "sockets":
				ok = (ownExe(m.ProcessExe) || m.ProcessExe == "" && s.Net == "") && slices.ContainsFunc(m.ListenPorts, ownPort)
			case "command":
				ok = s.Unit != "" && slices.ContainsFunc(m.Argv, func(a string) bool { return a == s.Unit || a == strings.TrimSuffix(s.Unit, ".service") })
			}
		case Exec:
			ok = m.Kind == "process" && m.NoChildren && ownExe(m.ProcessExe)
		case Network:
			ok = m.Kind == "sockets" && (ownExe(m.ProcessExe) || m.ProcessExe == "" && s.Net == "" && slices.ContainsFunc(m.ListenPorts, ownPort)) &&
				(m.NoOutbound || len(m.ListenPorts) > 0)
		case Files:
			ok = m.Kind == "file" && slices.ContainsFunc(m.Paths, func(p string) bool {
				if s.Root != "" {
					return inRoot(p)
				}
				for _, d := range []string{"/tmp", "/var/tmp", "/dev/shm"} {
					if p == d || strings.HasPrefix(p, d+"/") {
						return true
					}
				}
				return false
			})
		case Requests:
			ok = m.Kind == "log" && (c.TapDir != "" && strings.HasPrefix(m.Path, c.TapDir) || inRoot(m.Path) ||
				s.Name != "" && strings.Contains(m.Path, "/"+s.Name))
		case Start:
			ok = m.Kind == "process" && ownExe(m.ProcessExe) ||
				m.Kind == "command" && s.Unit != "" && slices.Contains(m.Argv, s.Unit)
		}
		if ok {
			by = append(by, m.ID)
		}
	}
	switch {
	case check == Exec && isOneOf(s, loginNames) && sensorOn["auth"]:
		by = append(by, "sensor:auth")
	case check == Start && sensorOn["process"]:
		by = append(by, "sensor:process")
	}
	return by
}

func urlPort(raw string) int {
	rest := raw
	scheme, after, ok := strings.Cut(raw, "://")
	if ok {
		rest = after
	}
	host, _, _ := strings.Cut(rest, "/")
	if i := strings.LastIndex(host, ":"); i >= 0 && !strings.HasSuffix(host, "]") {
		var n int
		if _, err := fmt.Sscan(host[i+1:], &n); err == nil {
			return n
		}
	}
	if scheme == "https" {
		return 443
	}
	return 80
}
