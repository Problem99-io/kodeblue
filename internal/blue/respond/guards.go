package respond

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ---- units ----

// stoppableSuffixes are the unit types stop_unit acts on: the ones an
// attacker's persistence uses. Targets, slices, mounts and the like are the
// system itself.
var stoppableSuffixes = []string{".service", ".socket", ".timer", ".path"}

var otherUnitSuffixes = []string{".target", ".mount", ".automount", ".swap", ".slice", ".scope", ".device"}

// builtinProtectedUnits are never stopped, whatever protected_units says:
// the way in for the admins, kodeblue itself, and the system manager.
var builtinProtectedUnits = []string{"ssh", "sshd", "kodeblue*", "systemd-*", "dbus", "dbus-broker", "init", "getty*", "serial-getty*"}

// A unit is a plain name with an optional @instance, over a deliberately
// narrow character set: letters, digits and : _ . - only. No glob characters
// (*?[]), no whitespace and no leading "-" (systemctl would read those as more
// than one unit or as options), and no backslash: systemd's escaped names
// (e.g. dev-disk-by\x2duuid….device) are only .device/.mount units, which
// stop_unit does not act on anyway, so rejecting the backslash loses nothing
// and keeps shell/systemctl escaping off the table.
var unitNameRe = regexp.MustCompile(`^[A-Za-z0-9:_.-]+(@[A-Za-z0-9:_.-]*)?$`)

// normalizeUnit validates a unit name and gives it its suffix (.service when
// none, as systemctl would).
func normalizeUnit(u string) (string, error) {
	if u == "" || len(u) > 255 || strings.HasPrefix(u, "-") || !unitNameRe.MatchString(u) {
		return "", fmt.Errorf("invalid unit name %q", u)
	}
	for _, s := range otherUnitSuffixes {
		if strings.HasSuffix(u, s) {
			return "", fmt.Errorf("refusing to stop %s: only %s units can be stopped", u, strings.Join(stoppableSuffixes, " "))
		}
	}
	if unitSuffix(u) == "" {
		u += ".service"
	}
	if name := strings.TrimSuffix(u, unitSuffix(u)); name == "" || strings.HasPrefix(name, "@") || strings.HasSuffix(name, "@") {
		return "", fmt.Errorf("invalid unit name %q", u)
	}
	return u, nil
}

func unitSuffix(u string) string {
	for _, s := range stoppableSuffixes {
		if strings.HasSuffix(u, s) {
			return s
		}
	}
	return ""
}

// unitProtected reports whether a normalized unit is protected, whatever its
// type: "ssh" covers ssh.service, ssh.socket and ssh@<conn>.service.
func unitProtected(p Policy, unit string) bool {
	name := strings.TrimSuffix(unit, unitSuffix(unit))
	template, _, _ := strings.Cut(name, "@")
	for _, prot := range append(append([]string{}, builtinProtectedUnits...), p.ProtectedUnits...) {
		prot = strings.TrimSuffix(prot, unitSuffix(prot))
		if globMatch(prot, name) || globMatch(prot, template) || globMatch(prot, unit) {
			return true
		}
	}
	return false
}

// ---- users ----

// groupPath is where groups are looked up (tests point it elsewhere).
var groupPath = "/etc/group"

// adminGroups make their members administrators.
var adminGroups = []string{"sudo", "wheel", "admin"}

type passwdEntry struct {
	name        string
	uid, gid    int
	home, shell string
}

func readPasswd() []passwdEntry {
	f, err := os.Open(passwdPath)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []passwdEntry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := strings.Split(sc.Text(), ":")
		if len(p) < 7 {
			continue
		}
		uid, err1 := strconv.Atoi(p[2])
		gid, err2 := strconv.Atoi(p[3])
		if err1 != nil || err2 != nil {
			continue
		}
		out = append(out, passwdEntry{name: p[0], uid: uid, gid: gid, home: p[5], shell: p[6]})
	}
	return out
}

// adminReason says why user is an administrator kodeblue must never lock
// out ("" if not): root and every uid 0 account, members of the sudo, wheel
// and admin groups, and the policy's protected users.
func adminReason(p Policy, user string) string {
	if user == "kodeblue" {
		return "it is kodeblue's own account"
	}
	if contains(p.ProtectedUsers, user) {
		return "it is in protected_users"
	}
	var me *passwdEntry
	for _, e := range readPasswd() {
		if e.name == user {
			ee := e
			me = &ee
			break
		}
	}
	if user == "root" || (me != nil && me.uid == 0) {
		return "it has uid 0"
	}
	b, err := os.ReadFile(groupPath)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		p := strings.Split(line, ":")
		if len(p) < 4 || !contains(adminGroups, p[0]) {
			continue
		}
		if gid, err := strconv.Atoi(p[2]); err == nil && me != nil && me.gid == gid {
			return "its primary group is " + p[0]
		}
		if contains(strings.Split(p[3], ","), user) {
			return "it is a member of " + p[0]
		}
	}
	return ""
}

// keyFileOwner reports whether path is an authorized_keys file and whose it
// is ("" when no account has that home).
func keyFileOwner(path string) (user string, isKeyFile bool) {
	if !contains(sshKeyFiles, filepath.Base(path)) || filepath.Base(filepath.Dir(path)) != ".ssh" {
		return "", false
	}
	home := filepath.Dir(filepath.Dir(path))
	for _, e := range readPasswd() {
		if filepath.Clean(e.home) == home {
			return e.name, true
		}
	}
	if home == "/root" {
		return "root", true
	}
	return "", true
}

// adminKeyFile reports whose authorized_keys path is and why that user is an
// administrator (why is "" when path is not an admin's key file). Removing
// such a file locks the real admins out, so it is never quarantined. A path
// under /proc/<pid>/root is also checked as the path inside it, whatever
// process that is: a host process's /proc/<pid>/root/root/.ssh/authorized_keys
// is root's file, and telling a container's root apart at check time would
// race a pid reused by a host process before the file is moved.
func adminKeyFile(p Policy, path string) (user, why string) {
	paths := []string{path}
	if base, inner := splitProcRoot(path); base != "" {
		paths = append(paths, inner)
	}
	for _, c := range paths {
		if u, ok := keyFileOwner(c); ok && u != "" {
			if why := adminReason(p, u); why != "" {
				return u, why
			}
		}
	}
	return "", ""
}

// ---- addresses ----

// sshdConfig is read for extra SSH ports (tests point it elsewhere).
var sshdConfig = "/etc/ssh/sshd_config"

func sshPorts() map[int]bool {
	ports := map[int]bool{22: true}
	b, err := os.ReadFile(sshdConfig)
	if err != nil {
		return ports
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && strings.EqualFold(f[0], "Port") {
			if n, err := strconv.Atoi(f[1]); err == nil {
				ports[n] = true
			}
		}
	}
	return ports
}

// lookupIP resolves the hosts in InfraHosts (tests replace it).
var lookupIP = func(ctx context.Context, host string) ([]net.IP, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, a.IP)
	}
	return ips, err
}

// infraHostReason says why ip must not be blocked because it is (or may be)
// one of hosts — the hub and model endpoints kodeblue depends on, given as
// URLs or host names. It fails closed: if a host name cannot be resolved
// (a lookup error, not merely an empty answer), the address cannot be ruled
// out against it, so blocking is refused rather than risk cutting the server
// off from its hub or model. A clean "no such host" answer rules it out.
func infraHostReason(ip net.IP, hosts []string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		host := h
		if u, err := url.Parse(h); err == nil && u.Host != "" {
			host = u.Hostname()
		}
		if lit := net.ParseIP(host); lit != nil {
			if lit.Equal(ip) {
				return "it is " + h + ", which kodeblue depends on"
			}
			continue
		}
		ips, err := lookupIP(ctx, host)
		for _, a := range ips {
			if a.Equal(ip) {
				return "it is " + h + ", which kodeblue depends on"
			}
		}
		if err != nil && !isNoSuchHost(err) {
			return "it could not be ruled out against " + h + " (DNS lookup failed: " + err.Error() + "); refusing to block while that cannot be checked"
		}
	}
	return ""
}

// isNoSuchHost reports whether err is a definitive "this name does not
// resolve" (so the target is not that host), as opposed to a transient
// failure (timeout, servfail) where we must fail closed.
func isNoSuchHost(err error) bool {
	var d *net.DNSError
	return errors.As(err, &d) && d.IsNotFound
}

// KeyFileUser reports whether path is an authorized_keys file and, if a known
// account owns that home, whose. It is exported for the MCP layer's check.
func KeyFileUser(path string) (user string, isKeyFile bool) { return keyFileOwner(path) }

// AdminReason says why user is an administrator kodeblue must not lock out or
// cut off ("" if not). Exported for the MCP layer's check.
func AdminReason(p Policy, user string) string { return adminReason(p, user) }

// AdminKeyFile reports whether path is an administrator's authorized_keys
// file (why != ""), as Check refuses to quarantine it. Exported for the MCP
// layer's check, which explains the refusal to the agent.
func AdminKeyFile(p Policy, path string) (user, why string) { return adminKeyFile(p, path) }
