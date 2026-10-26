// Package respond performs containment actions on the host. It is the only
// part of kodeblue that changes the server, and it is built to be safe to hand
// to an automated responder:
//
//   - It runs as root only as `kodeblue respond exec`, started per request
//     by the kodeblue-respond.socket unit that only the kodeblue user can
//     connect to. The kodeblue user itself is unprivileged.
//   - It acts on paths other users control (homes, /tmp) without following
//     their symlinks (see safefs.go).
//   - Policy (mode, allowed actions, protected users/IPs/units, rate limit) is
//     read by the root helper from the root-owned /etc/kodeblue/kodeblue.toml,
//     so a compromised kodeblue user cannot widen it.
//   - Every action is journaled with its undo recipe, and all but
//     kill_process can be undone (see Undoable).
package respond

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var modeOrder = []string{"off", "recommend", "contain"}

// Ceiling is the highest mode this server may run: Mode, or HubMaxMode when
// a hub may set the mode (hubSettings) and it is higher.
func (p Policy) Ceiling(hubSettings bool) string {
	if hubSettings && slices.Index(modeOrder, p.HubMaxMode) > slices.Index(modeOrder, p.Mode) {
		return p.HubMaxMode
	}
	return p.Mode
}

// HubMayAutomate reports whether root let a hub turn on actions that run
// without a person looking each time: mode or hub_max_mode is contain. A
// hub approval of a containment rule counts only then.
func (p Policy) HubMayAutomate() bool { return p.Ceiling(true) == "contain" }

// Policy governs what the helper will do.
type Policy struct {
	// Mode: off | recommend | contain. recommend records the request for an
	// operator to approve with `kodeblue respond approve <id>`.
	Mode string `toml:"mode"`
	// HubMaxMode is the highest mode a kodeblue hub may switch this server
	// to (off | recommend | contain); empty or lower than Mode: none above
	// Mode. The helper cannot see the hub's choice, so above Mode it trusts
	// the kodeblue daemon to apply it: with "contain" here, an agent's
	// actions run without an operator's approval whenever the daemon says
	// the hub chose contain. That is why only root can set it.
	HubMaxMode     string   `toml:"hub_max_mode"`
	AllowedActions []string `toml:"allowed_actions"`
	ProtectedUsers []string `toml:"protected_users"`
	ProtectedIPs   []string `toml:"protected_ips"` // IPs or CIDRs
	// RefusePrivateIPs makes block_ip refuse every private address. By
	// default a private address may be blocked when it is only a client of
	// this server (an attacker elsewhere on the network), never when the
	// server depends on it (gateway, resolver, a peer it connects out to,
	// an SSH session).
	RefusePrivateIPs  bool     `toml:"refuse_private_ips"`
	ProtectedUnits    []string `toml:"protected_units"`
	MaxActionsPerHour int      `toml:"max_actions_per_hour"`
	StateDir          string   `toml:"-"`
	// InfraHosts are hosts kodeblue itself depends on — the hub and the model
	// endpoints — whose addresses block_ip refuses whether public or private.
	// The root helper fills this from the root-owned config, not the request.
	InfraHosts []string `toml:"-"`
}

func DefaultPolicy() Policy {
	return Policy{
		Mode:              "recommend",
		AllowedActions:    []string{"kill_process", "quarantine_file", "block_ip", "disable_ssh_key", "lock_user", "stop_unit"},
		ProtectedUsers:    []string{"root"},
		ProtectedUnits:    []string{"ssh", "sshd", "kodeblue", "systemd-*", "dbus", "networking", "systemd-networkd", "systemd-resolved", "docker", "containerd"},
		MaxActionsPerHour: 10,
	}
}

// Request is what the agent asks for.
type Request struct {
	ID            string            `json:"id"`
	IncidentID    int64             `json:"incident_id"`
	Action        string            `json:"action"`
	Params        map[string]string `json:"params"`
	Justification string            `json:"justification"`
	RequestedBy   string            `json:"requested_by"`
	RequestedAt   time.Time         `json:"requested_at"`
}

// Record is a journal line.
type Record struct {
	Request
	Status   string            `json:"status"` // pending | done | failed | undone | refused
	Result   string            `json:"result"`
	Undo     map[string]string `json:"undo,omitempty"`
	DoneAt   time.Time         `json:"done_at,omitempty"`
	UndoneAt time.Time         `json:"undone_at,omitempty"`
}

var actionParams = map[string][]string{
	"kill_process":    {"pid", "expect_exe"},
	"quarantine_file": {"path"},
	"block_ip":        {"ip"},
	"disable_ssh_key": {"user", "key_id"},
	"lock_user":       {"user"},
	"stop_unit":       {"unit"},
}

// ActionNames lists every containment action, sorted.
func ActionNames() []string {
	names := make([]string, 0, len(actionParams))
	for name := range actionParams {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Check validates a request against policy without executing it.
func Check(p Policy, r Request) error {
	need, ok := actionParams[r.Action]
	if !ok {
		return fmt.Errorf("unknown action %q", r.Action)
	}
	if !contains(p.AllowedActions, r.Action) {
		return fmt.Errorf("action %q is not enabled by policy", r.Action)
	}
	for _, k := range need {
		if strings.TrimSpace(r.Params[k]) == "" {
			return fmt.Errorf("param %q is required for %s", k, r.Action)
		}
	}
	if len(strings.TrimSpace(r.Justification)) < 20 {
		return errors.New("justification must explain the evidence (>= 20 chars)")
	}
	switch r.Action {
	case "kill_process":
		pid, err := strconv.Atoi(r.Params["pid"])
		if err != nil || pid <= 1 {
			return errors.New("invalid pid")
		}
		if pid == os.Getpid() || pid == os.Getppid() {
			return errors.New("refusing to kill kodeblue itself")
		}
	case "quarantine_file":
		if err := checkQuarantinePath(r.Params["path"]); err != nil {
			return err
		}
		// Enforced here, not only in the MCP layer: the unprivileged side can
		// skip its own checks and call the helper directly.
		if user, why := adminKeyFile(p, r.Params["path"]); why != "" {
			return fmt.Errorf("refusing to quarantine %s: it is %s's authorized_keys and %s (disable the specific planted key instead)", r.Params["path"], user, why)
		}
	case "block_ip":
		ip := net.ParseIP(r.Params["ip"])
		if ip == nil {
			return errors.New("invalid ip")
		}
		if v4 := ip.To4(); v4 != nil {
			ip = v4 // ::ffff:a.b.c.d, as access logs write IPv4 clients
		}
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
			return errors.New("refusing to block a loopback/link-local/multicast address")
		}
		// Infrastructure this server depends on is never blocked, public or
		// private: its own addresses, gateway, resolvers, the hub and model
		// endpoints, and admins in a live SSH session.
		if why := infraReason(ip, p.InfraHosts); why != "" {
			return fmt.Errorf("refusing to block %s: %s", ip, why)
		}
		if ip.IsPrivate() && p.RefusePrivateIPs {
			return errors.New("refusing to block a private address (refuse_private_ips is set)")
		}
		for _, prot := range p.ProtectedIPs {
			if _, cidr, err := net.ParseCIDR(prot); err == nil && cidr.Contains(ip) {
				return fmt.Errorf("%s is protected (%s)", ip, prot)
			}
			if net.ParseIP(prot).Equal(ip) {
				return fmt.Errorf("%s is protected", ip)
			}
		}
	case "disable_ssh_key":
		// A planted key may be removed from any user's file, but never from an
		// administrator kodeblue must not lock out (root, uid 0, sudo/wheel/
		// admin members, protected_users). keyID must be a full fingerprint
		// so a prefix cannot sweep up the admin's real key with the attacker's.
		if why := adminReason(p, r.Params["user"]); why != "" {
			return fmt.Errorf("refusing to touch %s's keys: %s", r.Params["user"], why)
		}
		if !fullKeyID(r.Params["key_id"]) {
			return errors.New("key_id must be a full key fingerprint (the ssh_key item hash: 16 or 64 hex chars), not a short prefix")
		}
	case "lock_user":
		if why := adminReason(p, r.Params["user"]); why != "" {
			return fmt.Errorf("user %q is protected: %s", r.Params["user"], why)
		}
	case "stop_unit":
		unit, err := normalizeUnit(r.Params["unit"])
		if err != nil {
			return err
		}
		if unitProtected(p, unit) {
			return fmt.Errorf("unit %q is protected", unit)
		}
	}
	return nil
}

// fullKeyID reports whether k is a whole key fingerprint: the 16-hex short
// form the ssh_key sensor publishes, or the full 64-hex sha256. A shorter
// value is a prefix that could match several keys and is refused.
func fullKeyID(k string) bool {
	if len(k) != 16 && len(k) != 64 {
		return false
	}
	for _, c := range k {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// keyMatches reports whether the line's sha256 fingerprint is the one keyID
// names (whole short or full form, never a prefix).
func keyMatches(line, keyID string) bool {
	h := sha256.Sum256([]byte(strings.TrimSpace(line)))
	full := hex.EncodeToString(h[:])
	switch len(keyID) {
	case 64:
		return full == keyID
	case 16:
		return full[:16] == keyID
	}
	return false
}

var quarantineAllowedRoots = []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/home/", "/root/", "/opt/", "/srv/", "/var/www/", "/etc/cron.d/", "/etc/cron.hourly/", "/etc/cron.daily/", "/etc/systemd/system/", "/etc/profile.d/", "/etc/ld.so.preload", "/var/spool/cron/", "/usr/local/bin/", "/usr/local/sbin/", "/run/user/"}

func checkQuarantinePath(p string) error {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return errors.New("path must be absolute and clean")
	}
	// A workload's file seen through its /proc/<pid>/root follows the same
	// rules as the path inside it.
	if base, inner := splitProcRoot(p); base != "" {
		if base == fmt.Sprintf("/proc/%d/root", os.Getpid()) {
			return errors.New("refusing to quarantine kodeblue's own files")
		}
		p = inner
	}
	if strings.Contains(p, "kodeblue") {
		return errors.New("refusing to quarantine kodeblue's own files")
	}
	for _, root := range quarantineAllowedRoots {
		if strings.HasPrefix(p, root) || p == strings.TrimSuffix(root, "/") {
			return nil
		}
	}
	return fmt.Errorf("quarantine is limited to non-system locations (%s); system binaries must be restored from packages by a human", strings.Join(quarantineAllowedRoots, " "))
}

// Execute performs a request and journals its outcome. It must run as root
// (the respond helper). It holds an exclusive lock on the journal for the
// whole check–act–record so concurrent requests (the socket accepts several)
// cannot both slip past the rate limit or both act on one target, and so a
// forged or tampered journal is never acted on. The returned record has
// already been appended; callers must not append it again.
func Execute(p Policy, r Request) Record { return executeWith(p, r, nil) }

// executeWith is Execute with guard, an extra check made under the journal
// lock (a containment rule's scope and hourly limit) before acting.
func executeWith(p Policy, r Request, guard func(*journal, []Record) error) Record {
	rec := Record{Request: r, Status: "failed"}
	if err := Check(p, r); err != nil {
		rec.Status, rec.Result = "refused", err.Error()
		return rec
	}
	j, err := openJournal(p.StateDir)
	if err != nil {
		rec.Status, rec.Result = "refused", "journal unavailable: "+err.Error()
		return rec
	}
	defer j.Close()
	records, err := j.records()
	if err != nil {
		rec.Status, rec.Result = "refused", "journal unreadable: "+err.Error()
		return rec
	}
	if guard != nil {
		if err := guard(j, records); err != nil {
			rec.Status, rec.Result = "refused", err.Error()
			_ = j.append(rec)
			return rec
		}
	}
	// Concurrent incidents about the same attack often ask for the same
	// action; answer from the journal instead of acting twice.
	for _, prev := range records {
		if prev.Status == "done" && prev.ID == r.ID && !prev.DoneAt.IsZero() {
			// The same request, carried out already (a retried call whose
			// answer was lost): its record untouched, so its undo recipe and
			// its place in the rate count stay.
			return prev
		}
		if prev.Status != "done" || prev.Action != r.Action || !sameTarget(prev.Params, r.Params) {
			continue
		}
		if stillInEffect(prev) {
			rec.Status, rec.Result = "done", "already done by "+prev.ID+" (incident #"+fmt.Sprint(prev.IncidentID)+"): "+prev.Result
			_ = j.append(rec)
			return rec
		}
		// A lapsed block is booked as over, so undoing it later cannot remove
		// the rule this request puts in place. (A quarantined file stays
		// quarantined: the one now at its path is a new file.)
		if prev.Action == "block_ip" {
			prev.Status, prev.UndoneAt = "undone", time.Now()
			prev.Result += "; found no longer in effect, applied again by " + r.ID
			_ = j.append(prev)
		}
	}
	if n := countRecentIn(records, time.Hour); p.MaxActionsPerHour > 0 && n >= p.MaxActionsPerHour {
		rec.Status, rec.Result = "refused", fmt.Sprintf("rate limit: %d actions in the last hour", n)
		_ = j.append(rec)
		return rec
	}
	switch r.Action {
	case "kill_process":
		rec.Undo, rec.Result, err = killProcess(p, r.Params)
	case "quarantine_file":
		rec.Undo, rec.Result, err = quarantine(p, r.Params["path"])
	case "block_ip":
		rec.Undo, rec.Result, err = blockIP(r.Params["ip"])
	case "disable_ssh_key":
		rec.Undo, rec.Result, err = disableKey(p.StateDir, r.Params["user"], r.Params["key_id"])
	case "lock_user":
		rec.Undo, rec.Result, err = lockUser(r.Params["user"])
	case "stop_unit":
		unit, _ := normalizeUnit(r.Params["unit"])
		rec.Undo, rec.Result, err = stopUnit(unit)
	}
	if err != nil {
		rec.Result = err.Error()
		_ = j.append(rec)
		return rec
	}
	rec.Status, rec.DoneAt = "done", time.Now()
	_ = j.append(rec)
	return rec
}

// UndoByID reverses a completed record under the journal lock and records the
// reversal. It must run as root (the respond helper).
func UndoByID(p Policy, id string) (Record, error) {
	j, err := openJournal(p.StateDir)
	if err != nil {
		return Record{}, fmt.Errorf("journal unavailable: %w", err)
	}
	defer j.Close()
	rec, err := j.find(id)
	if err != nil {
		return Record{}, err
	}
	if rec == nil {
		return Record{}, fmt.Errorf("no action %s", id)
	}
	if err := undo(p, rec); err != nil {
		return *rec, err
	}
	_ = j.append(*rec)
	return *rec, nil
}

func killProcess(p Policy, params map[string]string) (map[string]string, string, error) {
	pid, _ := strconv.Atoi(params["pid"])
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return nil, "", fmt.Errorf("process %d not found: %v", pid, err)
	}
	clean := strings.TrimSuffix(exe, " (deleted)")
	if clean != params["expect_exe"] {
		return nil, "", fmt.Errorf("pid %d is now %s, not %s (pid reuse?) — refusing", pid, clean, params["expect_exe"])
	}
	if strings.Contains(clean, "kodeblue") || clean == "/sbin/init" || clean == "/usr/lib/systemd/systemd" || clean == "/lib/systemd/systemd" {
		return nil, "", errors.New("refusing to kill a protected process")
	}
	if reason := killJustified(pid, exe, params); reason == "" {
		return nil, "", fmt.Errorf("refusing to kill pid %d (%s): it is a packaged binary in a normal location with no public network connection and is not referenced by the incident's evidence. Recommend it to a human instead", pid, clean)
	}
	// Preserve the binary for forensics before it disappears.
	qdir := filepath.Join(p.StateDir, "quarantine", fmt.Sprintf("%d-pid%d", time.Now().Unix(), pid))
	_ = os.MkdirAll(qdir, 0o700)
	sum := copyFile(fmt.Sprintf("/proc/%d/exe", pid), filepath.Join(qdir, "exe"))
	if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil {
		_ = os.WriteFile(filepath.Join(qdir, "cmdline"), b, 0o600)
	}
	_ = syscall.Kill(pid, syscall.SIGSTOP)
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		return nil, "", err
	}
	if sum == "" {
		return map[string]string{"note": "process killed; its binary could not be preserved"}, fmt.Sprintf("killed pid %d (%s); its binary could not be copied, other evidence in %s", pid, clean, qdir), nil
	}
	return map[string]string{"note": "process killed; binary preserved at " + qdir, "evidence": qdir}, fmt.Sprintf("killed pid %d (%s), sha256 %s, evidence in %s", pid, clean, sum, qdir), nil
}

// killJustified returns why killing pid is defensible, or "" if it is not.
// An agent may only kill what looks like attacker tooling: a dropped or
// deleted binary, an unpackaged executable, a process talking to the
// internet (reverse shells, miners), or a process the incident's own
// evidence names. Ordinary packaged processes (an admin's shell, a service)
// need a human.
func killJustified(pid int, exe string, params map[string]string) string {
	clean := strings.TrimSuffix(exe, " (deleted)")
	switch {
	case strings.HasSuffix(exe, " (deleted)"):
		return "deleted executable"
	case strings.HasPrefix(clean, "/memfd:"), strings.HasPrefix(clean, "/tmp/"), strings.HasPrefix(clean, "/var/tmp/"), strings.HasPrefix(clean, "/dev/shm/"), strings.Contains(clean, "/."):
		return "suspicious location"
	case params["incident_linked"] == "true":
		return "referenced by incident evidence"
	}
	if out, err := exec.Command("dpkg", "-S", clean).CombinedOutput(); err != nil || strings.Contains(string(out), "no path found") {
		if _, rerr := exec.LookPath("rpm"); rerr != nil || exec.Command("rpm", "-qf", clean).Run() != nil {
			return "not owned by any package"
		}
	}
	if hasPublicConnection(pid) {
		return "holds a connection to a public address"
	}
	return ""
}

func hasPublicConnection(pid int) bool {
	inodes := map[string]bool{}
	fds, _ := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	for _, fd := range fds {
		if l, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, fd.Name())); err == nil && strings.HasPrefix(l, "socket:[") {
			inodes[strings.TrimSuffix(strings.TrimPrefix(l, "socket:["), "]")] = true
		}
	}
	for _, f := range []string{"tcp", "tcp6"} {
		b, err := os.ReadFile(fmt.Sprintf("/proc/%d/net/%s", pid, f))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n")[1:] {
			fl := strings.Fields(line)
			if len(fl) < 10 || fl[3] != "01" || !inodes[fl[9]] {
				continue
			}
			parts := strings.Split(fl[2], ":")
			raw, err := hex.DecodeString(parts[0])
			if err != nil || len(raw) < 4 {
				continue
			}
			ip := net.IP{raw[3], raw[2], raw[1], raw[0]}
			if len(raw) == 16 {
				ip = make(net.IP, 16)
				for i := 0; i < 16; i += 4 {
					ip[i], ip[i+1], ip[i+2], ip[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
				}
			}
			if !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()) {
				return true
			}
		}
	}
	return false
}

func quarantine(p Policy, path string) (map[string]string, string, error) {
	dir, name := filepath.Dir(path), filepath.Base(path)
	dfd, err := openDir(dir)
	if err != nil {
		return nil, "", err
	}
	defer unix.Close(dfd)
	src, err := openIn(dfd, dir, name, unix.O_RDONLY, 0)
	if err != nil {
		return nil, "", err
	}
	defer src.Close()
	st, err := regularFile(src)
	if err != nil {
		return nil, "", fmt.Errorf("refusing to quarantine: %w", err)
	}
	qdir := filepath.Join(p.StateDir, "quarantine", fmt.Sprintf("%d-%s", time.Now().UnixNano(), shortHash(path)))
	if err := os.MkdirAll(qdir, 0o700); err != nil {
		return nil, "", err
	}
	dest := filepath.Join(qdir, "file")
	sum, err := copyTo(dest, src, 0)
	if err != nil {
		return nil, "", fmt.Errorf("could not copy file to quarantine: %w", err)
	}
	mode := strconv.FormatUint(uint64(st.Mode&0o777), 8)
	meta, _ := json.Marshal(map[string]any{"path": path, "mode": mode, "uid": st.Uid, "gid": st.Gid, "sha256": sum})
	_ = os.WriteFile(filepath.Join(qdir, "meta.json"), meta, 0o600)
	// Unlink the name in the directory we opened, not the path: the path
	// may have been swapped for a link to somewhere else since.
	if err := unix.Unlinkat(dfd, name, 0); err != nil {
		return nil, "", &os.PathError{Op: "remove", Path: path, Err: err}
	}
	return map[string]string{"restore_from": dest, "restore_to": path, "mode": mode, "uid": fmt.Sprint(st.Uid), "gid": fmt.Sprint(st.Gid)},
		fmt.Sprintf("moved %s (sha256 %s) to %s", path, sum, dest), nil
}

// restore puts a quarantined file back. It never replaces whatever is at
// the original path now, reads only from this helper's own quarantine store
// (so a record cannot point the copy at an arbitrary source), and the
// destination must still be a quarantine-allowed location.
func restore(stateDir string, u map[string]string) error {
	from := filepath.Clean(u["restore_from"])
	qroot := filepath.Join(stateDir, "quarantine") + string(os.PathSeparator)
	if !strings.HasPrefix(from, qroot) {
		return fmt.Errorf("refusing to restore from %s: not in the quarantine store", u["restore_from"])
	}
	to := u["restore_to"]
	// The destination must be one quarantine itself would accept: a record can
	// only ever name a place a file was legitimately taken from.
	if err := checkQuarantinePath(to); err != nil {
		return fmt.Errorf("refusing to restore to %s: %w", to, err)
	}
	dir, name := filepath.Dir(to), filepath.Base(to)
	dfd, err := openDir(dir)
	if err != nil {
		return err
	}
	defer unix.Close(dfd)
	_ = os.Chmod(from, 0o400) // quarantined copies are 0000
	in, err := os.Open(from)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := openIn(dfd, dir, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("%s exists again; restore it by hand from %s", to, u["restore_from"])
	}
	if err != nil {
		return err
	}
	uid, _ := strconv.Atoi(u["uid"])
	gid, _ := strconv.Atoi(u["gid"])
	mode, _ := strconv.ParseUint(u["mode"], 8, 32)
	_, err = io.Copy(out, in)
	if err == nil {
		// chown first: it clears set-id bits that chmod then sets.
		err = out.Chown(uid, gid)
	}
	if err == nil {
		err = out.Chmod(os.FileMode(mode & 0o777))
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = unix.Unlinkat(dfd, name, 0)
		return fmt.Errorf("restore %s: %w", to, err)
	}
	return nil
}

// stillInEffect reports whether a done action still holds on the host. A
// firewall rule can vanish without kodeblue (a flush, a reboot, a container
// restart that gives the app a fresh network namespace), and an attacker can
// drop a file again where one was quarantined; the journal entry must not
// then stop the action from being taken again.
func stillInEffect(rec Record) bool {
	switch rec.Action {
	case "block_ip":
		return blockActive(rec.Undo)
	case "quarantine_file":
		_, err := os.Lstat(rec.Params["path"])
		return errors.Is(err, fs.ErrNotExist)
	}
	return true
}

// blockActive reports whether the rules a block_ip put in place are still
// there. When the firewall tool is gone it cannot tell and says yes.
var blockActive = func(u map[string]string) bool {
	switch u["cmd"] {
	case "iptables", "ip6tables":
		if _, err := exec.LookPath(u["cmd"]); err != nil {
			return true
		}
		if !iptRule(u["cmd"], "INPUT", u["ip"]) {
			return false
		}
		return u["docker_user"] != "true" || iptRule(u["cmd"], "DOCKER-USER", u["ip"])
	case "nft":
		out, err := exec.Command("nft", "list", "chain", "inet", "kodeblue", "input").Output()
		if err != nil {
			_, lerr := exec.LookPath("nft")
			return lerr != nil
		}
		return nftHasIP(string(out), u["ip"])
	}
	return true
}

// iptRule reports whether chain has kodeblue's DROP rule for ip.
func iptRule(bin, chain, ip string) bool {
	return exec.Command(bin, "-C", chain, "-s", ip, "-m", "comment", "--comment", "kodeblue", "-j", "DROP").Run() == nil
}

// nftHasIP reports whether an nft chain listing has a rule for ip.
func nftHasIP(listing, ip string) bool {
	for _, line := range strings.Split(listing, "\n") {
		f := strings.Fields(line)
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "saddr" && f[i+1] == ip {
				return true
			}
		}
	}
	return false
}

func blockIP(ip string) (map[string]string, string, error) {
	if p := net.ParseIP(ip); p != nil {
		ip = p.String() // ::ffff:a.b.c.d becomes a.b.c.d, an iptables rule
	}
	bin := "iptables"
	if strings.Contains(ip, ":") {
		bin = "ip6tables"
	}
	if _, err := exec.LookPath(bin); err == nil {
		out, err := exec.Command(bin, "-I", "INPUT", "1", "-s", ip, "-m", "comment", "--comment", "kodeblue", "-j", "DROP").CombinedOutput()
		if err != nil {
			return nil, "", fmt.Errorf("%s: %v %s", bin, err, out)
		}
		undo := map[string]string{"cmd": bin, "ip": ip}
		res := "dropped inbound traffic from " + ip + " via " + bin
		// Traffic to Docker containers is forwarded, not delivered: INPUT
		// never sees it. DOCKER-USER is the chain Docker leaves for this.
		if exec.Command(bin, "-n", "-L", "DOCKER-USER").Run() == nil {
			if out, err := exec.Command(bin, "-I", "DOCKER-USER", "1", "-s", ip, "-m", "comment", "--comment", "kodeblue", "-j", "DROP").CombinedOutput(); err == nil {
				undo["docker_user"] = "true"
				res += " (host and Docker containers)"
			} else {
				res += fmt.Sprintf(" (host only; DOCKER-USER: %v %s)", err, out)
			}
		}
		return undo, res, nil
	}
	if _, err := exec.LookPath("nft"); err == nil {
		fam := "ip"
		if strings.Contains(ip, ":") {
			fam = "ip6"
		}
		_ = exec.Command("nft", "add", "table", "inet", "kodeblue").Run()
		_ = exec.Command("nft", "add", "chain", "inet", "kodeblue", "input", "{ type filter hook input priority -10 ; }").Run()
		out, err := exec.Command("nft", "add", "rule", "inet", "kodeblue", "input", fam, "saddr", ip, "drop", "comment", "\"kodeblue\"").CombinedOutput()
		if err != nil {
			return nil, "", fmt.Errorf("nft: %v %s", err, out)
		}
		return map[string]string{"cmd": "nft", "ip": ip, "family": fam}, "dropped inbound traffic from " + ip + " via nft", nil
	}
	return nil, "", errors.New("neither iptables nor nft available")
}

// passwdPath is where users are looked up (tests point it elsewhere).
var passwdPath = "/etc/passwd"

// sshKeyFiles are the files in ~/.ssh that disable_ssh_key edits.
var sshKeyFiles = []string{"authorized_keys", "authorized_keys2"}

const maxKeyFileSize = 1 << 20

func lookupUser(user string) (home string, uid int, err error) {
	f, err := os.Open(passwdPath)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Split(sc.Text(), ":")
		if len(parts) >= 6 && parts[0] == user {
			if uid, err = strconv.Atoi(parts[2]); err == nil && parts[5] != "" {
				return parts[5], uid, nil
			}
		}
	}
	return "", 0, fmt.Errorf("unknown user %s", user)
}

// disableKey comments out the one key whose fingerprint is exactly keyID. It
// refuses unless exactly one key across the user's authorized_keys files
// matches, so a fingerprint can never sweep up an admin's key alongside an
// attacker's. The file is edited through a descriptor opened without
// following links, and the backup goes to the root-owned state dir.
func disableKey(stateDir, user, keyID string) (map[string]string, string, error) {
	home, uid, err := lookupUser(user)
	if err != nil {
		return nil, "", err
	}
	sshDir := filepath.Join(home, ".ssh")
	dfd, err := openDir(sshDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, "", fmt.Errorf("key %s not found for %s", keyID, user)
	}
	if err != nil {
		return nil, "", err
	}
	defer unix.Close(dfd)
	// First pass: count matches across every file, so uniqueness spans them.
	matches, matchFile := 0, ""
	for _, name := range sshKeyFiles {
		f, err := openIn(dfd, sshDir, name, unix.O_RDWR, 0)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, "", err
		}
		b, err := readKeyFile(f, uid)
		f.Close()
		if err != nil {
			return nil, "", err
		}
		for _, line := range strings.Split(string(b), "\n") {
			if t := strings.TrimSpace(line); t != "" && !strings.HasPrefix(t, "#") && keyMatches(t, keyID) {
				matches++
				matchFile = name
			}
		}
	}
	switch {
	case matches == 0:
		return nil, "", fmt.Errorf("key %s not found for %s", keyID, user)
	case matches > 1:
		return nil, "", fmt.Errorf("key %s matches %d keys for %s; refusing (report it to a human)", keyID, matches, user)
	}
	f, err := openIn(dfd, sshDir, matchFile, unix.O_RDWR, 0)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	return disableKeyIn(f, uid, keyID, filepath.Join(stateDir, "ssh-keys"), user+"-"+matchFile)
}

// disableKeyIn re-reads f (so nothing changed since the counting pass),
// comments out the one line matching keyID and backs the file up. It refuses
// if the file no longer holds exactly one matching key.
func disableKeyIn(f *os.File, uid int, keyID, backupDir, backupName string) (map[string]string, string, error) {
	b, err := readKeyFile(f, uid)
	if err != nil {
		return nil, "", err
	}
	now := time.Now().UTC()
	marker := "# kodeblue-disabled " + now.Format(time.RFC3339) + " "
	lines := strings.Split(string(b), "\n")
	hits := 0
	for i, line := range lines {
		tr := strings.TrimSpace(line)
		if tr == "" || strings.HasPrefix(tr, "#") {
			continue
		}
		if keyMatches(tr, keyID) {
			lines[i] = marker + line
			hits++
		}
	}
	if hits != 1 {
		return nil, "", fmt.Errorf("key %s now matches %d keys in %s; refusing", keyID, hits, f.Name())
	}
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		return nil, "", err
	}
	backup := filepath.Join(backupDir, fmt.Sprintf("%d-%s", now.UnixNano(), backupName))
	if err := writeNew(backup, b); err != nil {
		return nil, "", fmt.Errorf("backup failed, key left enabled: %w", err)
	}
	if err := rewrite(f, []byte(strings.Join(lines, "\n"))); err != nil {
		return nil, "", err
	}
	path := f.Name()
	return map[string]string{"file": path, "uid": strconv.Itoa(uid), "marker": marker, "backup": backup},
		"disabled key " + keyID + " in " + path + " (backup " + backup + ")", nil
}

// enableKey undoes disableKey by removing its marker, keeping any other
// changes made to the file since.
func enableKey(u map[string]string) error {
	path, marker := u["file"], u["marker"]
	uid, err := strconv.Atoi(u["uid"])
	if marker == "" || err != nil {
		return fmt.Errorf("this record has no undo marker; restore %s by hand from %s", path, u["backup"])
	}
	dir, name := filepath.Dir(path), filepath.Base(path)
	if filepath.Base(dir) != ".ssh" || !contains(sshKeyFiles, name) {
		return fmt.Errorf("%s is not an authorized_keys file", path)
	}
	dfd, err := openDir(dir)
	if err != nil {
		return err
	}
	defer unix.Close(dfd)
	f, err := openIn(dfd, dir, name, unix.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := readKeyFile(f, uid)
	if err != nil {
		return err
	}
	lines := strings.Split(string(b), "\n")
	n := 0
	for i, line := range lines {
		if rest, ok := strings.CutPrefix(line, marker); ok {
			lines[i] = rest
			n++
		}
	}
	if n == 0 {
		return fmt.Errorf("no key disabled by this action is left in %s", path)
	}
	return rewrite(f, []byte(strings.Join(lines, "\n")))
}

// readKeyFile reads an authorized_keys file the helper may rewrite: a
// regular file with one link, owned by its user or root.
func readKeyFile(f *os.File, uid int) ([]byte, error) {
	st, err := regularFile(f)
	if err != nil {
		return nil, err
	}
	if st.Nlink != 1 { // a hard link to /etc/shadow has two
		return nil, errors.New(f.Name() + " has more than one hard link")
	}
	if int(st.Uid) != uid && st.Uid != 0 {
		return nil, fmt.Errorf("%s is owned by uid %d, not its user", f.Name(), st.Uid)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxKeyFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxKeyFileSize {
		return nil, errors.New(f.Name() + " is too large")
	}
	return b, nil
}

// rewrite replaces f's contents in place, keeping its owner and mode.
func rewrite(f *os.File, b []byte) error {
	if _, err := f.WriteAt(b, 0); err != nil {
		return err
	}
	if err := f.Truncate(int64(len(b))); err != nil {
		return err
	}
	return f.Sync()
}
func lockUser(user string) (map[string]string, string, error) {
	// Remember the account's expiry and lock state first, so undo restores
	// them instead of clearing an expiry the admins had set or unlocking a
	// password that was already locked.
	u := map[string]string{"user": user}
	if b, err := os.ReadFile("/etc/shadow"); err == nil {
		if expire, locked, ok := shadowState(b, user); ok {
			u["prev_expire"] = expire
			if locked {
				u["was_locked"] = "true"
			}
		}
	}
	out, err := exec.Command("usermod", "-L", "-e", "1", user).CombinedOutput()
	if err != nil {
		return nil, "", fmt.Errorf("usermod: %v %s", err, out)
	}
	// End the user's live sessions; locking alone does not.
	_ = exec.Command("pkill", "-KILL", "-u", user).Run()
	return u, "locked " + user + " (password locked, account expired) and killed their processes", nil
}

// shadowState reads user's account expiry (the 8th field: days since the
// epoch, empty for none) and whether the password is already locked from
// /etc/shadow content. ok is false when the entry is missing or malformed.
func shadowState(b []byte, user string) (expire string, locked, ok bool) {
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Split(strings.TrimRight(line, "\r"), ":")
		if len(f) < 8 || f[0] != user {
			continue
		}
		expire = strings.TrimSpace(f[7])
		if expire != "" {
			if n, err := strconv.Atoi(expire); err != nil || n < 0 {
				return "", false, false
			}
		}
		return expire, strings.HasPrefix(f[1], "!"), true
	}
	return "", false, false
}

// unlockArgs are the usermod arguments that undo lock_user: the recorded
// expiry is restored (records from before it was recorded clear it, as undo
// always did), and the password is unlocked only if lock_user locked it. The
// expiry is re-checked so a tampered record cannot pass other arguments.
func unlockArgs(u map[string]string) []string {
	expire := u["prev_expire"]
	if n, err := strconv.Atoi(expire); err != nil || n < 0 {
		expire = ""
	}
	if u["was_locked"] == "true" {
		return []string{"-e", expire, u["user"]}
	}
	return []string{"-U", "-e", expire, u["user"]}
}

func stopUnit(unit string) (map[string]string, string, error) {
	wasEnabled := exec.Command("systemctl", "is-enabled", "--quiet", unit).Run() == nil
	out, err := exec.Command("systemctl", "stop", unit).CombinedOutput()
	if err != nil {
		return nil, "", fmt.Errorf("systemctl stop: %v %s", err, out)
	}
	_ = exec.Command("systemctl", "disable", unit).Run()
	return map[string]string{"unit": unit, "was_enabled": strconv.FormatBool(wasEnabled)}, "stopped and disabled " + unit, nil
}

// Undoable reports whether a completed action can be undone: all but
// kill_process, since a killed process cannot be revived.
func Undoable(action string) bool { return action != "kill_process" }

// Undo reverses a completed record without the journal lock. It is for the
// live firewall test; the helper uses UndoByID, which holds the lock.
func Undo(rec *Record) error { return undo(Policy{}, rec) }

// undo reverses a completed record. The undo recipe comes from the root-owned
// journal, but the firewall tool is still chosen by name (never run from the
// record) and the IP is re-validated, so a tampered recipe cannot run an
// arbitrary command as root.
func undo(p Policy, rec *Record) error {
	if rec.Status != "done" {
		return fmt.Errorf("record %s is %s, not done", rec.ID, rec.Status)
	}
	u := rec.Undo
	var err error
	switch rec.Action {
	case "kill_process":
		return errors.New("a killed process cannot be revived; restart its service if it was legitimate")
	case "quarantine_file":
		err = restore(p.StateDir, u)
	case "block_ip":
		err = unblockIP(u)
	case "disable_ssh_key":
		err = enableKey(u)
	case "lock_user":
		err = exec.Command("usermod", unlockArgs(u)...).Run()
	case "stop_unit":
		unit, nerr := normalizeUnit(u["unit"])
		if nerr != nil {
			return nerr
		}
		if u["was_enabled"] == "true" {
			_ = exec.Command("systemctl", "enable", unit).Run()
		}
		err = exec.Command("systemctl", "start", unit).Run()
	}
	if err != nil {
		return err
	}
	rec.Status, rec.UndoneAt = "undone", time.Now()
	return nil
}

// unblockIP removes a block_ip rule. The firewall tool is fixed by name and
// the address re-parsed, so the recipe can name only iptables/ip6tables/nft
// and a valid IP.
func unblockIP(u map[string]string) error {
	ip := net.ParseIP(u["ip"])
	if ip == nil {
		return fmt.Errorf("undo block_ip: invalid ip %q in record", u["ip"])
	}
	addr := ip.String()
	if u["cmd"] == "nft" {
		// Flush only our own table's rule for this address.
		out, _ := exec.Command("nft", "-a", "list", "chain", "inet", "kodeblue", "input").Output()
		var err error
		for _, line := range strings.Split(string(out), "\n") {
			if nftHasIP(line, addr) && strings.Contains(line, "# handle ") {
				h := strings.TrimSpace(line[strings.LastIndex(line, "# handle ")+9:])
				err = exec.Command("nft", "delete", "rule", "inet", "kodeblue", "input", "handle", h).Run()
			}
		}
		return err
	}
	bin := fwBin(u["cmd"])
	if bin == "" {
		return fmt.Errorf("undo block_ip: unknown firewall tool %q in record", u["cmd"])
	}
	// A rule already gone (flushed, fresh namespace) is undone.
	chains := []string{"INPUT"}
	if u["docker_user"] == "true" {
		chains = append(chains, "DOCKER-USER")
	}
	var err error
	for _, c := range chains {
		if !iptRule(bin, c, addr) {
			continue
		}
		if derr := exec.Command(bin, "-D", c, "-s", addr, "-m", "comment", "--comment", "kodeblue", "-j", "DROP").Run(); err == nil {
			err = derr
		}
	}
	return err
}

// fwBin maps a recorded tool name to the allowed binary, or "".
func fwBin(name string) string {
	switch name {
	case "iptables", "ip6tables":
		return name
	}
	return ""
}

// SameTarget reports whether two requests' params name the same target.
func SameTarget(a, b map[string]string) bool { return sameTarget(a, b) }

func sameTarget(a, b map[string]string) bool {
	for _, k := range []string{"pid", "path", "ip", "user", "key_id", "unit"} {
		if a[k] != b[k] {
			return false
		}
	}
	return true
}

// ActionsLastHour counts the containment actions done in the last hour, for
// a rate limit lower than the root helper's own (one the hub set).
func ActionsLastHour(stateDir string) int { return countRecentIn(Load(stateDir), time.Hour) }

func countRecentIn(records []Record, d time.Duration) int {
	n := 0
	for _, r := range records {
		if r.Status == "done" && time.Since(r.DoneAt) < d {
			n++
		}
	}
	return n
}

// NewID makes a short action id.
func NewID() string {
	h := sha256.Sum256([]byte(fmt.Sprint(time.Now().UnixNano(), os.Getpid())))
	return "act_" + hex.EncodeToString(h[:5])
}

// copyFile copies src to a new file dst and returns its sha256, or "".
func copyFile(src, dst string) string {
	in, err := os.Open(src)
	if err != nil {
		return ""
	}
	defer in.Close()
	sum, _ := copyTo(dst, in, 0o600)
	return sum
}

// copyTo writes r to a new file dst (never an existing one or a link) and
// returns its sha256.
func copyTo(dst string, r io.Reader, perm os.FileMode) (string, error) {
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(out, h), r); err != nil {
		out.Close()
		return "", err
	}
	if err := out.Close(); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func writeNew(path string, b []byte) error {
	_, err := copyTo(path, bytes.NewReader(b), 0o600)
	return err
}

func shortHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:4])
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func globMatch(pattern, s string) bool {
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(s, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == s
}

// SocketPath is where the systemd-activated root helper listens.
const SocketPath = "/run/kodeblue/respond.sock"

// Invoke sends an envelope to the root helper and returns its JSON reply. It
// prefers the systemd socket (the daemon stays fully sandboxed), falls back to
// `sudo -n` on hosts without systemd, and runs the helper directly when
// already root (tests, containers).
// invokeSlots bounds concurrent helper calls from one process (the socket
// allows 4 connections).
var invokeSlots = make(chan struct{}, 2)

func invokeSocket(ctx context.Context, payload []byte) ([]byte, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", SocketPath)
	if err != nil {
		return nil, fmt.Errorf("respond socket: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Minute))
	if _, err := conn.Write(append(payload, '\n')); err != nil {
		return nil, err
	}
	if uc, ok := conn.(*net.UnixConn); ok {
		_ = uc.CloseWrite()
	}
	return io.ReadAll(io.LimitReader(conn, 1<<20))
}

func Invoke(ctx context.Context, configPath string, payload []byte) ([]byte, error) {
	if st, err := os.Stat(SocketPath); err == nil && st.Mode()&os.ModeSocket != 0 {
		// The socket takes a few connections at once (MaxConnections in
		// kodeblue-respond.socket); past that systemd resets them before a
		// helper starts. Hold this process to fewer, and retry a reset or
		// empty answer of an execute: the helper answers a request it already
		// carried out from its journal. An undo is not retried, since its
		// helper may have run before the answer was lost.
		var env struct {
			Op string `json:"op"`
		}
		_ = json.Unmarshal(payload, &env)
		tries := 1
		if env.Op == "execute" {
			tries = 6
		}
		select {
		case invokeSlots <- struct{}{}:
			defer func() { <-invokeSlots }()
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		var out []byte
		var err error
		for attempt := 0; attempt < tries; attempt++ {
			if out, err = invokeSocket(ctx, payload); err == nil && len(bytes.TrimSpace(out)) > 0 {
				return out, nil
			}
			if err == nil {
				err = errors.New("respond socket: no answer")
			}
			if attempt == tries-1 {
				break
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt+1) * 300 * time.Millisecond):
			}
		}
		return nil, err
	}
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	var cmd *exec.Cmd
	if os.Geteuid() == 0 {
		cmd = exec.CommandContext(ctx, self, "respond", "exec", "--config", configPath)
	} else {
		cmd = exec.CommandContext(ctx, "sudo", "-n", self, "respond", "exec", "--config", configPath)
	}
	cmd.Stdin = bytes.NewReader(payload)
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return nil, fmt.Errorf("response helper: %s", strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, err
	}
	return out, nil
}
