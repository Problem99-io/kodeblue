// Package detect turns sensor snapshots into findings. It is deterministic and
// spends no tokens: diff against the learned baseline, score with fixed rules,
// explain away what the package manager or an allow rule accounts for,
// debounce, and dedupe. Only what survives reaches a model.
package detect

import (
	"fmt"
	"strings"

	"github.com/Problem99-io/kodeblue/internal/blue/sensors"
)

// Severity levels, ordered.
const (
	SevInfo     = "info"
	SevLow      = "low"
	SevMedium   = "medium"
	SevHigh     = "high"
	SevCritical = "critical"
)

var sevRank = map[string]int{SevInfo: 0, SevLow: 1, SevMedium: 2, SevHigh: 3, SevCritical: 4}

// Rank orders severities.
func Rank(s string) int { return sevRank[s] }

// ChangeKind is how an item differs from the baseline.
type ChangeKind string

const (
	ChangeNew     ChangeKind = "new"
	ChangeChanged ChangeKind = "changed"
	ChangeGone    ChangeKind = "gone"
)

// Verdict of a rule on one change.
type Verdict struct {
	Rule     string
	Severity string
	Title    string
	// Instant findings skip debounce (a single observation is enough).
	Instant bool
	// Protected findings can never be auto-allowed by a model's benign
	// verdict; only an operator can allow them.
	Protected bool
}

// scoreChange applies the fixed rules to a state change. A zero Verdict
// (empty Rule) means "not interesting": absorb silently.
func scoreChange(kind ChangeKind, it sensors.Item, prevValue string) Verdict {
	a := it.Attrs
	switch it.Collector {
	case "process":
		if kind != ChangeNew {
			return Verdict{}
		}
		switch {
		case a["deleted"] == "true":
			return Verdict{Rule: "process.deleted_exe", Severity: SevCritical, Title: "Process running from a deleted executable: " + it.Key, Instant: true, Protected: true}
		case a["suspicious_location"] == "memfd":
			return Verdict{Rule: "process.memfd_exe", Severity: SevCritical, Title: "Fileless process (memfd) running: " + it.Key, Instant: true, Protected: true}
		case a["suspicious_location"] != "":
			return Verdict{Rule: "process.suspicious_location", Severity: SevHigh, Title: "Process running from " + a["suspicious_location"] + ": " + it.Key, Instant: true, Protected: true}
		case a["package"] == "":
			return Verdict{Rule: "process.new_unpackaged", Severity: SevMedium, Title: "New executable not owned by any package is running: " + it.Key}
		default:
			// A packaged binary we have not seen run before is normal churn
			// (cron jobs, admin tools). Absorb it; the reviewer sees it.
			return Verdict{Rule: "process.new_packaged", Severity: SevInfo, Title: "New packaged executable ran: " + it.Key}
		}
	case "listener":
		if kind == ChangeGone {
			return Verdict{Rule: "listener.gone", Severity: SevLow, Title: "Service stopped listening: " + it.Key}
		}
		if kind != ChangeNew {
			return Verdict{}
		}
		if strings.Contains(it.Key, "/public/") {
			if strings.HasSuffix(it.Key, "/unknown") {
				return Verdict{Rule: "listener.new_public_unknown", Severity: SevHigh, Title: "New public listener with unknown owner: " + it.Key}
			}
			return Verdict{Rule: "listener.new_public", Severity: SevMedium, Title: "New publicly reachable listener: " + it.Key}
		}
		return Verdict{Rule: "listener.new_loopback", Severity: SevLow, Title: "New loopback listener: " + it.Key}
	case "outbound":
		if kind != ChangeNew {
			return Verdict{}
		}
		port := it.Key[strings.LastIndex(it.Key, ">")+1:]
		switch port {
		case "4444", "1337", "31337", "6667", "6697", "3333", "5555", "14444", "45700", "9001", "9050":
			return Verdict{Rule: "outbound.suspicious_port", Severity: SevHigh, Title: "Outbound connection to a port associated with shells/miners/IRC/Tor: " + it.Key, Instant: true, Protected: true}
		}
		if strings.HasPrefix(it.Key, "/bin/") || strings.HasPrefix(it.Key, "/usr/bin/bash") || strings.HasPrefix(it.Key, "/usr/bin/sh") || strings.HasPrefix(it.Key, "/usr/bin/dash") || strings.Contains(it.Key, "/nc") || strings.Contains(it.Key, "ncat") || strings.Contains(it.Key, "socat") {
			return Verdict{Rule: "outbound.shell", Severity: SevCritical, Title: "Shell or netcat-like binary holds an outbound connection: " + it.Key, Instant: true, Protected: true}
		}
		return Verdict{Rule: "outbound.new", Severity: SevLow, Title: "New program making outbound connections: " + it.Key}
	case "account":
		switch {
		case strings.HasPrefix(it.Key, "user/"):
			if kind == ChangeGone {
				return Verdict{Rule: "account.removed", Severity: SevMedium, Title: "Account removed: " + it.Key}
			}
			uid0 := strings.HasPrefix(it.Value, "uid=0 ") && it.Key != "user/root"
			if uid0 {
				return Verdict{Rule: "account.uid0", Severity: SevCritical, Title: "Non-root account with UID 0: " + it.Key, Instant: true, Protected: true}
			}
			if strings.Contains(it.Value, "password=empty") && strings.Contains(it.Value, " login ") {
				return Verdict{Rule: "account.empty_password", Severity: SevCritical, Title: "Login account with an empty password: " + it.Key, Instant: true, Protected: true}
			}
			if kind == ChangeNew {
				if strings.Contains(it.Value, " login ") {
					return Verdict{Rule: "account.new_login", Severity: SevHigh, Title: "New account with a login shell: " + it.Key, Protected: true}
				}
				return Verdict{Rule: "account.new_system", Severity: SevLow, Title: "New system account: " + it.Key}
			}
			if !strings.Contains(prevValue, " login ") && strings.Contains(it.Value, " login ") {
				return Verdict{Rule: "account.shell_enabled", Severity: SevHigh, Title: "Account gained a login shell: " + it.Key, Protected: true}
			}
			return Verdict{Rule: "account.changed", Severity: SevMedium, Title: "Account attributes changed: " + it.Key}
		case strings.HasPrefix(it.Key, "group/"):
			if kind == ChangeNew {
				return Verdict{Rule: "account.privileged_group", Severity: SevHigh, Title: "Account added to privileged group: " + strings.TrimPrefix(it.Key, "group/"), Protected: true}
			}
			return Verdict{}
		case strings.HasPrefix(it.Key, "sudoers"):
			if kind == ChangeGone {
				return Verdict{Rule: "sudoers.removed", Severity: SevLow, Title: "sudoers file removed: " + strings.TrimPrefix(it.Key, "sudoers")}
			}
			return Verdict{Rule: "sudoers.changed", Severity: SevHigh, Title: "sudoers configuration changed: " + strings.TrimPrefix(it.Key, "sudoers"), Protected: true}
		}
	case "ssh_key":
		if strings.HasPrefix(it.Key, "sshd_config") {
			if kind == ChangeGone {
				return Verdict{}
			}
			return Verdict{Rule: "sshd.config_changed", Severity: SevMedium, Title: "sshd configuration changed: " + strings.TrimPrefix(it.Key, "sshd_config")}
		}
		if kind == ChangeNew {
			sev := SevHigh
			if strings.HasPrefix(it.Key, "root/") {
				sev = SevCritical
			}
			return Verdict{Rule: "ssh_key.added", Severity: sev, Title: "New SSH authorized key for " + strings.SplitN(it.Key, "/", 2)[0] + " (" + it.Attrs["comment"] + ")", Instant: sev == SevCritical, Protected: true}
		}
		return Verdict{}
	case "persistence":
		if kind == ChangeGone {
			return Verdict{Rule: "persistence.removed", Severity: SevInfo, Title: "Persistence file removed: " + it.Key}
		}
		if a["package_verified"] == "true" {
			return Verdict{} // matches what the package shipped
		}
		if it.Key == "/etc/ld.so.preload" {
			return Verdict{Rule: "persistence.ld_preload", Severity: SevCritical, Title: "/etc/ld.so.preload created or modified", Instant: true, Protected: true}
		}
		if strings.HasPrefix(it.Key, "/etc/pam.d/") || strings.Contains(it.Key, "/.ssh/rc") || it.Key == "/etc/ssh/sshrc" {
			return Verdict{Rule: "persistence.auth_hook", Severity: SevHigh, Title: "Authentication hook changed: " + it.Key, Protected: true}
		}
		if strings.Contains(it.Key, "cron") || strings.Contains(it.Key, "systemd") || strings.Contains(it.Key, "init.d") || strings.Contains(it.Key, "rc.local") || strings.Contains(it.Key, "autostart") {
			verb := "added"
			if kind == ChangeChanged {
				verb = "changed"
			}
			return Verdict{Rule: "persistence.autorun", Severity: SevMedium, Title: "Autorun entry " + verb + ": " + it.Key}
		}
		return Verdict{Rule: "persistence.config", Severity: SevLow, Title: "Startup/config file changed: " + it.Key}
	case "integrity":
		if kind == ChangeGone {
			return Verdict{Rule: "integrity.missing", Severity: SevMedium, Title: "Monitored binary disappeared: " + it.Key}
		}
		if kind == ChangeNew && a["package_verified"] != "false" {
			// First hash of a newly watched path (the learner added it, or a
			// file appeared under a watched glob): recorded for the digest,
			// not alerted. Changes after this are.
			return Verdict{Rule: "integrity.new", Severity: SevLow, Title: "Now watching file content: " + it.Key}
		}
		switch a["package_verified"] {
		case "true":
			return Verdict{} // upgrade: the new bytes are the package's bytes
		case "false":
			return Verdict{Rule: "integrity.package_mismatch", Severity: SevCritical, Title: "Binary does not match its package checksum: " + it.Key, Instant: true, Protected: true}
		case "unexplained":
			return Verdict{Rule: "integrity.changed", Severity: SevHigh, Title: "Monitored file changed without a package upgrade (its package checksum list matches, so check that too): " + it.Key, Protected: true}
		}
		return Verdict{Rule: "integrity.changed", Severity: SevHigh, Title: "Monitored file content changed: " + it.Key, Protected: true}
	case "suid":
		if kind == ChangeGone {
			return Verdict{}
		}
		if a["package"] != "" {
			return Verdict{Rule: "suid.packaged", Severity: SevLow, Title: "New " + it.Value + " file from package " + a["package"] + ": " + it.Key}
		}
		sev := SevHigh
		if strings.HasPrefix(it.Key, "/tmp/") || strings.HasPrefix(it.Key, "/var/tmp/") || strings.HasPrefix(it.Key, "/home/") || strings.HasPrefix(it.Key, "/dev/shm/") {
			sev = SevCritical
		}
		return Verdict{Rule: "suid.new", Severity: sev, Title: "New unpackaged " + it.Value + " file: " + it.Key, Instant: sev == SevCritical, Protected: true}
	case "kernel_module":
		if kind != ChangeNew {
			return Verdict{}
		}
		return Verdict{Rule: "kernel_module.new", Severity: SevMedium, Title: "Kernel module loaded: " + it.Key}
	case "package":
		// Mostly an explanation source; the reviewer sees the drift. But a
		// checksum list that changes while the version stays the same is how
		// a trojaned binary is made to "verify".
		if kind == ChangeChanged {
			prevSums, curSums := packageSums(prevValue), packageSums(it.Value)
			if packageVersion(prevValue) == packageVersion(it.Value) && prevSums != "" && curSums != prevSums {
				return Verdict{Rule: "package.checksums_changed", Severity: SevHigh, Title: "Package checksum list changed without a version change: " + it.Key, Instant: true, Protected: true}
			}
		}
		return Verdict{}
	case "tmp_exec":
		if kind != ChangeNew && kind != ChangeChanged {
			return Verdict{}
		}
		if a["magic"] == "elf" {
			return Verdict{Rule: "tmp_exec.elf", Severity: SevHigh, Title: "Executable binary dropped in a world-writable dir: " + it.Key, Protected: true}
		}
		return Verdict{Rule: "tmp_exec.script", Severity: SevLow, Title: "Executable script in a world-writable dir: " + it.Key}
	case "container":
		if kind == ChangeNew {
			return Verdict{Rule: "container.new", Severity: SevLow, Title: "New container running: " + it.Key}
		}
		if kind == ChangeGone {
			return Verdict{Rule: "container.gone", Severity: SevLow, Title: "Container no longer running: " + it.Key}
		}
		return Verdict{}
	case "cpu_hog":
		if kind != ChangeNew {
			return Verdict{}
		}
		return Verdict{Rule: "cpu_hog.new", Severity: SevMedium, Title: fmt.Sprintf("Unfamiliar process using %s%% CPU: %s", a["cpu_percent"], it.Key)}
	}
	return Verdict{}
}

// DisappearanceMatters lists collectors whose items going away is a signal
// (a service stopped, an account vanished). For the rest, gone is silent.
var DisappearanceMatters = map[string]bool{"listener": true, "account": true, "integrity": true, "container": true}

// Package item values are "<version>" or "<version> sums:<digest>", the digest
// covering the package's checksum list (dpkg md5sums, apk Z: lines).
const pkgSumsSep = " sums:"

func packageVersion(value string) string {
	v, _, _ := strings.Cut(value, pkgSumsSep)
	return v
}

func packageSums(value string) string {
	_, s, _ := strings.Cut(value, pkgSumsSep)
	return s
}
