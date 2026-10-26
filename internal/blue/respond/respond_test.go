package respond

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCheck(t *testing.T) {
	p := DefaultPolicy()
	p.ProtectedIPs = []string{"203.0.113.0/24"}
	j := "evidence: reverse shell from this process to 198.51.100.7:4444"
	ok := []Request{
		{Action: "block_ip", Params: map[string]string{"ip": "198.51.100.7"}, Justification: j},
		{Action: "quarantine_file", Params: map[string]string{"path": "/tmp/.x/miner"}, Justification: j},
		{Action: "lock_user", Params: map[string]string{"user": "mallory"}, Justification: j},
		{Action: "stop_unit", Params: map[string]string{"unit": "evil.service"}, Justification: j},
	}
	for _, r := range ok {
		if err := Check(p, r); err != nil {
			t.Errorf("%s %v should pass: %v", r.Action, r.Params, err)
		}
	}
	bad := []Request{
		{Action: "block_ip", Params: map[string]string{"ip": "127.0.0.1"}, Justification: j},
		{Action: "block_ip", Params: map[string]string{"ip": "169.254.169.254"}, Justification: j},
		{Action: "block_ip", Params: map[string]string{"ip": "203.0.113.9"}, Justification: j},
		{Action: "quarantine_file", Params: map[string]string{"path": "/usr/bin/sudo"}, Justification: j},
		{Action: "quarantine_file", Params: map[string]string{"path": "/tmp/../etc/passwd"}, Justification: j},
		{Action: "lock_user", Params: map[string]string{"user": "root"}, Justification: j},
		{Action: "stop_unit", Params: map[string]string{"unit": "sshd.service"}, Justification: j},
		{Action: "stop_unit", Params: map[string]string{"unit": "systemd-journald"}, Justification: j},
		{Action: "kill_process", Params: map[string]string{"pid": "1", "expect_exe": "/sbin/init"}, Justification: j},
		{Action: "block_ip", Params: map[string]string{"ip": "198.51.100.7"}, Justification: "bad"},
		{Action: "format_disk", Params: map[string]string{}, Justification: j},
	}
	for _, r := range bad {
		if err := Check(p, r); err == nil {
			t.Errorf("%s %v must be refused", r.Action, r.Params)
		}
	}
}

// TestBlockReappliedWhenRuleGone: the journal says an address is blocked but
// the rule is gone (flushed, or the app got a fresh network namespace). A new
// block_ip must act again instead of answering "already done".
func TestBlockReappliedWhenRuleGone(t *testing.T) {
	p := DefaultPolicy()
	p.StateDir = t.TempDir()
	if err := Append(p.StateDir, Record{Request: Request{ID: "act_old", IncidentID: 43, Action: "block_ip", Params: map[string]string{"ip": "198.51.100.7"}},
		Status: "done", Result: "dropped inbound traffic from 198.51.100.7 via iptables", Undo: map[string]string{"cmd": "iptables", "ip": "198.51.100.7"}}); err != nil {
		t.Fatal(err)
	}
	r := Request{ID: "act_new", IncidentID: 50, Action: "block_ip", Params: map[string]string{"ip": "198.51.100.7"},
		Justification: "evidence: scripted exploit chain from 198.51.100.7 in the request tap"}
	defer func(f func(map[string]string) bool) { blockActive = f }(blockActive)

	blockActive = func(map[string]string) bool { return true }
	if rec := Execute(p, r); rec.Status != "done" || !strings.HasPrefix(rec.Result, "already done by act_old") {
		t.Fatalf("rule in place: %s %q", rec.Status, rec.Result)
	}
	blockActive = func(map[string]string) bool { return false }
	if rec := Execute(p, r); strings.HasPrefix(rec.Result, "already done") {
		t.Fatalf("rule gone, still deduped: %q", rec.Result)
	}
	if old := Load(p.StateDir)[0]; old.ID != "act_old" || old.Status != "undone" || !strings.Contains(old.Result, "applied again by act_new") {
		t.Fatalf("the lapsed block must be booked as over: %+v", old)
	}
}

func TestNftHasIP(t *testing.T) {
	l := "table inet kodeblue {\n\tchain input {\n\t\tip saddr 198.51.100.7 drop comment \"kodeblue\" # handle 4\n\t}\n}"
	if !nftHasIP(l, "198.51.100.7") || nftHasIP(l, "198.51.100.70") || nftHasIP(l, "98.51.100.7") {
		t.Fatal("nftHasIP must match the whole address")
	}
}

// TestQuarantineAgainWhenFileBack: a payload dropped again at a path kodeblue
// already quarantined is a new file and is quarantined again.
func TestQuarantineAgainWhenFileBack(t *testing.T) {
	p := DefaultPolicy()
	p.StateDir = t.TempDir()
	dir, err := os.MkdirTemp("/tmp", "kbq")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, ".p")
	if err := Append(p.StateDir, Record{Request: Request{ID: "act_q1", Action: "quarantine_file", Params: map[string]string{"path": path}}, Status: "done"}); err != nil {
		t.Fatal(err)
	}
	r := Request{ID: "act_q2", Action: "quarantine_file", Params: map[string]string{"path": path}, Justification: "evidence: ELF payload dropped by the upload exploit"}
	if rec := Execute(p, r); !strings.HasPrefix(rec.Result, "already done by act_q1") {
		t.Fatalf("file still gone: %s %q", rec.Status, rec.Result)
	}
	if err := os.WriteFile(path, []byte("payload"), 0o755); err != nil {
		t.Fatal(err)
	}
	if rec := Execute(p, r); strings.HasPrefix(rec.Result, "already done") {
		t.Fatalf("file back, still deduped: %q", rec.Result)
	}
}

func TestLockUserRestoresExpiry(t *testing.T) {
	shadow := []byte("root:$6$x:19000:0:99999:7:::\n" +
		"alice:$6$y:19000:0:99999:7::20500:\n" +
		"bob:!$6$z:19000:0:99999:7:::\n" +
		"carol:$6$w:19000:0:99999:7::soon:\n" +
		"short:x:1\n")
	cases := []struct {
		user, expire string
		locked, ok   bool
	}{
		{"alice", "20500", false, true},
		{"bob", "", true, true},
		{"root", "", false, true},
		{"carol", "", false, false}, // garbage expiry: not recorded
		{"short", "", false, false},
		{"nobody", "", false, false},
	}
	for _, c := range cases {
		expire, locked, ok := shadowState(shadow, c.user)
		if expire != c.expire || locked != c.locked || ok != c.ok {
			t.Errorf("shadowState(%s) = %q %v %v, want %q %v %v", c.user, expire, locked, ok, c.expire, c.locked, c.ok)
		}
	}
	for _, c := range []struct {
		name string
		undo map[string]string
		want string
	}{
		// A record from before the expiry was recorded clears it, as before.
		{"old record", map[string]string{"user": "alice"}, "-U|-e||alice"},
		{"restored", map[string]string{"user": "alice", "prev_expire": "20500"}, "-U|-e|20500|alice"},
		{"no expiry", map[string]string{"user": "alice", "prev_expire": ""}, "-U|-e||alice"},
		{"already locked", map[string]string{"user": "bob", "prev_expire": "", "was_locked": "true"}, "-e||bob"},
		{"tampered", map[string]string{"user": "alice", "prev_expire": "-1 -G wheel"}, "-U|-e||alice"},
	} {
		if got := strings.Join(unlockArgs(c.undo), "|"); got != c.want {
			t.Errorf("%s: usermod %q, want %q", c.name, got, c.want)
		}
	}
}

// A retried execute of a request the helper already carried out answers with
// that record and appends nothing, so the undo recipe is not overwritten.
func TestExecuteRetryKeepsRecord(t *testing.T) {
	p := DefaultPolicy()
	p.StateDir = t.TempDir()
	done := Record{Request: Request{ID: "act_r1", Action: "block_ip", Params: map[string]string{"ip": "203.0.113.5"}, Justification: "evidence: 400 failed ssh logins from this address"}, Status: "done",
		Result: "blocked", Undo: map[string]string{"rule": "x"}, DoneAt: time.Now()}
	if err := Append(p.StateDir, done); err != nil {
		t.Fatal(err)
	}
	rec := Execute(p, done.Request)
	if rec.Result != "blocked" || rec.Undo["rule"] != "x" {
		t.Fatalf("retry answered %q %v", rec.Result, rec.Undo)
	}
	if all := Load(p.StateDir); len(all) != 1 || all[0].Undo["rule"] != "x" {
		t.Fatalf("journal after retry: %+v", all)
	}
}
