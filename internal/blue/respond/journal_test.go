package respond

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A journal under a directory a non-root user can replace is refused, so a
// forged actions.jsonl planted by swapping the directory is never read.
func TestJournalRefusesUntrustedStateDir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("run as a normal user: the check keys on who owns the dir")
	}
	root := t.TempDir()
	// A state dir owned by the test user (== stateOwner here) is fine.
	good := filepath.Join(root, "respond")
	if _, err := openJournal(good); err != nil {
		t.Fatalf("own state dir refused: %v", err)
	}
	// Point stateOwner at root to stand in for "only root is trusted"; now the
	// test user's own dir is untrusted and must be refused.
	defer func(o uint32) { stateOwner = o }(stateOwner)
	stateOwner = 0
	if _, err := openJournal(filepath.Join(root, "respond2")); err == nil {
		t.Fatal("a non-root-owned state dir must be refused")
	}
}

// Undo acts only on records the journal holds; a record is found and reversed
// through the locked journal, and the reversal is appended.
func TestUndoByIDThroughJournal(t *testing.T) {
	p := DefaultPolicy()
	p.StateDir = t.TempDir()
	rec := Record{Request: Request{ID: "act_x", Action: "block_ip", Params: map[string]string{"ip": "198.51.100.9"}},
		Status: "done", Undo: map[string]string{"cmd": "iptables", "ip": "198.51.100.9"}}
	if err := Append(p.StateDir, rec); err != nil {
		t.Fatal(err)
	}
	defer func(f func(map[string]string) bool) { blockActive = f }(blockActive)
	blockActive = func(map[string]string) bool { return false } // rule already gone
	out, err := UndoByID(p, "act_x")
	if err != nil {
		t.Fatalf("undo: %v", err)
	}
	if out.Status != "undone" {
		t.Fatalf("status %q", out.Status)
	}
	if got := Find(p.StateDir, "act_x"); got == nil || got.Status != "undone" {
		t.Fatalf("reversal not journaled: %+v", got)
	}
	if _, err := UndoByID(p, "nope"); err == nil {
		t.Fatal("undo of an unknown id must fail")
	}
}

// restore reads only from the helper's own quarantine store: a recipe that
// points the source elsewhere (e.g. to plant /etc/shadow at a target) is
// refused.
func TestRestoreRefusesForeignSource(t *testing.T) {
	stateDir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "evil")
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := restore(stateDir, map[string]string{
		"restore_from": outside,
		"restore_to":   filepath.Join(t.TempDir(), "dest"),
		"uid":          "0", "gid": "0", "mode": "600",
	})
	if err == nil || !strings.Contains(err.Error(), "quarantine store") {
		t.Fatalf("want refusal of a source outside the store, got %v", err)
	}
}

// restore refuses a destination outside the quarantine allow-list, even when
// the source is a genuine store file: a record can only put a file back where
// quarantine would have taken it from.
func TestRestoreRefusesDisallowedDestination(t *testing.T) {
	stateDir := t.TempDir()
	q := filepath.Join(stateDir, "quarantine", "1-abcd")
	if err := os.MkdirAll(q, 0o700); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(q, "file")
	if err := os.WriteFile(src, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := restore(stateDir, map[string]string{
		"restore_from": src, "restore_to": "/etc/ld.so.preload.d/../../usr/bin/evil",
		"uid": "0", "gid": "0", "mode": "600",
	})
	if err == nil {
		t.Fatal("restore to a non-clean / disallowed path must be refused")
	}
	// A system path quarantine never accepts is refused too.
	if err := restore(stateDir, map[string]string{"restore_from": src, "restore_to": "/usr/bin/sudo", "uid": "0", "gid": "0", "mode": "600"}); err == nil {
		t.Fatal("restore to /usr/bin/sudo must be refused")
	}
}

// unblockIP never runs a binary named by the record: a bogus cmd is refused
// rather than executed.
func TestUnblockIPRejectsForeignBinary(t *testing.T) {
	if err := unblockIP(map[string]string{"cmd": "/usr/bin/evil", "ip": "198.51.100.9"}); err == nil {
		t.Fatal("undo must refuse a firewall tool it does not recognise")
	}
	if err := unblockIP(map[string]string{"cmd": "iptables", "ip": "not-an-ip"}); err == nil {
		t.Fatal("undo must refuse an invalid ip in the record")
	}
}

// The rate limit is enforced inside the journal lock, counting the done
// records already there.
func TestRateLimitRefusesWhenFull(t *testing.T) {
	p := DefaultPolicy()
	p.Mode = "contain"
	p.StateDir = t.TempDir()
	p.MaxActionsPerHour = 2
	for i := 0; i < 2; i++ {
		if err := Append(p.StateDir, Record{Request: Request{ID: "seed" + strconv.Itoa(i), Action: "block_ip"}, Status: "done", DoneAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	rec := Execute(p, Request{ID: "over", Action: "block_ip", Params: map[string]string{"ip": "198.51.100.9"},
		Justification: "evidence: scripted exploit chain from this address in the request tap"})
	if rec.Status != "refused" || !strings.Contains(rec.Result, "rate limit") {
		t.Fatalf("want rate-limit refusal, got %s %q", rec.Status, rec.Result)
	}
}

// openJournal holds an exclusive flock: a second open cannot proceed while the
// first is held, so concurrent helper invocations serialize their
// check–act–record instead of racing the rate limit or acting twice.
func TestJournalLockIsExclusive(t *testing.T) {
	dir := t.TempDir()
	j, err := openJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan struct{})
	go func() {
		j2, err := openJournal(dir) // blocks until j is closed
		if err == nil {
			j2.Close()
		}
		close(got)
	}()
	select {
	case <-got:
		t.Fatal("second open acquired the lock while the first was held")
	case <-time.After(150 * time.Millisecond):
	}
	j.Close()
	select {
	case <-got:
	case <-time.After(2 * time.Second):
		t.Fatal("second open never acquired the lock after release")
	}
}
