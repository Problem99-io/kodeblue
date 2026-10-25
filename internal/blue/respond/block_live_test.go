package respond

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestLiveBlockPrivate runs a real block_ip and its undo in this network
// namespace. It changes the firewall, so it only runs as root with
// KODEBLUE_LIVE_BLOCK set to an unused private address (e.g. 10.255.255.250);
// KODEBLUE_LIVE_REFUSE may name an address that must be refused (the gateway).
func TestLiveBlockPrivate(t *testing.T) {
	target := os.Getenv("KODEBLUE_LIVE_BLOCK")
	if target == "" || os.Geteuid() != 0 {
		t.Skip("set KODEBLUE_LIVE_BLOCK and run as root")
	}
	p := DefaultPolicy()
	p.Mode, p.StateDir = "contain", t.TempDir()
	j := "live test of private-address blocking; undone at once"
	if refuse := os.Getenv("KODEBLUE_LIVE_REFUSE"); refuse != "" {
		rec := Execute(p, Request{ID: "live-refuse", Action: "block_ip", Params: map[string]string{"ip": refuse}, Justification: j})
		if rec.Status != "refused" {
			t.Fatalf("%s must be refused: %s %s", refuse, rec.Status, rec.Result)
		}
		t.Logf("refused %s: %s", refuse, rec.Result)
	}
	rec := Execute(p, Request{ID: "live-block", Action: "block_ip", Params: map[string]string{"ip": "::ffff:" + target}, Justification: j})
	if rec.Status != "done" {
		t.Fatalf("block failed: %s %s", rec.Status, rec.Result)
	}
	t.Logf("blocked: %s", rec.Result)
	rules, _ := exec.Command("iptables", "-S", "INPUT").Output()
	if !strings.Contains(string(rules), target) {
		t.Fatalf("no INPUT rule for %s:\n%s", target, rules)
	}
	// The rule vanishes behind kodeblue's back (a flush, a fresh network
	// namespace): asking again must put it back, not answer "already done".
	if out, err := exec.Command("iptables", "-D", "INPUT", "-s", target, "-m", "comment", "--comment", "kodeblue", "-j", "DROP").CombinedOutput(); err != nil {
		t.Fatalf("drop the rule by hand: %v %s", err, out)
	}
	_ = Append(p.StateDir, rec)
	again := Execute(p, Request{ID: "live-block-again", Action: "block_ip", Params: map[string]string{"ip": target}, Justification: j})
	if again.Status != "done" || strings.HasPrefix(again.Result, "already done") {
		t.Fatalf("block after the rule vanished: %s %s", again.Status, again.Result)
	}
	rules, _ = exec.Command("iptables", "-S", "INPUT").Output()
	if !strings.Contains(string(rules), target) {
		t.Fatalf("rule not put back for %s:\n%s", target, rules)
	}
	t.Logf("put back: %s", again.Result)
	rec = again
	if err := Undo(&rec); err != nil {
		t.Fatalf("undo: %v", err)
	}
	rules, _ = exec.Command("iptables", "-S", "INPUT").Output()
	if strings.Contains(string(rules), target) {
		t.Fatalf("rule for %s left after undo:\n%s", target, rules)
	}
}
