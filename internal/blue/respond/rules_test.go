package respond

import (
	"strings"
	"testing"
	"time"
)

func sshRule() Rule {
	return Rule{ID: "cr-ssh-bruteforce", Title: "Block SSH brute force",
		Why:  "Incidents #4, #9 and #12: the same SSH password spraying from new addresses every day, blocked by hand each time.",
		When: Trigger{Rule: "auth.bruteforce", Field: "ip"}, Action: "block_ip", MaxPerHour: 5, Days: 30}
}

func TestValidateRule(t *testing.T) {
	if err := ValidateRule(sshRule()); err != nil {
		t.Fatalf("valid rule refused: %v", err)
	}
	for name, change := range map[string]func(*Rule){
		"bad id":           func(r *Rule) { r.ID = "ssh" },
		"short why":        func(r *Rule) { r.Why = "brute force" },
		"kill_process":     func(r *Rule) { r.Action = "kill_process" },
		"no expiry":        func(r *Rule) { r.Days = 0 },
		"too long":         func(r *Rule) { r.Days = 365 },
		"unlimited":        func(r *Rule) { r.MaxPerHour = 0 },
		"extract no group": func(r *Rule) { r.When.Extract = `client=[0-9.]+` },
		"unknown scope":    func(r *Rule) { r.Scope = map[string]string{"user": "root"} },
		"cidr for files": func(r *Rule) {
			r.Action, r.Scope = "quarantine_file", map[string]string{"cidr": "10.0.0.0/8", "path_prefix": "/var/tmp/.x"}
		},
		"quarantine no dir": func(r *Rule) { r.Action, r.When.Field = "quarantine_file", "path" },
		"quarantine root":   func(r *Rule) { r.Action, r.Scope = "quarantine_file", map[string]string{"path_prefix": "/"} },
		"bad cidr":          func(r *Rule) { r.Scope = map[string]string{"cidr": "nope"} },
	} {
		r := sshRule()
		change(&r)
		if ValidateRule(r) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRuleHashCoversWhatIsApproved(t *testing.T) {
	a, b := sshRule(), sshRule()
	b.Status, b.ApprovedBy, b.Note = RuleActive, "root", "x"
	if a.Hash() != b.Hash() {
		t.Fatal("state fields must not change the hash")
	}
	b.MaxPerHour = 60
	if a.Hash() == b.Hash() {
		t.Fatal("a changed limit must change the hash")
	}
}

func TestTriggerTargetsAndScope(t *testing.T) {
	tr := Trigger{Rule: "monitor.web-exploit", Field: "output", Extract: `client=([0-9a-f.:]+)`}
	got := tr.Targets(map[string]string{"output": "GET /x client=203.0.113.7\nGET /y client=203.0.113.7\nPOST client=198.51.100.2"})
	if strings.Join(got, ",") != "203.0.113.7,198.51.100.2" {
		t.Fatalf("targets %v", got)
	}
	r := sshRule()
	r.Scope = map[string]string{"cidr": "203.0.113.0/24"}
	if _, err := r.RuleParams("198.51.100.2"); err == nil {
		t.Fatal("address outside the scope accepted")
	}
	if p, err := r.RuleParams("203.0.113.7"); err != nil || p["ip"] != "203.0.113.7" {
		t.Fatalf("in scope: %v %v", p, err)
	}
	if _, err := r.RuleParams("not an ip"); err == nil {
		t.Fatal("non-address accepted")
	}
	q := Rule{Action: "quarantine_file", Scope: map[string]string{"path_prefix": "/var/tmp/.x"}}
	for _, bad := range []string{"/var/tmp/.xy/a", "/var/tmp/.x/../../etc/passwd", "relative/a"} {
		if _, err := q.RuleParams(bad); err == nil {
			t.Errorf("quarantine %s accepted", bad)
		}
	}
	if _, err := q.RuleParams("/var/tmp/.x/dropper"); err != nil {
		t.Fatalf("in scope: %v", err)
	}
}

func TestApproveRule(t *testing.T) {
	p := DefaultPolicy()
	p.StateDir = t.TempDir()
	now := time.Now()
	r := sshRule()
	if _, err := ApproveRule(p, r, "deadbeef", "root", now); err == nil {
		t.Fatal("approval of content nobody saw accepted")
	}
	if _, err := ApproveRule(p, r, r.Hash(), "agent", now); err == nil {
		t.Fatal("agent accepted as approver")
	}
	a, err := ApproveRule(p, r, r.Hash(), "hub:alice", now)
	if err != nil {
		t.Fatal(err)
	}
	if a.Status != RuleActive || !a.ExpiresAt.Equal(now.UTC().Add(30*24*time.Hour)) {
		t.Fatalf("approved %+v", a)
	}
	if got := LoadRules(p.StateDir); len(got) != 1 || got[0].ApprovedBy != "hub:alice" {
		t.Fatalf("helper copy %+v", got)
	}
	if a.Effective(now.Add(31*24*time.Hour)) != RuleExpired {
		t.Fatal("rule past expiry still active")
	}
	if _, err := SetRuleStatus(p, r.ID, RuleDeleted, "root", "gone", now); err != nil {
		t.Fatal(err)
	}
	if _, err := ApproveRule(p, r, r.Hash(), "root", now); err == nil {
		t.Fatal("a deleted rule approved again")
	}
	if _, err := SetRuleStatus(p, "cr-nope", RulePaused, "agent", "", now); err == nil {
		t.Fatal("paused a rule that was never approved")
	}
}

func ruleReq(id, ip string) Request {
	return Request{ID: NewID(), Action: "block_ip", Params: map[string]string{"ip": ip}, RequestedBy: RuleRequester(id),
		Justification: "containment rule " + id + " answering finding #3: brute force from " + ip}
}

// ExecuteRule refuses whatever the helper's copy of the rule does not cover,
// before anything runs.
func TestExecuteRuleChecksItsRule(t *testing.T) {
	p := DefaultPolicy()
	p.Mode = "recommend"
	p.StateDir = t.TempDir()
	now := time.Now()
	r := sshRule()
	r.MaxPerHour = 2
	r.Scope = map[string]string{"cidr": "203.0.113.0/24"}
	refused := func(name string, req Request, want string) {
		t.Helper()
		rec := ExecuteRule(p, req, now)
		if rec.Status != "refused" || !strings.Contains(rec.Result, want) {
			t.Errorf("%s: %s %q, want refusal with %q", name, rec.Status, rec.Result, want)
		}
	}
	refused("not approved", ruleReq(r.ID, "203.0.113.7"), "no approved containment rule")
	if _, err := ApproveRule(p, r, r.Hash(), "root", now); err != nil {
		t.Fatal(err)
	}
	refused("outside scope", ruleReq(r.ID, "198.51.100.2"), "outside the rule's scope")
	other := ruleReq(r.ID, "203.0.113.7")
	other.Action, other.Params = "quarantine_file", map[string]string{"path": "/var/tmp/x"}
	refused("other action", other, "may only block_ip")
	extra := ruleReq(r.ID, "203.0.113.7")
	extra.Params["cmd"] = "nft"
	refused("extra params", extra, "unexpected parameters")
	for i := 0; i < 2; i++ {
		if err := Append(p.StateDir, Record{Request: ruleReq(r.ID, "203.0.113.1"+string(rune('0'+i))), Status: "done", DoneAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	refused("over its limit", ruleReq(r.ID, "203.0.113.20"), "limit of 2")
	if _, err := SetRuleStatus(p, r.ID, RulePaused, "agent", "misfired", now); err != nil {
		t.Fatal(err)
	}
	refused("paused", ruleReq(r.ID, "203.0.113.21"), "is paused")
	if _, err := ApproveRule(p, r, r.Hash(), "root", now.Add(-31*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	refused("expired", ruleReq(r.ID, "203.0.113.22"), "is expired")
}

func TestAuthorizeRuleRequests(t *testing.T) {
	agent := Caller{UID: 999, Via: "socket", agentUID: 999}
	req := ruleReq("cr-ssh-bruteforce", "203.0.113.7")
	if err := Authorize("recommend", false, agent, req); err != nil {
		t.Fatalf("rule request from the daemon refused before its rule is checked: %v", err)
	}
	if Authorize("off", false, agent, req) == nil {
		t.Fatal("rule acted with response off")
	}
	if _, err := RuleApprover(false, agent, "hub:alice"); err == nil {
		t.Fatal("hub approval accepted without hub.accept_approvals")
	}
	if by, err := RuleApprover(true, agent, "hub:alice"); err != nil || by != "hub:alice" {
		t.Fatalf("hub approval: %q %v", by, err)
	}
	if _, err := RuleApprover(true, agent, "root"); err == nil {
		t.Fatal("the daemon claimed to be root")
	}
	if by, _ := RuleApprover(false, Caller{UID: 0, Via: "socket", agentUID: 999}, ""); by != "root" {
		t.Fatalf("root approver %q", by)
	}
}
