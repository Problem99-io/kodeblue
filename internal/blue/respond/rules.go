package respond

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Containment rules answer a recurring attack the same way every time, without
// asking again: block each address that brute-forces SSH, quarantine each
// file a known dropper writes to /var/tmp/.x. An agent proposes one when it
// sees the same incident come back; it does nothing until a person approves
// it, on the server (sudo kodeblue rules approve) or on the hub where
// hub.accept_approvals allows. Approval is that person's standing approval
// for exactly the rule's action, within its scope, until it expires.
//
// The approved rules are the root helper's: rules.jsonl beside the action
// journal, in the same root-owned directory, written under the journal lock.
// The kodeblue user can read them (to know when to fire) but not change
// them, and the helper checks every rule-driven request against its own copy.
// A paused, expired or deleted rule acts no more; only an approval makes it
// act again.

const rulesName = "rules.jsonl"

// Rule states.
const (
	RuleProposed = "proposed" // waiting for a person (kept on the kodeblue side)
	RuleActive   = "active"
	RulePaused   = "paused"
	RuleExpired  = "expired"
	RuleRejected = "rejected"
	RuleDeleted  = "deleted"
)

// RuleActions are what a rule may do on its own. Only actions whose target
// comes straight from the finding and can be bounded by a scope.
var RuleActions = []string{"block_ip", "quarantine_file"}

// Rule is a containment rule. The fields up to Days are what is proposed and
// approved (and hashed); the rest is the helper's record of its state.
type Rule struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	// Why: the recurring pattern, with the incidents or findings that show it.
	Why  string  `json:"why"`
	When Trigger `json:"when"`
	// Action is one of RuleActions; Scope bounds its targets: "cidr" (block_ip
	// only addresses inside it), "path_prefix" (quarantine_file, required).
	Action     string            `json:"action"`
	Scope      map[string]string `json:"scope,omitempty"`
	MaxPerHour int               `json:"max_per_hour"`
	Days       int               `json:"days"` // active for this long after approval

	Status     string    `json:"status"`
	ProposedBy string    `json:"proposed_by,omitempty"`
	ProposedAt time.Time `json:"proposed_at,omitzero"`
	ApprovedBy string    `json:"approved_by,omitempty"`
	ApprovedAt time.Time `json:"approved_at,omitzero"`
	ExpiresAt  time.Time `json:"expires_at,omitzero"`
	ChangedBy  string    `json:"changed_by,omitempty"`
	ChangedAt  time.Time `json:"changed_at,omitzero"`
	Note       string    `json:"note,omitempty"`
}

// Trigger is the finding a rule answers.
type Trigger struct {
	// Rule is the finding's rule: "auth.bruteforce", "monitor.<monitor id>".
	Rule string `json:"rule"`
	// Field is the evidence field naming the target ("ip", or "output" for a
	// monitor's sample lines); Extract, when set, is a regex whose first group
	// pulls targets out of it (every match counts, up to 10).
	Field   string `json:"field"`
	Extract string `json:"extract,omitempty"`
}

var (
	ruleIDRe   = regexp.MustCompile(`^cr-[a-z0-9][a-z0-9-]{1,60}$`)
	triggerRe  = regexp.MustCompile(`^(auth\.[a-z_]+|monitor\.[a-z0-9][a-z0-9-]{1,62}|[a-z_]+\.[a-z0-9_.-]+)$`)
	fieldRe    = regexp.MustCompile(`^[a-z_]{1,40}$`)
	ruleByRe   = regexp.MustCompile(`^rule:(cr-[a-z0-9][a-z0-9-]{1,60})$`)
	approverRe = regexp.MustCompile(`^(root|uid-\d+|hub:[^\n+]{1,200})$`)
)

// ValidateRule checks what is proposed: a narrow, bounded, expiring answer
// to one kind of finding.
func ValidateRule(r Rule) error {
	switch {
	case !ruleIDRe.MatchString(r.ID):
		return errors.New("id must start with cr- and use lowercase letters, digits and dashes")
	case strings.TrimSpace(r.Title) == "" || len(r.Title) > 200:
		return errors.New("title is required (at most 200 characters)")
	case len(strings.TrimSpace(r.Why)) < 20 || len(r.Why) > 4000:
		return errors.New("why must describe the recurring pattern and the incidents that show it (20-4000 characters)")
	case !triggerRe.MatchString(r.When.Rule):
		return errors.New("when.rule must name a finding rule, e.g. auth.bruteforce or monitor.<id>")
	case !fieldRe.MatchString(r.When.Field):
		return errors.New("when.field must name an evidence field, e.g. ip or output")
	case !slices.Contains(RuleActions, r.Action):
		return fmt.Errorf("action must be one of %s", strings.Join(RuleActions, ", "))
	case r.MaxPerHour < 1 || r.MaxPerHour > 60:
		return errors.New("max_per_hour must be 1-60")
	case r.Days < 1 || r.Days > 90:
		return errors.New("days must be 1-90: a rule expires and needs approval again")
	}
	if r.When.Extract != "" {
		re, err := regexp.Compile(r.When.Extract)
		if err != nil || re.NumSubexp() < 1 || len(r.When.Extract) > 300 {
			return errors.New("when.extract must be a regex (at most 300 characters) with one capture group for the target")
		}
	}
	for k := range r.Scope {
		if k != "cidr" && k != "path_prefix" {
			return fmt.Errorf("scope %q is unknown (cidr, path_prefix)", k)
		}
	}
	if c := r.Scope["cidr"]; c != "" {
		if r.Action != "block_ip" {
			return errors.New("scope cidr is for block_ip")
		}
		if _, err := netip.ParsePrefix(c); err != nil {
			return fmt.Errorf("scope cidr %q: %v", c, err)
		}
	}
	if r.Action == "quarantine_file" {
		p := r.Scope["path_prefix"]
		if !filepath.IsAbs(p) || filepath.Clean(p) != strings.TrimSuffix(p, "/") || p == "/" || len(p) < 5 {
			return errors.New("quarantine_file needs scope path_prefix: an absolute directory such as /var/tmp/.x/")
		}
		if err := checkQuarantinePath(filepath.Join(p, "x")); err != nil {
			return fmt.Errorf("scope path_prefix: %v", err)
		}
	}
	return nil
}

// Hash identifies what was proposed: an approval names the hash of the rule
// the person saw, so a rule changed after it was shown is not approved.
func (r Rule) Hash() string {
	b, _ := json.Marshal(struct {
		ID, Title, Why string
		When           Trigger
		Action         string
		Scope          map[string]string
		MaxPerHour     int
		Days           int
	}{r.ID, r.Title, r.Why, r.When, r.Action, r.Scope, r.MaxPerHour, r.Days})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Effective is the state at now: an active rule past its expiry is expired.
func (r Rule) Effective(now time.Time) string {
	if r.Status == RuleActive && !r.ExpiresAt.IsZero() && !now.Before(r.ExpiresAt) {
		return RuleExpired
	}
	return r.Status
}

// Targets pulls the targets out of a finding's evidence for this rule.
func (t Trigger) Targets(evidence map[string]string) []string {
	v := evidence[t.Field]
	if v == "" {
		return nil
	}
	if t.Extract == "" {
		return []string{strings.TrimSpace(v)}
	}
	re, err := regexp.Compile(t.Extract)
	if err != nil {
		return nil
	}
	var out []string
	for _, m := range re.FindAllStringSubmatch(v, 50) {
		if s := strings.TrimSpace(m[1]); s != "" && !slices.Contains(out, s) {
			out = append(out, s)
		}
		if len(out) == 10 {
			break
		}
	}
	return out
}

// RuleParams is the action's request parameters for one target, or an error
// when the target is not one the rule may act on.
func (r Rule) RuleParams(target string) (map[string]string, error) {
	switch r.Action {
	case "block_ip":
		ip := net.ParseIP(target)
		if ip == nil {
			return nil, fmt.Errorf("%q is not an IP address", target)
		}
		if c := r.Scope["cidr"]; c != "" {
			pfx, _ := netip.ParsePrefix(c)
			a, _ := netip.ParseAddr(ip.String())
			if !pfx.Contains(a.Unmap()) {
				return nil, fmt.Errorf("%s is outside the rule's scope %s", target, c)
			}
		}
		return map[string]string{"ip": ip.String()}, nil
	case "quarantine_file":
		p := filepath.Clean(target)
		prefix := strings.TrimSuffix(r.Scope["path_prefix"], "/") + "/"
		if !filepath.IsAbs(p) || !strings.HasPrefix(p, prefix) {
			return nil, fmt.Errorf("%s is outside the rule's scope %s", target, prefix)
		}
		return map[string]string{"path": p}, nil
	}
	return nil, fmt.Errorf("action %s cannot be taken by a rule", r.Action)
}

// RuleRequester is the requested_by of a rule's action.
func RuleRequester(id string) string { return "rule:" + id }

// RuleOf names the rule a request came from, or "".
func RuleOf(requestedBy string) string {
	if m := ruleByRe.FindStringSubmatch(requestedBy); m != nil {
		return m[1]
	}
	return ""
}

// ---- the helper's copy ----

// rules reads rules.jsonl through the checked directory: the latest line per
// rule id is its state.
func (j *journal) rules() (map[string]Rule, error) {
	f, err := j.openFile(rulesName, unix.O_RDONLY)
	if errors.Is(err, unix.ENOENT) {
		return map[string]Rule{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readRules(f), nil
}

func (j *journal) putRule(r Rule) error {
	f, err := j.openFile(rulesName, unix.O_WRONLY|unix.O_APPEND|unix.O_CREAT)
	if err != nil {
		return err
	}
	defer f.Close()
	var dst unix.Stat_t
	if unix.Fstat(j.dfd, &dst) == nil {
		_ = f.Chown(-1, int(dst.Gid))
	}
	b, _ := json.Marshal(r)
	_, err = f.Write(append(b, '\n'))
	return err
}

func readRules(f *os.File) map[string]Rule {
	out := map[string]Rule{}
	for _, line := range strings.Split(readAll(f), "\n") {
		var r Rule
		if json.Unmarshal([]byte(line), &r) == nil && r.ID != "" {
			out[r.ID] = r
		}
	}
	return out
}

func readAll(f *os.File) string {
	var b strings.Builder
	buf := make([]byte, 32<<10)
	for b.Len() < 8<<20 {
		n, err := f.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return b.String()
}

// LoadRules is the helper's rules for the unprivileged side, which reads
// them to know when to fire (the helper checks again).
func LoadRules(stateDir string) []Rule {
	f, err := os.Open(filepath.Join(stateDir, rulesName))
	if err != nil {
		return nil
	}
	defer f.Close()
	m := readRules(f)
	out := make([]Rule, 0, len(m))
	for _, r := range m {
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b Rule) int { return strings.Compare(a.ID, b.ID) })
	return out
}

// ApproveRule makes r active for r.Days, as approved by by ("root", "uid-N"
// or "hub:<operator>"). hash is what the approver saw; it must match r.
// Approving an active rule renews it; a paused or expired one resumes.
func ApproveRule(p Policy, r Rule, hash, by string, now time.Time) (Rule, error) {
	if err := ValidateRule(r); err != nil {
		return r, err
	}
	if hash != r.Hash() {
		return r, errors.New("the rule changed since it was shown for approval; look at it again")
	}
	if !approverRe.MatchString(by) {
		return r, fmt.Errorf("bad approver %q", by)
	}
	j, err := openJournal(p.StateDir)
	if err != nil {
		return r, err
	}
	defer j.Close()
	if cur, err := j.rules(); err == nil {
		if old, ok := cur[r.ID]; ok && old.Status == RuleDeleted {
			return r, fmt.Errorf("rule %s was deleted; propose it under a new id", r.ID)
		}
	}
	r.Status, r.ApprovedBy, r.ApprovedAt = RuleActive, by, now.UTC()
	r.ExpiresAt = now.UTC().Add(time.Duration(r.Days) * 24 * time.Hour)
	r.ChangedBy, r.ChangedAt, r.Note = by, now.UTC(), ""
	return r, j.putRule(r)
}

// SetRuleStatus pauses, rejects or deletes an approved rule (an approval is
// what makes it act again).
func SetRuleStatus(p Policy, id, status, by, note string, now time.Time) (Rule, error) {
	if status != RulePaused && status != RuleDeleted {
		return Rule{}, fmt.Errorf("a rule can be set to %s or %s here", RulePaused, RuleDeleted)
	}
	j, err := openJournal(p.StateDir)
	if err != nil {
		return Rule{}, err
	}
	defer j.Close()
	cur, err := j.rules()
	if err != nil {
		return Rule{}, err
	}
	r, ok := cur[id]
	if !ok {
		return Rule{}, fmt.Errorf("no approved rule %s", id)
	}
	r.Status, r.ChangedBy, r.ChangedAt, r.Note = status, by, now.UTC(), note
	return r, j.putRule(r)
}

// ExecuteRule runs a request a containment rule made. Under the journal lock
// it checks the helper's own copy of the rule: active and unexpired, the
// same action, a target within its scope, and under its hourly limit; then
// the request goes through every check an agent's does (protected targets,
// infrastructure, the policy's rate limit).
func ExecuteRule(p Policy, r Request, now time.Time) Record {
	return executeWith(p, r, func(j *journal, records []Record) error {
		id := RuleOf(r.RequestedBy)
		if id == "" {
			return errors.New("not a rule request")
		}
		rules, err := j.rules()
		if err != nil {
			return fmt.Errorf("rules unreadable: %v", err)
		}
		rule, ok := rules[id]
		if !ok {
			return fmt.Errorf("no approved containment rule %s", id)
		}
		if st := rule.Effective(now); st != RuleActive {
			return fmt.Errorf("containment rule %s is %s", id, st)
		}
		if r.Action != rule.Action {
			return fmt.Errorf("containment rule %s may only %s", id, rule.Action)
		}
		target := r.Params["ip"]
		if rule.Action == "quarantine_file" {
			target = r.Params["path"]
		}
		want, err := rule.RuleParams(target)
		if err != nil {
			return err
		}
		if !sameTarget(want, r.Params) || len(r.Params) != len(want) {
			return fmt.Errorf("containment rule %s: unexpected parameters", id)
		}
		n := 0
		for _, rec := range records {
			if rec.RequestedBy == r.RequestedBy && rec.Status == "done" && now.Sub(rec.DoneAt) < time.Hour && !strings.HasPrefix(rec.Result, "already done by ") {
				n++
			}
		}
		if n >= rule.MaxPerHour {
			return fmt.Errorf("containment rule %s reached its limit of %d actions an hour", id, rule.MaxPerHour)
		}
		return nil
	})
}
