package containment

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/config"
	"github.com/Problem99-io/kodeblue/internal/blue/respond"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

// A changed proposal beside an active rule is shown as what an approval
// would activate, with the active copy it replaces beside it, so a person
// never approves content they were not shown.
func TestPendingChangeShowsWhatApprovalActivates(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Response.StateDir = filepath.Join(dir, "respond")
	st, err := store.Open(filepath.Join(dir, "kb.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	r := respond.Rule{ID: "cr-ssh", Title: "Block SSH brute force", Why: "The same password spraying from new addresses every day.",
		When: respond.Trigger{Rule: "auth.bruteforce", Field: "ip"}, Action: "block_ip", Scope: map[string]string{"cidr": "203.0.113.0/24"}, MaxPerHour: 5, Days: 7}
	v, err := Propose(st, r, "agent")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := respond.ApproveRule(cfg.Response, v.Rule, v.Hash, "root", time.Now()); err != nil {
		t.Fatal(err)
	}
	wide := r
	wide.Scope, wide.MaxPerHour = nil, 60
	if _, err := Propose(st, wide, "agent"); err != nil {
		t.Fatal(err)
	}
	got := Get(cfg, st, "cr-ssh")
	if got == nil || !got.Pending || got.Current == nil {
		t.Fatalf("view %+v", got)
	}
	if got.MaxPerHour != 60 || got.Scope["cidr"] != "" || got.Hash != wide.Hash() {
		t.Fatalf("the view must show the change it would approve: %+v", got.Rule)
	}
	if got.Current.MaxPerHour != 5 || got.Current.Scope["cidr"] != "203.0.113.0/24" || got.Status != respond.RuleActive {
		t.Fatalf("current: %+v status %s", got.Current, got.Status)
	}
	if act := Active(cfg, time.Now()); len(act) != 1 || act[0].MaxPerHour != 5 {
		t.Fatalf("the approved copy keeps acting until the change is approved: %+v", act)
	}
}
