package triage

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/sensors"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

// Every automatic decision is journaled: an absorbed finding and the allow
// rule triage accepted with it both show up for the reviewer.
func TestAbsorbIsJournaled(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "kb.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	tr := &Triager{Store: st, Env: &sensors.Env{Root: t.TempDir()}}
	f := store.Finding{ID: 7, Rule: "persistence.added", Title: "new cron job /etc/cron.d/backup-job", ItemID: "persistence|/etc/cron.d/backup-job", Value: "abc"}
	r := result{ID: 7, Verdict: "benign", Confidence: 0.95, Reason: "nightly backup installed by the backup package"}
	r.Allow = &struct {
		KeyPattern string `json:"key_pattern"`
		Reason     string `json:"reason"`
	}{KeyPattern: "/etc/cron.d/backup-job", Reason: "backup cron job"}
	tr.absorb(f, r)

	var absorbed, rule bool
	for _, j := range st.JournalSince(time.Now().Add(-time.Minute), 50) {
		switch {
		case j.Actor == "triage" && j.Action == "absorb" && strings.Contains(j.Detail, "#7") && strings.Contains(j.Detail, "nightly backup"):
			absorbed = true
		case j.Actor == "triage" && j.Action == "allow_rule.add" && strings.Contains(j.Detail, "/etc/cron.d/backup-job"):
			rule = true
		}
	}
	if !absorbed || !rule {
		t.Fatalf("journal: absorb %v, allow rule %v; want both", absorbed, rule)
	}
}
