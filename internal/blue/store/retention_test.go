package store

import (
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "k.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func addFinding(t *testing.T, st *Store, itemID, status, verdict string, incident int64) *Finding {
	t.Helper()
	f := &Finding{Fingerprint: "fp:" + itemID, Collector: "c", Rule: "r", Severity: "high", Title: itemID, ItemID: itemID}
	if err := st.AddFinding(f); err != nil {
		t.Fatal(err)
	}
	if status != "new" || verdict != "" || incident != 0 {
		if err := st.SetFindingStatus(f.ID, status, verdict, "", incident); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func TestItemUnsettledUsesItemColumns(t *testing.T) {
	st := openTest(t)
	addFinding(t, st, "persistence|cron/root/abc", "new", "", 0)
	addFinding(t, st, "process|/var/tmp/.x/kworker@root", "closed", "true_positive", 0)
	addFinding(t, st, "persistence|cron/root/old", "closed", "false_positive", 0)
	// A LIKE wildcard in an item id must not match other items.
	addFinding(t, st, "accounts|user/a_b", "new", "", 0)

	for id, want := range map[string]bool{
		"persistence|cron/root/abc":     true,  // open
		"persistence|cron/root/old":     false, // settled as harmless
		"persistence|cron/root/ab":      false, // exact match only for non-paths
		"tmp_exec|/var/tmp/.x/kworker":  true,  // same path, another sensor, judged an attack
		"tmp_exec|/var/tmp/.x/kworker2": false,
		"tmp_exec|/var/tmp/other":       false,
		"accounts|user/axb":             false,
		"accounts|user/a_b":             true,
	} {
		if got := st.ItemUnsettled(id); got != want {
			t.Errorf("ItemUnsettled(%q) = %v, want %v", id, got, want)
		}
	}
	// Both lookups are index searches, not a scan of every finding.
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`SELECT COUNT(*) FROM findings WHERE item_id=? AND (` + unsettled + `)`, []any{"x|y"}},
		{`SELECT COUNT(*) FROM findings WHERE item_key>=? AND item_key<? AND (` + unsettled + `)`, []any{"/var/tmp", "/var/tmp\U0010FFFF"}},
	} {
		plan := queryPlan(t, st.db, q.sql, q.args...)
		if !strings.Contains(plan, "USING INDEX findings_item") {
			t.Errorf("query does not use the item index: %s", plan)
		}
	}
}

func queryPlan(t *testing.T, db *sql.DB, q string, args ...any) string {
	t.Helper()
	rows, err := db.Query(`EXPLAIN QUERY PLAN `+q, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var b strings.Builder
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		b.WriteString(detail + "; ")
	}
	return b.String()
}

// A database written before the item columns existed is filled in from the
// evidence JSON on open, so maintenance windows still respect old findings.
func TestMigrationBackfillsItemColumns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT, fingerprint TEXT NOT NULL, collector TEXT NOT NULL, rule TEXT NOT NULL,
  severity TEXT NOT NULL, title TEXT NOT NULL, detail TEXT NOT NULL, evidence TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'new', verdict TEXT NOT NULL DEFAULT '', verdict_reason TEXT NOT NULL DEFAULT '',
  incident_id INTEGER, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, occurrences INTEGER NOT NULL DEFAULT 1);
INSERT INTO findings(fingerprint,collector,rule,severity,title,detail,evidence,status,created_at,updated_at)
  VALUES('a','files','r','high','t','d','{"_item_id":"tmp_exec|/var/tmp/.x/kworker","_value":"h"}','incident',1,1),
        ('b','files','r','high','t','d','{"x":"y"}','new',1,1),
        ('c','files','r','high','t','d','not json','new',1,1);`)
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	// A crash between adding the columns and filling them in must not leave
	// them in place but empty: the next open has to fill them in.
	migrateHook = func(*sql.Tx) error { return errors.New("killed mid-migration") }
	if st, err := Open(path); err == nil {
		st.Close()
		t.Fatal("open should fail when the migration does")
	}
	migrateHook = nil
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if !st.ItemUnsettled("tmp_exec|/var/tmp/.x/kworker") || st.ItemUnsettled("tmp_exec|/var/tmp/other") {
		t.Fatal("old finding not found by its item after migration")
	}
	if f := st.GetFinding(1); f == nil || f.ItemID != "tmp_exec|/var/tmp/.x/kworker" {
		t.Fatalf("finding read back wrong: %+v", f)
	}
	// Opening again does not fail on the existing columns.
	st.Close()
	again, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if !again.ItemUnsettled("tmp_exec|/var/tmp/.x/kworker") {
		t.Fatal("reopened store lost the item columns")
	}
	again.Close()
}

func TestPruneKeepsWhatStillMatters(t *testing.T) {
	st := openTest(t)
	open := &Incident{Title: "open", Severity: "high"}
	done := &Incident{Title: "done", Severity: "high"}
	_ = st.CreateIncident(open)
	_ = st.CreateIncident(done)
	done.Status = "resolved"
	_ = st.UpdateIncident(done)

	oldClosed := addFinding(t, st, "a|x", "closed", "false_positive", 0)
	oldDigest := addFinding(t, st, "a|y", "digest", "", 0)
	oldOfDone := addFinding(t, st, "a|z", "closed", "benign_change", done.ID)
	oldOfOpen := addFinding(t, st, "a|w", "closed", "benign_change", open.ID)
	oldAttack := addFinding(t, st, "a|v", "closed", "true_positive", 0)
	oldNew := addFinding(t, st, "a|u", "new", "", 0)
	oldAck := addFinding(t, st, "a|t", "needs_ack", "benign", 0)
	recent := addFinding(t, st, "a|s", "closed", "false_positive", 0)

	old := time.Now().Add(-100 * 24 * time.Hour).Unix()
	for _, f := range []*Finding{oldClosed, oldDigest, oldOfDone, oldOfOpen, oldAttack, oldNew, oldAck} {
		_, _ = st.db.Exec(`UPDATE findings SET updated_at=?, created_at=? WHERE id=?`, old, old, f.ID)
	}
	st.Journal("x", "old", "")
	st.Journal("x", "recent", "")
	_, _ = st.db.Exec(`UPDATE journal SET at=? WHERE action='old'`, old)
	st.Spend("triage", "m", 1, 1, 0, 0.1)
	st.Spend("triage", "m", 1, 1, 0, 0.2)
	_, _ = st.db.Exec(`UPDATE ledger SET at=? WHERE cost_usd<0.15`, old)

	p, err := st.Prune(time.Now().Add(-90 * 24 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if p.Findings != 3 || p.Journal != 1 || p.Ledger != 1 {
		t.Fatalf("pruned %+v, want 3 findings, 1 journal, 1 ledger", p)
	}
	for _, f := range []*Finding{oldClosed, oldDigest, oldOfDone} {
		if st.GetFinding(f.ID) != nil {
			t.Errorf("finding %s should be pruned", f.ItemID)
		}
	}
	for _, f := range []*Finding{oldOfOpen, oldAttack, oldNew, oldAck, recent} {
		if st.GetFinding(f.ID) == nil {
			t.Errorf("finding %s must be kept", f.ItemID)
		}
	}
	if j := st.JournalSince(time.Time{}, 10); len(j) != 1 || j[0].Action != "recent" {
		t.Fatalf("journal after prune: %+v", j)
	}
	if usd, _, _ := st.SpentSince(time.Time{}); usd < 0.19 || usd > 0.21 {
		t.Fatalf("ledger after prune: $%v", usd)
	}
	// Nothing left to prune: a second run is a no-op.
	if p, _ := st.Prune(time.Now().Add(-90 * 24 * time.Hour)); p != (Pruned{}) {
		t.Fatalf("second prune deleted %+v", p)
	}
}

func TestPruneLargeTableInBatches(t *testing.T) {
	st := openTest(t)
	old := time.Now().Add(-100 * 24 * time.Hour).Unix()
	tx, _ := st.db.Begin()
	for i := 0; i < 2500; i++ {
		_, _ = tx.Exec(`INSERT INTO journal(at,actor,action,detail) VALUES(?,?,?,?)`, old, "x", "y", "z")
	}
	_ = tx.Commit()
	p, err := st.Prune(time.Now().Add(-24 * time.Hour))
	if err != nil || p.Journal != 2500 {
		t.Fatalf("pruned %+v err %v, want 2500 journal rows", p, err)
	}
}

func TestRequeueTriaging(t *testing.T) {
	st := openTest(t)
	f := addFinding(t, st, "a|b", "triaging", "", 0)
	g := addFinding(t, st, "a|c", "benign", "benign", 0)
	if n := st.RequeueTriaging(); n != 1 {
		t.Fatalf("requeued %d, want 1", n)
	}
	if st.GetFinding(f.ID).Status != "new" || st.GetFinding(g.ID).Status != "benign" {
		t.Fatal("requeue touched the wrong findings")
	}
}

// Criticals in "new" must not crowd the triage queue out (the limit applied
// before filtering them used to stop triage entirely).
func TestQueuedFindingsSplitsCriticals(t *testing.T) {
	st := openTest(t)
	for i := 0; i < 50; i++ {
		_ = st.AddFinding(&Finding{Fingerprint: fmt.Sprint("c", i), Collector: "c", Rule: "r", Severity: "critical", Title: "c"})
	}
	_ = st.AddFinding(&Finding{Fingerprint: "h", Collector: "c", Rule: "r", Severity: "high", Title: "h"})
	if q := st.QueuedFindings(false, 40); len(q) != 1 || q[0].Severity != "high" {
		t.Fatalf("triage queue: %d findings", len(q))
	}
	if q := st.QueuedFindings(true, 40); len(q) != 40 || q[0].Severity != "critical" {
		t.Fatalf("critical queue: %d findings", len(q))
	}
}
