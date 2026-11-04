package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestFileEvidenceTransactionRollbackAndRetry(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Set("reference", "before"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec("CREATE TRIGGER fail_evidence BEFORE INSERT ON file_changes BEGIN SELECT RAISE(ABORT,'fixture failure'); END"); err != nil {
		t.Fatal(err)
	}
	f := Finding{Fingerprint: "monitor:fixture", Collector: "monitor", Rule: "monitor.fixture", Severity: "medium", Evidence: map[string]string{"kind": "file"}}
	changes := []FileChange{{Path: "/tmp", Name: "inert", Kind: "entry", After: "inert\t1\t600\t1"}}
	if err := st.CommitFileObservation(&f, map[string]string{"reference": "after"}, changes); err == nil {
		t.Fatal("transaction did not fail")
	}
	if f.ID != 0 || st.Get("reference") != "before" || len(st.FindingsSince(time.Now().Add(-time.Hour), 10)) != 0 {
		t.Fatal("partial evidence/reference/finding accepted")
	}
	if _, err := st.db.Exec("DROP TRIGGER fail_evidence"); err != nil {
		t.Fatal(err)
	}
	if err := st.CommitFileObservation(&f, map[string]string{"reference": "after"}, changes); err != nil {
		t.Fatal(err)
	}
	if st.Get("reference") != "after" || f.ID == 0 {
		t.Fatal("retry failed")
	}
	if _, err := st.db.Exec("CREATE TRIGGER fail_state BEFORE UPDATE ON kv BEGIN SELECT RAISE(ABORT,'fixture failure'); END"); err != nil {
		t.Fatal(err)
	}
	if err := st.CommitFileObservation(&f, map[string]string{"reference": "later"}, changes); err == nil {
		t.Fatal("existing-finding transaction did not fail")
	}
	page, err := st.FileChanges(f.ID, 0, 0, 20)
	if err != nil || len(page.Changes) != 1 || st.GetFinding(f.ID).Occurrences != 1 || st.Get("reference") != "after" {
		t.Fatal("failed append partially committed")
	}
}

func TestFileEvidenceSurvivesRestartAndFollowsFindingRetention(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	f := Finding{Fingerprint: "monitor:retention", Collector: "monitor", Rule: "monitor.retention", Evidence: map[string]string{"kind": "file"}}
	if err := st.CommitFileObservation(&f, nil, []FileChange{{Path: "/tmp", Name: "inert", Kind: "entry", After: "metadata"}}); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	page, err := st.FileChanges(f.ID, 0, 0, 20)
	if err != nil || len(page.Changes) != 1 {
		t.Fatal("restart lost history")
	}
	in := Incident{Title: "ongoing investigation", Severity: "high", Status: "open"}
	if err := st.CreateIncident(&in); err != nil {
		t.Fatal(err)
	}
	if err := st.SetFindingStatus(f.ID, "closed", "benign", "fixture", in.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec("UPDATE findings SET updated_at=? WHERE id=?", time.Now().Add(-100*24*time.Hour).Unix(), f.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Prune(time.Now().Add(-90 * 24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	page, err = st.FileChanges(f.ID, 0, 0, 20)
	if err != nil || len(page.Changes) != 1 {
		t.Fatal("open incident lost history")
	}
	in.Status = "resolved"
	if err := st.UpdateIncident(&in); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Prune(time.Now().Add(-90 * 24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	page, err = st.FileChanges(f.ID, 0, 0, 20)
	if err != nil || len(page.Changes) != 0 || st.GetFinding(f.ID) != nil {
		t.Fatal("pruning left orphan evidence")
	}
}
