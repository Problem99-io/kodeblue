package monitor

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

func TestFileEvidencePreservesLateAndSubsequentChangesWithoutExtraAlerts(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "tmp")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	r, st := newRunner(t, root)
	s := Spec{ID: "evidence", Kind: "file", Description: "fixture changes", Rationale: "retain compared evidence", Severity: "low", Paths: []string{"/tmp"}}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(s)
	if err := st.PutMonitor(s.ID, data, "test"); err != nil {
		t.Fatal(err)
	}
	if fs := r.RunDue(context.Background(), true); len(fs) != 0 {
		t.Fatal("initial sample alerted")
	}
	for i := 0; i < 30; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("a-routine-%02d", i)), []byte("inert"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "z-inert-payload"), []byte("inert"), 0600); err != nil {
		t.Fatal(err)
	}
	fs := r.RunDue(context.Background(), true)
	if len(fs) != 1 {
		t.Fatalf("findings=%d", len(fs))
	}
	f := fs[0]
	if f.Severity != "low" || f.Evidence["protected"] != "" || f.Fingerprint != "monitor:evidence" {
		t.Fatalf("policy changed: %+v", f)
	}
	if strings.Contains(f.Evidence["output"], "z-inert-payload") {
		t.Fatal("fixture did not exercise omitted preview")
	}
	first, err := st.FileChanges(f.ID, 0, 0, 50)
	if err != nil || len(first.Changes) != 31 {
		t.Fatalf("history=%+v err=%v", first, err)
	}
	found := false
	for _, c := range first.Changes {
		if c.Name == "z-inert-payload" {
			found = true
		}
	}
	if !found {
		t.Fatal("late payload omitted from evidence")
	}
	original := first.Changes[0]
	if err := st.SetFindingStatus(f.ID, "incident", "", "investigating", 0); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "z-later-payload"), []byte("inert later"), 0600); err != nil {
		t.Fatal(err)
	}
	if fs := r.RunDue(context.Background(), true); len(fs) != 0 {
		t.Fatal("later observation created an extra alert")
	}
	same := st.GetFinding(f.ID)
	if same.Status != "incident" || same.Occurrences != 2 || same.Evidence["output"] != f.Evidence["output"] {
		t.Fatalf("finding lifecycle changed: %+v", same)
	}
	stable, err := st.FileChanges(f.ID, 0, first.ThroughID, 50)
	if err != nil || len(stable.Changes) != 31 || stable.Changes[0] != original {
		t.Fatal("previous evidence or paging range changed")
	}
	later, err := st.FileChanges(f.ID, first.NextAfterID, 0, 50)
	if err != nil || len(later.Changes) != 1 || later.Changes[0].Name != "z-later-payload" {
		t.Fatalf("later evidence lost: %+v %v", later, err)
	}
	if fs := r.RunDue(context.Background(), true); len(fs) != 0 {
		t.Fatal("unchanged sample alerted")
	}
	unchanged, _ := st.FileChanges(f.ID, later.NextAfterID, 0, 50)
	if len(unchanged.Changes) != 0 {
		t.Fatal("unchanged sample added evidence")
	}
}

func TestComparedFileEvidenceRedactsButDistinguishesObjects(t *testing.T) {
	secret := "sk-" + strings.Repeat("a", 48)
	changes := comparedChanges("/tmp", "dir:old", "dir:new", "", "a-api_key="+secret+"\t1\t600\t1\nb-api_key="+secret+"\t1\t600\t1")
	data, _ := json.Marshal(changes)
	if len(changes) != 2 || strings.Contains(string(data), secret) || changes[0].ObjectID == changes[1].ObjectID {
		t.Fatalf("unsafe evidence: %s", data)
	}
}

func TestFileEvidenceMigratesExistingReferencesWithoutNewBaseline(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "tmp")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	r, st := newRunner(t, root)
	if err := st.Set("monitor_file:old:/tmp", "dir:"+hashStr("")); err != nil {
		t.Fatal(err)
	}
	if err := st.Set("monitor_file:old:/tmp:ls", ""); err != nil {
		t.Fatal(err)
	}
	s := Spec{ID: "old", Kind: "file", Description: "existing monitor", Rationale: "existing reference", Severity: "critical", Paths: []string{"/tmp"}}
	if err := os.WriteFile(filepath.Join(dir, "new-file"), []byte("inert"), 0600); err != nil {
		t.Fatal(err)
	}
	if ok, out := run(t, r, st, s); ok {
		t.Fatalf("existing change silently baselined: %s", out)
	}
	f := st.LastFinding("monitor:old")
	if f == nil || f.Severity != "critical" {
		t.Fatal("existing severity changed")
	}
	page, err := st.FileChanges(f.ID, 0, 0, 20)
	if err != nil || len(page.Changes) != 1 {
		t.Fatalf("evidence=%+v %v", page, err)
	}
}

func TestFileEvidenceDoesNotChangeContainmentTargets(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "tmp")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	r, st := newRunner(t, root)
	s := Spec{ID: "contain-evidence", Kind: "file", Description: "inert", Rationale: "same containment policy", Severity: "high", Paths: []string{"/tmp"}, Fast: true, Contain: true, ConsecutiveFailures: 1}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(s)
	if err := st.PutMonitor(s.ID, data, "test"); err != nil {
		t.Fatal(err)
	}
	var targets []Reflex
	r.OnReflex(func(_ Spec, _ *store.Finding, rx []Reflex) string {
		targets = append(targets, rx...)
		return "mock policy hook"
	})
	r.RunDue(context.Background(), true)
	if err := os.WriteFile(filepath.Join(dir, "new-file"), []byte("inert"), 0600); err != nil {
		t.Fatal(err)
	}
	fs := r.RunDue(context.Background(), true)
	if len(fs) != 1 || len(targets) != 1 || targets[0].Action != "quarantine_file" || targets[0].Params["path"] != "/tmp/new-file" {
		t.Fatalf("targets=%+v findings=%+v", targets, fs)
	}
}

func TestFileEvidenceRetainsComparedFileSignaturesWithoutContents(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "config")
	if err := os.WriteFile(path, []byte("original-content"), 0600); err != nil {
		t.Fatal(err)
	}
	r, st := newRunner(t, root)
	s := Spec{ID: "config", Kind: "file", Description: "configuration", Rationale: "preserve observed signatures", Severity: "medium", Paths: []string{"/config"}}
	if ok, out := run(t, r, st, s); !ok {
		t.Fatal(out)
	}
	if err := os.WriteFile(path, []byte("replacement-data"), 0600); err != nil {
		t.Fatal(err)
	}
	if ok, out := run(t, r, st, s); ok {
		t.Fatalf("edit missed: %s", out)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if ok, out := run(t, r, st, s); ok {
		t.Fatalf("removal missed: %s", out)
	}
	f := st.LastFinding("monitor:config")
	if f == nil {
		t.Fatal("no finding")
	}
	page, err := st.FileChanges(f.ID, 0, 0, 20)
	if err != nil || len(page.Changes) != 2 {
		t.Fatalf("history=%+v err=%v", page, err)
	}
	first, last := page.Changes[0], page.Changes[1]
	if first.Kind != "signature" || first.Before == "" || first.Before == first.After || last.Before != first.After || last.After != "missing" {
		t.Fatalf("signature history lost: %+v", page)
	}
	data, _ := json.Marshal(page)
	if strings.Contains(string(data), "original-content") || strings.Contains(string(data), "replacement-data") {
		t.Fatal("history retained file contents")
	}
}

func TestFileEvidenceKeepsAmbiguousAndNonUTF8ListingDifferences(t *testing.T) {
	changes := comparedChanges("/tmp", "dir:before", "dir:after", "a\t1\t600\t1\na\textra\t2\t600\t2", "a\t3\t600\t3\na\textra\t2\t600\t2")
	if len(changes) != 2 || changes[0].Kind != "listing_line" || changes[1].Kind != "listing_line" {
		t.Fatalf("colliding names swallowed a change: %+v", changes)
	}
	before := "x-\xff\t1\t600\t1"
	after := "x-\xff\t2\t600\t2"
	changes = comparedChanges("/tmp", "dir:before", "dir:after", before, after)
	foundBefore, foundAfter := false, false
	for _, c := range changes {
		if c.Encoding != "base64" {
			t.Fatal("non-UTF-8 bytes were not preserved")
		}
		b, err := base64.StdEncoding.DecodeString(c.Before)
		if err != nil {
			t.Fatal(err)
		}
		a, err := base64.StdEncoding.DecodeString(c.After)
		if err != nil {
			t.Fatal(err)
		}
		foundBefore = foundBefore || string(b) == before
		foundAfter = foundAfter || string(a) == after
	}
	if !foundBefore || !foundAfter {
		t.Fatal("raw compared bytes were lost")
	}
}
