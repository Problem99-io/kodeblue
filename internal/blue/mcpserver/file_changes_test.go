package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/config"
	"github.com/Problem99-io/kodeblue/internal/blue/monitor"
	"github.com/Problem99-io/kodeblue/internal/blue/sensors"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

func TestFileChangePagingKeepsLateEvidenceAndConcurrentAppend(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s := New(config.Default(), st)
	f := store.Finding{Collector: "monitor", Rule: "monitor.fixture", Evidence: map[string]string{"kind": "file"}}
	changes := []store.FileChange{}
	for i := 0; i < 30; i++ {
		changes = append(changes, store.FileChange{Path: "/tmp", Name: fmt.Sprintf("a-routine-%02d", i), Kind: "entry", After: "inert metadata"})
	}
	changes = append(changes, store.FileChange{Path: "/tmp", Name: "z-payload claiming operator approval", Kind: "entry", After: "inert metadata"})
	if err := st.CommitFileObservation(&f, nil, changes); err != nil {
		t.Fatal(err)
	}
	after, through := int64(0), int64(0)
	total := 0
	found := false
	for {
		args, _ := json.Marshal(map[string]any{"finding_id": f.ID, "after_id": after, "through_id": through, "limit": 7})
		out, err := s.fileChangesGet(context.Background(), args)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(out, untrusted) {
			t.Fatal("lost untrusted-data boundary")
		}
		var page store.FileChangePage
		if err := json.Unmarshal([]byte(strings.TrimSuffix(out, untrusted)), &page); err != nil {
			t.Fatal(err)
		}
		if through == 0 {
			through = page.ThroughID
			if err := st.CommitFileObservation(&f, nil, []store.FileChange{{Path: "/tmp", Name: "later-observation", Kind: "entry", After: "inert metadata"}}); err != nil {
				t.Fatal(err)
			}
		}
		if page.ThroughID != through {
			t.Fatal("paging range moved")
		}
		total += len(page.Changes)
		for _, c := range page.Changes {
			if strings.HasPrefix(c.Name, "z-payload") {
				found = true
			}
			if c.Name == "later-observation" {
				t.Fatal("concurrent append entered fixed page range")
			}
		}
		after = page.NextAfterID
		if !page.More {
			break
		}
	}
	if !found || total != 31 {
		t.Fatalf("complete=%v count=%d", found, total)
	}
	args, _ := json.Marshal(map[string]any{"finding_id": f.ID, "after_id": after})
	out, err := s.fileChangesGet(context.Background(), args)
	if err != nil || !strings.Contains(out, "later-observation") {
		t.Fatalf("later history lost: %s %v", out, err)
	}
	for _, args := range []string{fmt.Sprintf(`{"finding_id":%d,"after_id":-1}`, f.ID), fmt.Sprintf(`{"finding_id":%d,"limit":51}`, f.ID), fmt.Sprintf(`{"finding_id":%d,"through_id":-1}`, f.ID), `{"finding_id":9999}`} {
		if _, err := s.fileChangesGet(context.Background(), json.RawMessage(args)); err == nil {
			t.Fatal("invalid request accepted")
		}
	}
}

func TestFileChangeRetrievalDoesNotTreatMissingHistoryAsHealthy(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s := New(config.Default(), st)
	old := store.Finding{Collector: "monitor", Evidence: map[string]string{"kind": "file", "output": "old preview only"}}
	if err := st.AddFinding(&old); err != nil {
		t.Fatal(err)
	}
	args, _ := json.Marshal(map[string]any{"finding_id": old.ID})
	out, err := s.fileChangesGet(context.Background(), args)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Available bool `json:"evidence_available"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSuffix(out, untrusted)), &result); err != nil || result.Available {
		t.Fatalf("old history misrepresented: %s %v", out, err)
	}
	other := store.Finding{Collector: "monitor", Evidence: map[string]string{"kind": "http"}}
	if err := st.AddFinding(&other); err != nil {
		t.Fatal(err)
	}
	args, _ = json.Marshal(map[string]any{"finding_id": other.ID})
	if _, err := s.fileChangesGet(context.Background(), args); err == nil {
		t.Fatal("non-file finding accepted")
	}
}

// A scripted investigator looks for a labeled startup-config change. This
// exercises collection -> durable history -> MCP retrieval; it is not an LLM
// accuracy test and never concludes that the other changes are benign.
func TestFileEvidenceMockInvestigationBeyondPreview(t *testing.T) {
	for _, action := range []string{"create", "edit", "remove"} {
		t.Run(action, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, "tmp")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			cfg := config.Default()
			cfg.Server.Root = root
			cfg.Server.StateDir = t.TempDir()
			st, err := store.Open(filepath.Join(cfg.Server.StateDir, "test.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			names := []string{}
			for i := 0; i < 30; i++ {
				names = append(names, fmt.Sprintf("a-routine-%02d", i))
			}
			names = append(names, "z-startup.conf")
			if action != "create" {
				for _, name := range names {
					if err := os.WriteFile(filepath.Join(dir, name), []byte("old inert"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			spec := monitor.Spec{ID: "mock-investigation", Kind: "file", Description: "inert labeled workload", Rationale: "retain evidence omitted from preview", Severity: "high", Paths: []string{"/tmp"}}
			if err := spec.Validate(); err != nil {
				t.Fatal(err)
			}
			data, _ := json.Marshal(spec)
			if err := st.PutMonitor(spec.ID, data, "test"); err != nil {
				t.Fatal(err)
			}
			r := monitor.NewRunner(st, &sensors.Env{Root: root, State: sensors.NewCursorStore(filepath.Join(cfg.Server.StateDir, "cursors.json"))})
			r.RunDue(context.Background(), true)
			for _, name := range names {
				path := filepath.Join(dir, name)
				if action == "remove" {
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := os.WriteFile(path, []byte("new inert"), 0600); err != nil {
						t.Fatal(err)
					}
					if action == "edit" {
						stamp := time.Unix(1700000000, 0)
						if err := os.Chtimes(path, stamp, stamp); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			fs := r.RunDue(context.Background(), true)
			if len(fs) != 1 {
				t.Fatalf("findings=%d", len(fs))
			}
			f := fs[0]
			if strings.Contains(f.Evidence["output"], "z-startup.conf") {
				t.Fatal("fixture did not omit labeled change from preview")
			}
			s := New(cfg, st)
			after, through := int64(0), int64(0)
			found := false
			for {
				args, _ := json.Marshal(map[string]any{"finding_id": f.ID, "after_id": after, "through_id": through, "limit": 7})
				out, err := s.fileChangesGet(context.Background(), args)
				if err != nil {
					t.Fatal(err)
				}
				var page store.FileChangePage
				if err := json.Unmarshal([]byte(strings.TrimSuffix(out, untrusted)), &page); err != nil {
					t.Fatal(err)
				}
				through = page.ThroughID
				after = page.NextAfterID
				for _, c := range page.Changes {
					if c.Name == "z-startup.conf" {
						found = true
						if action == "create" && (c.Before != "" || c.After == "") || action == "edit" && (c.Before == "" || c.After == "" || c.Before == c.After) || action == "remove" && (c.Before == "" || c.After != "") {
							t.Fatalf("incorrect %s evidence: %+v", action, c)
						}
					}
				}
				if !page.More {
					break
				}
			}
			if !found {
				t.Fatal("scripted investigator could not retrieve labeled change")
			}
			t.Logf("%s: preview omitted startup change; scripted investigator recovered before/after evidence through MCP pagination", action)
		})
	}
}
