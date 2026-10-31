package blue

import "testing"

func TestInvestigatorHasOnlyEvidenceReads(t *testing.T) {
	defs, err := Agents()
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"mcp__kodeblue__research_context": true}
	for _, a := range defs {
		if a.Name != "blue-investigator" {
			continue
		}
		if a.MaxIterations != 24 {
			t.Fatal(a.MaxIterations)
		}
		for _, tool := range a.Tools {
			if !allowed[tool] {
				t.Fatalf("investigator acquired %s", tool)
			}
		}
		if len(a.Tools) != len(allowed) {
			t.Fatal("incomplete investigator evidence tools")
		}
		return
	}
	t.Fatal("native investigator was not registered")
}
