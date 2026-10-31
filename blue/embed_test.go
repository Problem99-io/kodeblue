package blue

import (
	"io/fs"
	"strings"
	"testing"

	"github.com/Problem99-io/kodeblue/internal/skill"
)

func TestAgentsParse(t *testing.T) {
	agents, err := Agents()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"blue-learner": false, "blue-responder": false, "blue-reviewer": false, "blue-operator": false, "blue-assessor": false, "blue-investigator": false}
	for _, a := range agents {
		want[a.Name] = true
		if len(a.Tools) == 0 || (a.Name != "blue-investigator" && len(a.Tools) < 5) || a.Instructions == "" || a.MaxIterations == 0 {
			t.Errorf("%s incomplete: %+v", a.Name, a)
		}
		for _, tool := range a.Tools {
			if strings.Contains(tool, "run_shell") || strings.Contains(tool, "fetch") || strings.Contains(tool, "web_search") {
				t.Errorf("%s must not get %s", a.Name, tool)
			}
		}
	}
	for n, ok := range want {
		if !ok {
			t.Errorf("missing agent %s", n)
		}
	}
	for _, a := range agents {
		hasResolve := false
		hasRespond := false
		for _, tool := range a.Tools {
			hasResolve = hasResolve || tool == "mcp__kodeblue__incident_resolve"
			hasRespond = hasRespond || tool == "mcp__kodeblue__respond"
		}
		if a.Name == "blue-responder" && !hasResolve {
			t.Error("responder must be able to resolve incidents")
		}
		// Containment is for incident response and for explicit operator
		// requests; the learner and reviewer never act on the host.
		if a.Name != "blue-responder" && a.Name != "blue-operator" && hasRespond {
			t.Errorf("%s must not have containment actions", a.Name)
		}
	}
}

func TestSkillsParse(t *testing.T) {
	n := 0
	err := fs.WalkDir(SkillsFS, "skills", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, _ := SkillsFS.ReadFile(path)
		def, err := skill.ParseMarkdown(string(b))
		if err != nil {
			t.Errorf("%s: %v", path, err)
			return nil
		}
		if err := skill.ValidateName(def.Name); err != nil {
			t.Errorf("%s: %v", path, err)
		}
		if !strings.Contains(string(b), "kodeblue-bundled: true") {
			t.Errorf("%s must carry the bundled marker", path)
		}
		n++
		return nil
	})
	if err != nil || n < 5 {
		t.Fatalf("skills: %v (%d)", err, n)
	}
}

func TestAgentsSendNoOutputCap(t *testing.T) {
	agents, err := Agents()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range agents {
		if a.MaxOutputTokens != -1 {
			t.Errorf("%s: max_output_tokens %d; kodeblue agents must not cap output (-1)", a.Name, a.MaxOutputTokens)
		}
	}
}
