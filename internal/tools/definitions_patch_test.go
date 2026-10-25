package tools

import (
	"strings"
	"testing"

	"github.com/Problem99-io/kodeblue/internal/definitions"
)

func TestPatchDefinitionMultilineContent(t *testing.T) {
	def, err := patchDefinition(definitions.Definition{Title: "Server role"}, `content: WORKLOAD: OWASP Juice Shop
node /juice-shop/build/app.js on port 3000

uid 65532, distroless image
snippet: Juice Shop on :3000
*** Add Note: relearn
Title: Relearn
Content: re-verified`)
	if err != nil {
		t.Fatal(err)
	}
	want := "WORKLOAD: OWASP Juice Shop\nnode /juice-shop/build/app.js on port 3000\n\nuid 65532, distroless image"
	if def.Content != want {
		t.Errorf("content = %q, want %q", def.Content, want)
	}
	if def.Snippet != "Juice Shop on :3000" {
		t.Errorf("snippet = %q", def.Snippet)
	}
	if len(def.Notes) != 1 || def.Notes[0].ID != "relearn" || def.Notes[0].Content != "re-verified" {
		t.Errorf("notes = %+v", def.Notes)
	}
}

func TestPatchDefinitionErrorShowsSyntax(t *testing.T) {
	_, err := patchDefinition(definitions.Definition{}, `notes: add id=x title="y"`)
	if err == nil || !strings.Contains(err.Error(), "*** Add Note:") {
		t.Fatalf("error should show the syntax, got %v", err)
	}
}
