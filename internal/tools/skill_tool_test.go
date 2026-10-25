package tools

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Problem99-io/kodeblue/internal/skill"
)

// Skills published to the agent-skills ecosystem ship references/ and
// templates/ next to SKILL.md and point at them by relative path, so loading a
// skill has to tell the model where the directory is and what is in it.
func TestSkillToolListsBundledFiles(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}

	skillDir := filepath.Join(root, ".kodeblue", "skills", "clerk-nextjs-patterns")
	for _, sub := range []string{"references", "templates/nextjs-app"} {
		if err := os.MkdirAll(filepath.Join(skillDir, sub), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", sub, err)
		}
	}

	files := map[string]string{
		"SKILL.md":                      "---\nname: clerk-nextjs-patterns\ndescription: Advanced Next.js patterns.\n---\n\nSee references/middleware.md\n",
		"references/middleware.md":      "# middleware",
		"references/server-actions.md":  "# server actions",
		"templates/nextjs-app/page.tsx": "export default function Page() {}",
	}
	for rel, content := range files {
		if err := os.WriteFile(filepath.Join(skillDir, rel), []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}

	registry := skill.NewRegistry(root, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	registry.Discover()

	tool := NewSkillTool(registry)
	result, err := tool.Execute(context.Background(), json.RawMessage(`{"name":"clerk-nextjs-patterns"}`))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error result: %s", result.Content)
	}

	for _, want := range []string{
		skillDir,
		"references/middleware.md",
		"references/server-actions.md",
		"templates/nextjs-app/page.tsx",
		"See references/middleware.md", // body still present
	} {
		if !strings.Contains(result.Content, want) {
			t.Errorf("result missing %q\n---\n%s", want, result.Content)
		}
	}

	// SKILL.md itself is redundant — its content is already inlined.
	if strings.Contains(result.Content, "- SKILL.md") {
		t.Error("SKILL.md should not be listed as a bundled file")
	}

	if got := result.Metadata["directory_path"]; got != skillDir {
		t.Errorf("directory_path = %v, want %s", got, skillDir)
	}
}

// A skill with nothing beside SKILL.md must not grow an empty listing.
func TestSkillToolOmitsEmptyBundledListing(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}
	skillDir := filepath.Join(root, ".kodeblue", "skills", "solo")
	if err := os.MkdirAll(skillDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(skillDir, "SKILL.md"),
		[]byte("---\nname: solo\ndescription: Nothing bundled.\n---\n\nbody\n"),
		0o644,
	); err != nil {
		t.Fatalf("write: %v", err)
	}

	registry := skill.NewRegistry(root, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	registry.Discover()

	result, err := NewSkillTool(registry).Execute(context.Background(), json.RawMessage(`{"name":"solo"}`))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if strings.Contains(result.Content, "Bundled files") {
		t.Errorf("expected no bundled listing:\n%s", result.Content)
	}
	if !strings.Contains(result.Content, skillDir) {
		t.Error("directory should still be reported")
	}
}
