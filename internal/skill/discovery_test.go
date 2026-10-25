package skill

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func writeSkill(t *testing.T, dir, name, description string) {
	t.Helper()
	skillDir := filepath.Join(dir, name)
	if err := os.MkdirAll(skillDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", skillDir, err)
	}
	body := "---\nname: " + name + "\ndescription: " + description + "\n---\n\nbody\n"
	if err := os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte(body), 0o644); err != nil {
		t.Fatalf("write SKILL.md: %v", err)
	}
}

// Discovery scans only <project>/.kodeblue/skills; other agents' skill
// directories in the project are not part of the engine's skill set.
func TestDiscoverScansOnlyKodeblueSkillsDir(t *testing.T) {
	root := t.TempDir()
	writeSkill(t, filepath.Join(root, ".kodeblue", "skills"), "kept", "Discovered.")
	for _, other := range []string{".agents", ".claude", ".opencode", "agent"} {
		writeSkill(t, filepath.Join(root, other, "skills"), "ignored-"+strings.TrimPrefix(other, "."), "Not discovered.")
	}

	r := NewRegistry(root, nil, quietLogger())
	r.Discover()

	if _, ok := r.Load("kept"); !ok {
		t.Error("skill from .kodeblue/skills not discovered")
	}
	if got := len(r.List()); got != 1 {
		t.Errorf("discovered %d skills, want only the .kodeblue/skills one", got)
	}
}

// A skill installed mid-session must show up on the next run without a restart.
func TestRefreshPicksUpNewlyInstalledSkill(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // Keep ambient installed user skills out of this fixture.
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}
	skillsDir := filepath.Join(root, ".kodeblue", "skills")
	writeSkill(t, skillsDir, "already-here", "Present before the install.")

	r := NewRegistry(root, nil, quietLogger())
	r.Discover()
	if len(r.List()) != 1 {
		t.Fatalf("expected 1 skill before install, got %d", len(r.List()))
	}

	// Refresh with nothing changed must not lose what we already had.
	r.Refresh()
	if _, ok := r.Load("already-here"); !ok {
		t.Fatal("no-op refresh dropped an existing skill")
	}

	// Simulate `npx skills add`: a new subdirectory bumps the parent's mtime.
	writeSkill(t, skillsDir, "clerk-billing", "Clerk Billing for subscription management.")
	bumpModTime(t, skillsDir)

	r.Refresh()
	if _, ok := r.Load("clerk-billing"); !ok {
		t.Error("newly installed skill not picked up by Refresh")
	}
	if _, ok := r.Load("already-here"); !ok {
		t.Error("Refresh dropped a pre-existing skill")
	}
}

// A skill removed on disk must disappear on the next refresh.
func TestRefreshDropsRemovedSkill(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}
	skillsDir := filepath.Join(root, ".kodeblue", "skills")
	writeSkill(t, skillsDir, "temporary", "Goes away.")

	r := NewRegistry(root, nil, quietLogger())
	r.Discover()
	if _, ok := r.Load("temporary"); !ok {
		t.Fatal("skill not discovered before removal")
	}

	if err := os.RemoveAll(filepath.Join(skillsDir, "temporary")); err != nil {
		t.Fatalf("remove: %v", err)
	}
	bumpModTime(t, skillsDir)

	r.Refresh()
	if _, ok := r.Load("temporary"); ok {
		t.Error("removed skill still present after Refresh")
	}
}

// bumpModTime pushes a directory's mtime forward so the change is visible
// regardless of the filesystem's timestamp granularity.
func bumpModTime(t *testing.T, dir string) {
	t.Helper()
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat %s: %v", dir, err)
	}
	future := info.ModTime().Add(2 * time.Second)
	if err := os.Chtimes(dir, future, future); err != nil {
		t.Fatalf("chtimes %s: %v", dir, err)
	}
}

// A broken symlink must be skipped rather than abort the scan.
func TestDiscoverSkipsBrokenSymlink(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}

	skillsDir := filepath.Join(root, ".kodeblue", "skills")
	if err := os.MkdirAll(skillsDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Symlink(filepath.Join("..", "..", "nope"), filepath.Join(skillsDir, "dangling")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	writeSkill(t, filepath.Join(root, ".kodeblue", "skills"), "intact", "Still discovered.")

	r := NewRegistry(root, nil, quietLogger())
	r.Discover()

	if _, ok := r.Load("dangling"); ok {
		t.Error("broken symlink should not yield a skill")
	}
	if _, ok := r.Load("intact"); !ok {
		t.Error("scan should continue past a broken symlink")
	}
}
