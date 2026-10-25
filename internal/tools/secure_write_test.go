package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	internal "github.com/Problem99-io/kodeblue/internal"
	"github.com/Problem99-io/kodeblue/internal/definitions"
	"github.com/Problem99-io/kodeblue/internal/policy"
	"golang.org/x/sys/unix"
)

func assertNoTempFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("temporary file left behind: %s", e.Name())
		}
	}
}

func TestSecureWriteReplacesAtomically(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "reports", "r.md")
	if err := secureWrite(context.Background(), root, path, []byte("first"), false); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := secureWrite(context.Background(), root, path, []byte("second"), true); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "second" {
		t.Fatalf("content = %q", got)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %v, want the replaced file's 0640", info.Mode().Perm())
	}
	assertNoTempFiles(t, filepath.Dir(path))
}

func TestSecureWriteWithoutOverwriteRefusesExisting(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "a.txt")
	if err := os.WriteFile(path, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := secureWrite(context.Background(), root, path, []byte("new"), false); !os.IsExist(err) {
		t.Fatalf("err = %v, want exists", err)
	}
	if got, _ := os.ReadFile(path); string(got) != "keep" {
		t.Fatalf("content = %q", got)
	}
	assertNoTempFiles(t, root)
}

func TestSecureWriteRefusesLinkedTargets(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "sym.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, filepath.Join(root, "hard.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(outside), filepath.Join(root, "dirlink")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"sym.txt", "hard.txt", "dirlink/outside.txt"} {
		if err := secureWrite(context.Background(), root, filepath.Join(root, name), []byte("x"), true); err == nil {
			t.Errorf("%s: write through a link succeeded", name)
		}
	}
	if got, _ := os.ReadFile(outside); string(got) != "outside" {
		t.Fatalf("outside file changed: %q", got)
	}
	assertNoTempFiles(t, root)
}

// A write that stops before the rename (here: the run is cancelled) leaves
// the old file whole and no temporary file behind.
func TestSecureWriteFailureKeepsOldFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "a.txt")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := secureWrite(ctx, root, path, []byte("new"), true); err == nil {
		t.Fatal("cancelled write succeeded")
	}
	if got, _ := os.ReadFile(path); string(got) != "old" {
		t.Fatalf("content = %q", got)
	}
	assertNoTempFiles(t, root)
}

// Readers racing an overwriting writer only ever see a complete version.
func TestSecureWriteReadersNeverSeePartialFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "def.json")
	versions := [][]byte{bytes.Repeat([]byte("a"), 1<<16), bytes.Repeat([]byte("b"), 1<<16)}
	if err := secureWrite(context.Background(), root, path, versions[0], false); err != nil {
		t.Fatal(err)
	}
	var stop atomic.Bool
	var wg sync.WaitGroup
	var bad atomic.Value
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				got, err := os.ReadFile(path)
				if err != nil || (!bytes.Equal(got, versions[0]) && !bytes.Equal(got, versions[1])) {
					bad.Store(len(got))
					return
				}
			}
		}()
	}
	for i := range 200 {
		if err := secureWrite(context.Background(), root, path, versions[i%2], true); err != nil {
			t.Fatal(err)
		}
	}
	stop.Store(true)
	wg.Wait()
	if n := bad.Load(); n != nil {
		t.Fatalf("a reader saw a partial file of %d bytes", n)
	}
}

// The path guard decodes write_file's arguments itself. For every argument
// shape here, if the guard allows the call then the tool must not write under
// the denied directory: a parser difference would show up as a denied file.
func TestToolGuardAgreesWithWriteFile(t *testing.T) {
	cases := []string{
		`{"path":"denied/a.txt","content":"x"}`,
		`{"PATH":"denied/a.txt","content":"x"}`,
		`{"path":"ok.txt","path":"denied/a.txt","content":"x"}`,
		`{"path":"ok.txt","writes":[{"path":"denied/a.txt","content":"x"}]}`,
		`{"writes":[{"path":"ok.txt","content":"x"},{"Path":"denied/a.txt","content":"x"}]}`,
		`{"writes":[{"path":"ok.txt","content":"x"}],"Writes":[{"path":"denied/a.txt","content":"x"}]}`,
		`{"writes":[],"path":"denied/a.txt","content":"x"}`,
		`{"writes":null,"path":"denied/a.txt","content":"x"}`,
		`{"path":"ok.txt\r\ndenied/a.txt","content":"x"}`,
		`{"path":"./denied/../denied/a.txt","content":"x"}`,
		`{"path":"sub/../denied/a.txt","content":"x"}`,
		`{"path":"denied/a.txt","content":"x"}`,
	}
	for _, raw := range cases {
		root := t.TempDir()
		cfg := policy.DefaultConfig()
		cfg.Paths.ProjectRoot = root
		cfg.Paths.AllowWritePaths = []string{"."}
		cfg.Paths.DenyPaths = []string{"denied"}
		guard, err := policy.NewToolGuard(cfg)
		if err != nil {
			t.Fatal(err)
		}
		check, err := guard.CheckToolExecutionAtRoot(internal.ToolName("write_file"), json.RawMessage(raw), root)
		if err != nil || !check.Allowed {
			continue
		}
		if _, err := NewWriteFile(ToolConfig{ProjectRoot: root}).Execute(context.Background(), json.RawMessage(raw)); err != nil {
			t.Fatal(err)
		}
		if entries, _ := os.ReadDir(filepath.Join(root, "denied")); len(entries) > 0 {
			t.Errorf("guard allowed %s but write_file wrote under denied/", raw)
		}
	}
}

// A rename needs only write access to the directory. The engine must still
// not replace a file it could not have written in place: one owned by another
// user, or one it may not write.
func TestSecureWriteRefusesFilesItCannotWrite(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "a.txt")
	if err := os.WriteFile(path, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	dirFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(dirFD)
	var st unix.Stat_t
	if err := unix.Fstatat(dirFD, "a.txt", &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		t.Fatal(err)
	}
	if err := checkReplaceable(dirFD, "a.txt", &st, int(st.Uid)+1); err == nil || !strings.Contains(err.Error(), "owned by another user") {
		t.Fatalf("file owned by another uid: err = %v", err)
	}
	if err := checkReplaceable(dirFD, "a.txt", &st, int(st.Uid)); err != nil {
		t.Fatalf("own writable file refused: %v", err)
	}

	if os.Geteuid() == 0 {
		t.Skip("root can write a read-only file")
	}
	if err := os.Chmod(path, 0o444); err != nil {
		t.Fatal(err)
	}
	if err := secureWrite(context.Background(), root, path, []byte("new"), true); err == nil {
		t.Fatal("replaced a read-only file")
	}
	if got, _ := os.ReadFile(path); string(got) != "keep" {
		t.Fatalf("content = %q", got)
	}
	assertNoTempFiles(t, root)
}

func TestSecureWriteNewFileRespectsUmask(t *testing.T) {
	old := unix.Umask(0o027)
	defer unix.Umask(old)
	root := t.TempDir()
	path := filepath.Join(root, "r.md")
	if err := secureWrite(context.Background(), root, path, []byte("x"), false); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %v, want 0664 less umask 027", info.Mode().Perm())
	}
}

func TestRemoveTempFilesAndListDirHidesThem(t *testing.T) {
	root := t.TempDir()
	store := definitions.NewStore(root)
	if _, err := store.List(); err != nil {
		t.Fatal(err)
	}
	temps := []string{
		filepath.Join(root, ".kodeblue-0123456789abcdef.tmp"),
		filepath.Join(root, "reports", ".kodeblue-fedcba9876543210.tmp"),
		filepath.Join(store.Root(), ".def_a.json.tmp-0123456789abcdef"),
	}
	keep := []string{filepath.Join(root, "reports", "r.md"), filepath.Join(root, ".kodeblue-notes.tmp")}
	for _, p := range append(append([]string{}, temps...), keep...) {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	res, err := NewListDir(ToolConfig{ProjectRoot: root}).Execute(context.Background(), mustJSON(t, map[string]string{"path": "reports"}))
	if err != nil || res.IsError {
		t.Fatalf("list_dir: %v %v", err, res)
	}
	if res.Content != "r.md" {
		t.Fatalf("list_dir reports = %q, want only r.md", res.Content)
	}

	// A sweep with an age limit keeps files a write in flight may own.
	RemoveTempFiles(root, root, time.Hour)
	for _, p := range temps {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("fresh temp file removed by an aged sweep: %s", p)
		}
	}
	RemoveTempFiles(root, root, 0)
	for _, p := range temps {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("temp file kept: %s", p)
		}
	}
	for _, p := range keep {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("real file removed: %s", p)
		}
	}
}
