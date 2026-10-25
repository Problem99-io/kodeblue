package definitions

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestStoreUpdateIsAtomic(t *testing.T) {
	store := NewStore(t.TempDir())
	created, err := store.Create(Definition{Title: "Server role", Snippet: "web", Content: "nginx", Scope: []string{"etc/nginx"}})
	if err != nil {
		t.Fatal(err)
	}
	path, _ := store.pathForID(created.ID)

	var stop atomic.Bool
	var wg sync.WaitGroup
	var bad atomic.Value
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				data, err := os.ReadFile(path)
				if err != nil || !bytes.HasSuffix(data, []byte("}\n")) {
					bad.Store(len(data))
					return
				}
			}
		}()
	}
	for i := range 200 {
		created.Content = strings.Repeat("x", 1000+i)
		if _, err := store.Update(*created); err != nil {
			t.Fatal(err)
		}
	}
	stop.Store(true)
	wg.Wait()
	if n := bad.Load(); n != nil {
		t.Fatalf("a reader saw a partial definition of %d bytes", n)
	}

	entries, _ := os.ReadDir(store.Root())
	if len(entries) != 1 {
		t.Fatalf("definitions dir holds %d entries, want only the definition", len(entries))
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("mode = %v", info.Mode().Perm())
	}
}

// An empty definition left by a crash before writes were atomic, and a
// temporary file a crash left mid-write, must not hide the good definitions.
func TestStoreListSkipsDamagedAndTemporaryFiles(t *testing.T) {
	store := NewStore(t.TempDir())
	good, err := store.Create(Definition{Title: "Access model", Snippet: "keys", Content: "ssh keys only", Scope: []string{"etc/ssh"}})
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{
		"def_empty.json": "",
		"." + good.ID + ".json.tmp-0123456789abcdef": "{",
		"def_trunc.json": `{"id":"def_trunc","ti`,
	} {
		if err := os.WriteFile(filepath.Join(store.Root(), name), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	items, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].ID != good.ID {
		t.Fatalf("List = %#v, want only %s", items, good.ID)
	}
	if _, err := store.Get("def_empty"); err == nil {
		t.Fatal("Get of an empty definition should report the damage")
	}
}

func TestStoreListRemovesStaleTemporaryFiles(t *testing.T) {
	store := NewStore(t.TempDir())
	if _, err := store.List(); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(store.Root(), ".def_a.json.tmp-0000000000000001")
	fresh := filepath.Join(store.Root(), ".def_a.json.tmp-0000000000000002")
	for _, p := range []string{stale, fresh} {
		if err := os.WriteFile(p, []byte("{"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-2 * staleTempAge)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}
	if _, err := store.List(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale temporary file kept: %v", err)
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Fatalf("fresh temporary file (a write in flight) removed: %v", err)
	}
}

// New definitions get 0644 less the umask, as os.WriteFile gave them; a
// rewritten one keeps the mode it has.
func TestStoreWriteRespectsUmaskAndKeepsMode(t *testing.T) {
	old := unix.Umask(0o027)
	defer unix.Umask(old)
	store := NewStore(t.TempDir())
	def, err := store.Create(Definition{Title: "Access model", Snippet: "keys", Content: "keys only", Scope: []string{"etc/ssh"}})
	if err != nil {
		t.Fatal(err)
	}
	path, _ := store.pathForID(def.ID)
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o640 {
		t.Fatalf("new definition mode = %v, want 0640 under umask 027", info.Mode().Perm())
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	def.Content = "keys only, no passwords"
	if _, err := store.Update(*def); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Fatalf("rewritten definition mode = %v, want its 0600 kept", info.Mode().Perm())
	}
}
