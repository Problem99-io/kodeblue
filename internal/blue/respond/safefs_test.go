package respond

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyMaterial mallory@evil"

func keyID() string {
	h := sha256.Sum256([]byte(testKey))
	return hex.EncodeToString(h[:])[:16]
}

// keyHome makes a home for user "bob" (the test's own uid) and points
// passwdPath at it.
func keyHome(t *testing.T) (home, stateDir string) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home, stateDir = filepath.Join(root, "home", "bob"), filepath.Join(root, "state")
	for _, d := range []string{home, stateDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	passwd := filepath.Join(root, "passwd")
	line := fmt.Sprintf("bob:x:%d:%d::%s:/bin/sh\n", os.Getuid(), os.Getgid(), home)
	if err := os.WriteFile(passwd, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	old := passwdPath
	passwdPath = passwd
	t.Cleanup(func() { passwdPath = old })
	return home, stateDir
}

func TestDisableKeyAndUndo(t *testing.T) {
	home, stateDir := keyHome(t)
	ssh := filepath.Join(home, ".ssh")
	os.Mkdir(ssh, 0o700)
	keys := filepath.Join(ssh, "authorized_keys")
	orig := "ssh-ed25519 AAAAgood alice@laptop\n" + testKey + "\n"
	if err := os.WriteFile(keys, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	undo, _, err := disableKey(stateDir, "bob", keyID())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(keys)
	if !strings.HasPrefix(string(b), "ssh-ed25519 AAAAgood alice@laptop\n# kodeblue-disabled ") {
		t.Fatalf("after disable:\n%s", b)
	}
	if !strings.HasPrefix(undo["backup"], filepath.Join(stateDir, "ssh-keys")+"/") {
		t.Fatalf("backup outside the state dir: %s", undo["backup"])
	}
	if bk, _ := os.ReadFile(undo["backup"]); string(bk) != orig {
		t.Fatalf("backup: %q", bk)
	}
	if st, _ := os.Stat(keys); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode changed to %v", st.Mode())
	}
	// A key the user adds afterwards survives the undo.
	f, _ := os.OpenFile(keys, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("ssh-ed25519 AAAAnew alice@phone\n")
	f.Close()
	if err := enableKey(undo); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(keys); string(b) != orig+"ssh-ed25519 AAAAnew alice@phone\n" {
		t.Fatalf("after undo:\n%s", b)
	}
	if err := enableKey(undo); err == nil {
		t.Fatal("second undo found a marker")
	}
}

func TestDisableKeyRefusesLinks(t *testing.T) {
	cases := map[string]func(t *testing.T, ssh, victim string){
		"symlinked authorized_keys": func(t *testing.T, ssh, victim string) {
			os.Mkdir(ssh, 0o700)
			if err := os.Symlink(victim, filepath.Join(ssh, "authorized_keys")); err != nil {
				t.Fatal(err)
			}
		},
		"symlinked .ssh": func(t *testing.T, ssh, victim string) {
			if err := os.Symlink(filepath.Dir(victim), ssh); err != nil {
				t.Fatal(err)
			}
		},
		"hard-linked authorized_keys": func(t *testing.T, ssh, victim string) {
			os.Mkdir(ssh, 0o700)
			if err := os.Link(victim, filepath.Join(ssh, "authorized_keys")); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, plant := range cases {
		t.Run(name, func(t *testing.T) {
			home, stateDir := keyHome(t)
			// victim stands in for /etc/shadow: a file the user must not
			// get root to rewrite. It holds the key so a followed link
			// would match.
			vdir := filepath.Join(filepath.Dir(stateDir), "etc")
			os.Mkdir(vdir, 0o700)
			victim := filepath.Join(vdir, "authorized_keys")
			if err := os.WriteFile(victim, []byte(testKey+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			plant(t, filepath.Join(home, ".ssh"), victim)
			if _, _, err := disableKey(stateDir, "bob", keyID()); err == nil {
				t.Fatal("disableKey went through a link")
			}
			if b, _ := os.ReadFile(victim); string(b) != testKey+"\n" {
				t.Fatalf("victim changed: %q", b)
			}
		})
	}
}

func TestQuarantineAndRestore(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := Policy{StateDir: filepath.Join(root, "state")}
	// restore re-validates the destination against the quarantine allow-list;
	// the test's temp root stands in for an allowed location.
	defer func(a []string) { quarantineAllowedRoots = a }(quarantineAllowedRoots)
	quarantineAllowedRoots = append(quarantineAllowedRoots, root+"/")
	drop := filepath.Join(root, "tmp", ".x")
	os.MkdirAll(drop, 0o755)
	miner := filepath.Join(drop, "miner")
	os.WriteFile(miner, []byte("evil"), 0o751)

	undo, _, err := quarantine(p, miner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(miner); !os.IsNotExist(err) {
		t.Fatal("file still in place")
	}
	if err := restore(p.StateDir, undo); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(miner)
	if err != nil || st.Mode().Perm() != 0o751 {
		t.Fatalf("restored: %v %v", st, err)
	}
	if b, _ := os.ReadFile(miner); string(b) != "evil" {
		t.Fatalf("restored content %q", b)
	}

	// Restore never replaces what is at the path now.
	if _, _, err := quarantine(p, miner); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(miner, []byte("new"), 0o600)
	if err := restore(p.StateDir, undo); err == nil {
		t.Fatal("restore overwrote an existing file")
	}
}

func TestQuarantineAndRestoreRefuseLinks(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := Policy{StateDir: filepath.Join(root, "state")}
	etc := filepath.Join(root, "etc")
	os.Mkdir(etc, 0o700)
	shadow := filepath.Join(etc, "shadow")
	os.WriteFile(shadow, []byte("secret"), 0o600)
	tmp := filepath.Join(root, "tmp")
	os.Mkdir(tmp, 0o777)

	// The file itself is a link.
	link := filepath.Join(tmp, "x")
	os.Symlink(shadow, link)
	if _, _, err := quarantine(p, link); err == nil {
		t.Fatal("quarantined through a symlink")
	}
	// A directory on the way is a link the user controls.
	os.Symlink(etc, filepath.Join(tmp, "d"))
	if _, _, err := quarantine(p, filepath.Join(tmp, "d", "shadow")); err == nil {
		t.Fatal("quarantined through a symlinked directory")
	}
	if b, _ := os.ReadFile(shadow); string(b) != "secret" {
		t.Fatal("shadow touched")
	}

	// Restore into a directory swapped for a link (think /etc/cron.d).
	q := filepath.Join(tmp, "q")
	os.Mkdir(q, 0o755)
	f := filepath.Join(q, "job")
	os.WriteFile(f, []byte("* * * * * root evil"), 0o644)
	undo, _, err := quarantine(p, f)
	if err != nil {
		t.Fatal(err)
	}
	os.Remove(q)
	os.Symlink(etc, q)
	if err := restore(p.StateDir, undo); err == nil {
		t.Fatal("restored through a symlinked directory")
	}
	if _, err := os.Lstat(filepath.Join(etc, "job")); !os.IsNotExist(err) {
		t.Fatal("file written into the link target")
	}
}
