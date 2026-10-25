//go:build linux

package respond

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// A process to look at through /proc/<pid>/root: the test binary itself,
// chrooted into a jail, sleeping.
func TestMain(m *testing.M) {
	if os.Getenv("KODEBLUE_TEST_SLEEP") == "1" {
		time.Sleep(time.Minute)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestWalkStaysInsideProcRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to chroot")
	}
	jail := t.TempDir()
	_ = os.Chmod(jail, 0o755)
	for _, d := range []string{"bin", "tmp", "etc"} {
		if err := os.Mkdir(filepath.Join(jail, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	self, _ := os.Executable()
	copyExe(t, self, filepath.Join(jail, "bin", "t"))
	_ = os.WriteFile(filepath.Join(jail, "etc", "jail-marker"), nil, 0o644)
	_ = os.WriteFile(filepath.Join(jail, "tmp", "payload"), []byte("x"), 0o644)
	// Links that would leave the jail if resolved against the host's root.
	_ = os.Symlink("/etc", filepath.Join(jail, "tmp", "abs"))
	_ = os.Symlink("../../../../../../etc", filepath.Join(jail, "tmp", "rel"))

	cmd := exec.Command("/bin/t")
	cmd.Env = []string{"KODEBLUE_TEST_SLEEP=1"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Chroot: jail}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	base := fmt.Sprintf("/proc/%d/root", cmd.Process.Pid)
	for i := 0; i < 50; i++ {
		if l, _ := os.Readlink(base); l == "/" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	for _, link := range []string{"abs", "rel"} {
		fd, err := openDir(base + "/tmp/" + link)
		if err != nil {
			t.Fatalf("%s: %v", link, err)
		}
		err = unix.Faccessat(fd, "jail-marker", unix.F_OK, 0)
		unix.Close(fd)
		if err != nil {
			t.Fatalf("%s resolved outside the process's root", link)
		}
	}

	state := t.TempDir()
	if _, _, err := quarantine(Policy{StateDir: state}, base+"/tmp/payload"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(jail, "tmp", "payload")); !os.IsNotExist(err) {
		t.Fatalf("payload still in the jail: %v", err)
	}
}

func copyExe(t *testing.T, src, dst string) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	out.Close()
}
