package hub

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func sha(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// distHub is a hub whose dist holds the given files.
func distHub(t *testing.T, files map[string]string) *Server {
	t.Helper()
	dir := t.TempDir()
	st, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	dist := filepath.Join(dir, "dist")
	_ = os.MkdirAll(dist, 0o755)
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dist, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return NewServer(Options{DataDir: dir, DistDir: dist, PublicURL: "https://hub.example.com:8443", Pin: "sha256//AbC+/x="}, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

const testInstaller = "#!/bin/sh\n# kodeblue installer\n#   --help text\nset -eu\necho \"$KODEBLUE_DIST_SHA256SUMS\"\n"

func TestInstallScriptPinsTarballs(t *testing.T) {
	amd, arm := "amd64 tarball", "arm64 tarball"
	s := distHub(t, map[string]string{
		"install.sh":                  testInstaller,
		"kodeblue-linux-amd64.tar.gz": amd,
		"kodeblue-linux-arm64.tar.gz": arm,
		"SHA256SUMS":                  sha([]byte(amd)) + "  kodeblue-linux-amd64.tar.gz\n" + sha([]byte(arm)) + "  kodeblue-linux-arm64.tar.gz\n",
		"notes.txt":                   "not a tarball",
	})
	snap := s.dist()
	script := string(snap.script)
	want := "KODEBLUE_DIST_SHA256SUMS='" + sha([]byte(amd)) + "  kodeblue-linux-amd64.tar.gz\n" + sha([]byte(arm)) + "  kodeblue-linux-arm64.tar.gz'\n"
	if !strings.Contains(script, want) || strings.Contains(script, "notes.txt") {
		t.Fatalf("pinned sums missing or wrong:\n%s", script)
	}
	// The header comment (printed by --help by line number) stays on top.
	if !strings.HasPrefix(script, "#!/bin/sh\n# kodeblue installer\n#   --help text\n# Pinned") || !strings.HasSuffix(script, "set -eu\necho \"$KODEBLUE_DIST_SHA256SUMS\"\n") {
		t.Fatalf("script layout:\n%s", script)
	}
	// Changing a release file under a running hub does not change the pins.
	_ = os.WriteFile(filepath.Join(s.opt.DistDir, "kodeblue-linux-amd64.tar.gz"), []byte("swapped"), 0o644)
	if string(s.dist().script) != script {
		t.Fatal("pins were recomputed from swapped files")
	}

	// The served script is exactly what the command pins.
	r, _ := http.NewRequest("GET", "https://hub.example.com:8443/", nil)
	cmd := s.InstallCommand(r, "kbe_tok-123")
	if snap.sum != sha(snap.script) || !strings.Contains(cmd, `echo "`+snap.sum+`  $f" | sha256sum -c - && `) {
		t.Fatalf("command does not pin the served script (%s):\n%s", snap.sum, cmd)
	}
	for _, part := range []string{`f=$(mktemp) && r=$([ "$(id -u)" = 0 ] || echo sudo) && { curl -fsSL --proto =https --proto-redir =https -k --pinnedpubkey sha256//AbC+/x= -o "$f" https://hub.example.com:8443/install.sh`,
		`$r sh "$f" --hub https://hub.example.com:8443 --pin sha256//AbC+/x= --token kbe_tok-123; s=$?; rm -f "$f"; (exit "$s"); }`} {
		if !strings.Contains(cmd, part) {
			t.Fatalf("command lacks %q:\n%s", part, cmd)
		}
	}
	w := &recorder{h: http.Header{}}
	s.handleInstallScript(w, r)
	if w.body.String() != script {
		t.Fatal("served install.sh differs from the pinned one")
	}
}

type recorder struct {
	h    http.Header
	code int
	body strings.Builder
}

func (r *recorder) Header() http.Header         { return r.h }
func (r *recorder) Write(b []byte) (int, error) { return r.body.Write(b) }
func (r *recorder) WriteHeader(c int)           { r.code = c }

// A tarball that disagrees with SHA256SUMS is pinned to nothing, so its
// install fails instead of trusting either.
func TestInstallScriptRefusesMismatchedRelease(t *testing.T) {
	s := distHub(t, map[string]string{
		"install.sh":                  testInstaller,
		"kodeblue-linux-amd64.tar.gz": "tampered",
		"kodeblue-linux-arm64.tar.gz": "arm",
		"SHA256SUMS":                  sha([]byte("original")) + "  kodeblue-linux-amd64.tar.gz\n",
	})
	script := string(s.dist().script)
	if strings.Contains(script, "kodeblue-linux-amd64.tar.gz") || !strings.Contains(script, sha([]byte("arm"))+"  kodeblue-linux-arm64.tar.gz") {
		t.Fatalf("pins:\n%s", script)
	}
}

// When the installer reads the token from stdin (--token-file -), the
// command pipes it there instead of putting it on install.sh's command line.
func TestInstallCommandTokenForm(t *testing.T) {
	s := distHub(t, map[string]string{"install.sh": "#!/bin/sh\n# --token-file F  read the token from F (- for stdin)\nKODEBLUE_ENROLL_TOKEN=$TOKEN\n"})
	r, _ := http.NewRequest("GET", "https://x/", nil)
	cmd := s.InstallCommand(r, "kbe_abc")
	if !strings.Contains(cmd, `printf '%s\n' kbe_abc | $r sh "$f" --hub https://hub.example.com:8443 --pin sha256//AbC+/x= --token-file -; s=$?`) || strings.Contains(cmd, "--token ") {
		t.Fatalf("stdin form:\n%s", cmd)
	}
	// An older installer (which mentions KODEBLUE_ENROLL_TOKEN only for its
	// own enroll call) still gets --token.
	old := distHub(t, map[string]string{"install.sh": "#!/bin/sh\nKODEBLUE_ENROLL_TOKEN=$TOKEN kodeblue enroll\n"})
	if cmd := old.InstallCommand(r, "kbe_abc"); !strings.Contains(cmd, "--token kbe_abc;") || strings.Contains(cmd, "printf") {
		t.Fatalf("flag form:\n%s", cmd)
	}
	// No installer published: the plain pipe form (the hub's 404 explains).
	empty := distHub(t, nil)
	if cmd := empty.InstallCommand(r, "kbe_abc"); !strings.HasPrefix(cmd, "curl -fsSL --proto =https --proto-redir =https -k --pinnedpubkey sha256//AbC+/x= https://hub.example.com:8443/install.sh | sudo sh -s -- ") {
		t.Fatalf("fallback: %s", cmd)
	}
}

func TestInstallCommandQuotesHost(t *testing.T) {
	s := distHub(t, map[string]string{"install.sh": testInstaller})
	s.opt.PublicURL = ""
	r, _ := http.NewRequest("GET", "https://x/", nil)
	r.Host = "evil;touch /tmp/x"
	if cmd := s.InstallCommand(r, "kbe_abc"); strings.Count(cmd, "evil;") != 2 || strings.Count(cmd, "'http://evil;") != 2 {
		t.Fatalf("host not quoted: %s", cmd)
	}
}

// The command keeps the installer's exit status, and runs it only when the
// script matches the pinned hash.
func TestInstallCommandRuns(t *testing.T) {
	if _, err := exec.LookPath("sha256sum"); err != nil {
		t.Skip("no sha256sum")
	}
	s := distHub(t, map[string]string{"install.sh": "#!/bin/sh\necho ran \"$@\"\nexit 3\n"})
	r, _ := http.NewRequest("GET", "https://x/", nil)
	// Stand-ins: curl copies the served script, sudo just runs its command.
	bin := t.TempDir()
	served := filepath.Join(bin, "served.sh")
	_ = os.WriteFile(served, s.dist().script, 0o644)
	_ = os.WriteFile(filepath.Join(bin, "curl"), []byte("#!/bin/sh\nwhile [ $# -gt 1 ]; do [ \"$1\" = -o ] && out=$2; shift; done\ncp \""+served+"\" \"$out\"\n"), 0o755)
	_ = os.WriteFile(filepath.Join(bin, "sudo"), []byte("#!/bin/sh\nexec \"$@\"\n"), 0o755)
	run := func() (string, int) {
		c := exec.Command("sh", "-c", s.InstallCommand(r, "kbe_abc"))
		c.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"))
		out, _ := c.CombinedOutput()
		return string(out), c.ProcessState.ExitCode()
	}
	if out, code := run(); code != 3 || !strings.Contains(out, "ran --hub") {
		t.Fatalf("matching script: exit %d, %s", code, out)
	}
	_ = os.WriteFile(served, append(s.dist().script, "echo evil\n"...), 0o644)
	if out, code := run(); code == 0 || strings.Contains(out, "ran") || strings.Contains(out, "evil") {
		t.Fatalf("tampered script ran: exit %d, %s", code, out)
	}

	// An installer that takes --token-file - gets the token on its stdin.
	s = distHub(t, map[string]string{"install.sh": "#!/bin/sh\n# --token-file F\necho \"args=$* token=$(cat)\"\n"})
	_ = os.WriteFile(served, s.dist().script, 0o644)
	if out, code := run(); code != 0 || !strings.Contains(out, "token=kbe_abc") || !strings.Contains(out, "--token-file -") || strings.Contains(out, "args=--hub https://hub.example.com:8443 --pin sha256//AbC+/x= --token kbe") {
		t.Fatalf("stdin token: exit %d, %s", code, out)
	}
}

func TestPinSumsAndShq(t *testing.T) {
	if got := string(pinSums([]byte("set -eu\n"), []string{"a  b"})); !strings.HasSuffix(got, "KODEBLUE_DIST_SHA256SUMS='a  b'\nset -eu\n") || !strings.HasPrefix(got, "# Pinned") {
		t.Fatalf("no header: %q", got)
	}
	if got := string(pinSums([]byte("#!/bin/sh"), nil)); !strings.HasPrefix(got, "#!/bin/sh\n# Pinned") {
		t.Fatalf("no newline: %q", got)
	}
	for in, want := range map[string]string{"kbe_A-b.c": "kbe_A-b.c", "": "''", "a b": "'a b'", "it's": `'it'\''s'`, "$(x)": "'$(x)'"} {
		if got := shq(in); got != want {
			t.Errorf("shq(%q) = %s, want %s", in, got, want)
		}
	}
}

// The installer in this repository must use the sums the hub pins; if it
// stops reading the variable, the pin silently does nothing.
func TestRepoInstallerReadsPinnedSums(t *testing.T) {
	b, err := os.ReadFile("../../deploy/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`printf '%s\\n' "\$` + distSumsVar + `" > "\$tmp/SHA256SUMS"`).Match(b) {
		t.Fatalf("deploy/install.sh does not read $%s", distSumsVar)
	}
}
