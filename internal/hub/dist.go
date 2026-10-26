package hub

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Release integrity. SHA256SUMS lives next to the tarballs, so whoever can
// swap a tarball on the hub (or in transit, without a pin) can swap its
// checksum too. Instead the hub pins hashes into what servers run:
//
//   - the install command the console prints carries the sha256 of the
//     install.sh the hub serves, and checks it before running it as root;
//   - that install.sh carries the sha256 of every agent tarball
//     (KODEBLUE_DIST_SHA256SUMS), which the installer checks the download
//     against instead of fetching SHA256SUMS.
//
// The hashes are taken once, when first needed, and kept until the hub
// restarts (an upgrade restarts it), so release files changed under a
// running hub fail the check instead of being installed.

// distSumsVar is the shell variable install.sh reads the pinned sums from.
const distSumsVar = "KODEBLUE_DIST_SHA256SUMS"

var tarballRe = regexp.MustCompile(`^kodeblue-linux-[a-z0-9]+\.tar\.gz$`)

type distSnapshot struct {
	script []byte // install.sh as served, nil when the hub has none
	sum    string // hex sha256 of script
	// tokenStdin: the installer reads the enrollment token with
	// --token-file - (stdin), so it need not be on any command line.
	tokenStdin bool
	// hubMaxMode: the installer takes --hub-max-mode.
	hubMaxMode bool
}

// dist returns the snapshot, taking it on first use. Until an installer is
// published the hub keeps looking, so a dist filled after the hub started
// is picked up; once taken, the snapshot holds until the hub restarts.
func (s *Server) dist() *distSnapshot {
	s.distMu.Lock()
	defer s.distMu.Unlock()
	if s.distSnap == nil || s.distSnap.script == nil {
		s.distSnap = s.snapshotDist()
	}
	return s.distSnap
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// listedSums reads a SHA256SUMS file: name -> hex hash.
func listedSums(path string) map[string]string {
	out := map[string]string{}
	b, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		if f := strings.Fields(sc.Text()); len(f) == 2 {
			out[strings.TrimPrefix(f[1], "*")] = strings.ToLower(f[0])
		}
	}
	return out
}

func (s *Server) snapshotDist() *distSnapshot {
	snap := &distSnapshot{}
	if s.opt.DistDir == "" {
		return snap
	}
	raw, err := os.ReadFile(filepath.Join(s.opt.DistDir, "install.sh"))
	if err != nil {
		return snap
	}
	listed := listedSums(filepath.Join(s.opt.DistDir, "SHA256SUMS"))
	entries, _ := os.ReadDir(s.opt.DistDir) // sorted by name
	var lines []string
	for _, e := range entries {
		name := e.Name()
		if !e.Type().IsRegular() || !tarballRe.MatchString(name) {
			continue
		}
		sum, err := fileSHA256(filepath.Join(s.opt.DistDir, name))
		if err != nil {
			s.log.Error("release file unreadable; installs of it will fail", "file", name, "error", err)
			continue
		}
		if want, ok := listed[name]; ok && want != sum {
			// One of the two was changed; installing either could install
			// the wrong thing, so pin neither and let installs fail.
			s.log.Error("release file does not match SHA256SUMS; installs of it will fail until the release is fixed", "file", name)
			continue
		}
		lines = append(lines, sum+"  "+name)
	}
	snap.script = pinSums(raw, lines)
	h := sha256.Sum256(snap.script)
	snap.sum = hex.EncodeToString(h[:])
	snap.tokenStdin = bytes.Contains(raw, []byte("--token-file"))
	snap.hubMaxMode = bytes.Contains(raw, []byte("--hub-max-mode"))
	if len(lines) == 0 {
		s.log.Warn("no agent tarballs to pin in install.sh", "dist", s.opt.DistDir)
	}
	return snap
}

// pinSums puts the sums into the script as a shell variable, right after
// its leading comment block (which its --help prints by line number).
func pinSums(script []byte, lines []string) []byte {
	assign := fmt.Sprintf("# Pinned by the kodeblue hub that served this script: the agent tarballs' sha256.\n%s='%s'\n", distSumsVar, strings.Join(lines, "\n"))
	i := 0
	for i < len(script) && script[i] == '#' {
		nl := bytes.IndexByte(script[i:], '\n')
		if nl < 0 {
			i = len(script)
			break
		}
		i += nl + 1
	}
	out := make([]byte, 0, len(script)+len(assign)+1)
	out = append(out, script[:i]...)
	if i > 0 && script[i-1] != '\n' {
		out = append(out, '\n')
	}
	out = append(out, assign...)
	return append(out, script[i:]...)
}

// shq quotes s for a POSIX shell.
func shq(s string) string {
	if s != "" && strings.IndexFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_./:@%+=,", r))
	}) < 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
