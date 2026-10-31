package upgrade

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBehind(t *testing.T) {
	for _, tc := range []struct {
		have, want string
		behind     bool
	}{
		{"v0.2.0", "v0.3.0", true},
		{"v0.2.9", "v0.2.10", true},
		{"v0.3.0", "v0.3.0", false},
		{"v0.3.0-4-gabc", "v0.3.0", false},
		{"v0.3.1", "v0.3.0", false},
		{"v1.0.0", "v0.9.9", false},
		{"dev", "v0.3.0", false},
		{"v0.2.0", "dev", false},
		{"", "v0.3.0", false},
	} {
		if got := Behind(tc.have, tc.want); got != tc.behind {
			t.Errorf("Behind(%q, %q) = %t", tc.have, tc.want, got)
		}
	}
}

func TestCheck(t *testing.T) {
	for _, c := range []struct {
		to, from string
		ok       bool
	}{
		{"v0.1.7", "v0.1.6", true},
		{"v0.2.0", "v0.1.16", true},
		{"v1.0.0", "v0.9.9", true},
		{"v0.1.7", "v0.1.6-3-gabc123", true}, // a build after the v0.1.6 tag
		{"v0.1.6", "v0.1.6", false},
		{"v0.1.5", "v0.1.6", false}, // downgrade
		{"v0.1.10", "v0.1.9", true},
		{"v0.1.9", "v0.1.10", false},
		{"v0.1.7", "dev", false},
		{"0.1.7", "v0.1.6", false},
		{"v0.1.7-rc1", "v0.1.6", false},
		{"v0.1.7; rm -rf /", "v0.1.6", false},
		{"../v0.1.7", "v0.1.6", false},
	} {
		if err := Check(c.to, c.from); (err == nil) != c.ok {
			t.Errorf("Check(%q, %q) = %v, want ok=%v", c.to, c.from, err, c.ok)
		}
	}
}

// release builds a release tarball: name -> content (mode 0755 for binaries).
func release(t *testing.T, files map[string]string, extra func(*tar.Writer)) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	_ = tw.WriteHeader(&tar.Header{Name: "kodeblue/", Typeflag: tar.TypeDir, Mode: 0o755})
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o755, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		_, _ = tw.Write([]byte(body))
	}
	if extra != nil {
		extra(tw)
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

var goodFiles = map[string]string{"kodeblue/kodeblue": "bin", "kodeblue/kodeblue-engine": "engine", "kodeblue/deploy/install.sh": "#!/bin/sh\n"}

// releases serves base/<version>/{SHA256SUMS, kodeblue-linux-amd64.tar.gz}.
func releases(t *testing.T, version string, tarball []byte, sum string) *httptest.Server {
	t.Helper()
	if sum == "" {
		h := sha256.Sum256(tarball)
		sum = hex.EncodeToString(h[:])
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rel/" + version + "/SHA256SUMS":
			_, _ = w.Write([]byte("0000000000000000000000000000000000000000000000000000000000000000  install.sh\n" + sum + "  kodeblue-linux-amd64.tar.gz\n"))
		case "/rel/" + version + "/kodeblue-linux-amd64.tar.gz":
			_, _ = w.Write(tarball)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestApplyInstallsAVerifiedRelease(t *testing.T) {
	srv := releases(t, "v0.1.7", release(t, goodFiles, nil), "")
	state := t.TempDir()
	var ran string
	err := Apply(context.Background(), Options{ReleaseURL: srv.URL + "/rel/", Version: "v0.1.7", Running: "v0.1.6", Arch: "amd64",
		StateDir: state, StatusUID: -1, By: "hub:alice",
		Install: func(_ context.Context, dir string) error {
			b, err := os.ReadFile(filepath.Join(dir, "kodeblue", "deploy", "install.sh"))
			ran = string(b)
			if s := Read(state); s == nil || s.State != Installing || !strings.Contains(s.Detail, "SHA256SUMS") {
				t.Errorf("status while installing: %+v", s)
			}
			return err
		}})
	if err != nil || ran != "#!/bin/sh\n" {
		t.Fatalf("apply: %v, installer %q", err, ran)
	}
	if s := Read(state); s.To != "v0.1.7" || s.From != "v0.1.6" || s.By != "hub:alice" {
		t.Errorf("status: %+v", s)
	}
}

func TestApplyRefusesWhatDoesNotCheckOut(t *testing.T) {
	good := release(t, goodFiles, nil)
	installed := false
	install := func(context.Context, string) error { installed = true; return nil }
	apply := func(srv *httptest.Server, version, running string) error {
		state := t.TempDir()
		err := Apply(context.Background(), Options{ReleaseURL: srv.URL + "/rel", Version: version, Running: running, Arch: "amd64", StateDir: state, StatusUID: -1, Install: install})
		if err != nil {
			if s := Read(state); s != nil && s.State != Failed {
				t.Errorf("a failure must be recorded: %+v", s)
			}
		}
		return err
	}
	// A tarball that is not the one SHA256SUMS lists.
	if err := apply(releases(t, "v0.1.7", good, strings.Repeat("ab", 32)), "v0.1.7", "v0.1.6"); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Errorf("checksum mismatch: %v", err)
	}
	// No such release.
	if err := apply(releases(t, "v0.1.7", good, ""), "v0.1.8", "v0.1.6"); err == nil || !strings.Contains(err.Error(), "HTTP 404") {
		t.Errorf("missing release: %v", err)
	}
	// Downgrade, and the running version again.
	if err := apply(releases(t, "v0.1.5", good, ""), "v0.1.5", "v0.1.6"); err == nil || !strings.Contains(err.Error(), "downgrade") {
		t.Errorf("downgrade: %v", err)
	}
	// Entries that leave the release directory, or are links.
	evil := release(t, goodFiles, func(tw *tar.Writer) {
		_ = tw.WriteHeader(&tar.Header{Name: "kodeblue/../../etc/cron.d/x", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1})
		_, _ = tw.Write([]byte("x"))
	})
	if err := apply(releases(t, "v0.1.7", evil, ""), "v0.1.7", "v0.1.6"); err == nil || !strings.Contains(err.Error(), "unexpected entry") {
		t.Errorf("path traversal: %v", err)
	}
	link := release(t, goodFiles, func(tw *tar.Writer) {
		_ = tw.WriteHeader(&tar.Header{Name: "kodeblue/lib", Typeflag: tar.TypeSymlink, Linkname: "/etc", Mode: 0o777})
	})
	if err := apply(releases(t, "v0.1.7", link, ""), "v0.1.7", "v0.1.6"); err == nil || !strings.Contains(err.Error(), "entry type") {
		t.Errorf("symlink: %v", err)
	}
	incomplete := release(t, map[string]string{"kodeblue/kodeblue": "bin"}, nil)
	if err := apply(releases(t, "v0.1.7", incomplete, ""), "v0.1.7", "v0.1.6"); err == nil || !strings.Contains(err.Error(), "has no") {
		t.Errorf("incomplete release: %v", err)
	}
	if installed {
		t.Error("an installer ran for a release that did not check out")
	}
	// Plain http is for this host only.
	if err := Apply(context.Background(), Options{ReleaseURL: "http://releases.example.com", Version: "v0.1.7", Running: "v0.1.6", Install: install}); err == nil || !strings.Contains(err.Error(), "https") {
		t.Errorf("plain http: %v", err)
	}
}

func TestDownloadKeepsToTheScheme(t *testing.T) {
	// An https release server may not redirect to plain http (a CDN may
	// redirect within https).
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("x")) }))
	defer target.Close()
	tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusFound)
	}))
	defer tls.Close()
	_, err := Download(context.Background(), tls.Client(), tls.URL+"/v0.1.7", "kodeblue-linux-amd64.tar.gz", t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "redirect to http refused") {
		t.Errorf("downgrade redirect: %v", err)
	}
}

func TestInstallerFailureIsReported(t *testing.T) {
	srv := releases(t, "v0.1.7", release(t, goodFiles, nil), "")
	state := t.TempDir()
	err := Apply(context.Background(), Options{ReleaseURL: srv.URL + "/rel", Version: "v0.1.7", Running: "v0.1.6", Arch: "amd64", StateDir: state, StatusUID: -1,
		Install: func(context.Context, string) error { return errors.New("exit status 1") }})
	if err == nil {
		t.Fatal("installer failure not returned")
	}
	if s := Read(state); s.State != Failed || !strings.Contains(s.Detail, "journalctl -u kodeblue-upgrade") {
		t.Errorf("status: %+v", s)
	}
}
