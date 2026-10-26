// Package upgrade installs a published kodeblue release on this server.
//
// An upgrade is always started by a person: a hub operator clicking Update
// (which reaches the server as a command, waits until no learning or agent
// session runs, and goes through the root helper), or root running
// `kodeblue upgrade <version>`. Nothing upgrades on its own.
//
// The hub only names a version. The release itself comes from the release
// URL in the server's root-owned config (GitHub by default) and must match
// that release's SHA256SUMS, so a hub, or a kodeblue user, that was taken
// over can at most start the install of a newer genuine release. Downgrades
// and reinstalls of the running version are refused.
package upgrade

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// DefaultReleaseURL holds one directory per release tag (…/v0.1.7/).
const DefaultReleaseURL = "https://github.com/Problem99-io/kodeblue/releases/download"

// StatusFile, in the state directory, is what the daemon reports to the hub.
// The daemon writes it while it waits and when it hands over; the root side
// writes it while installing and when it fails.
const StatusFile = "upgrade.json"

// Unit is the transient systemd unit an upgrade runs in, so the install
// outlives the kodeblue service it restarts: journalctl -u kodeblue-upgrade.
const Unit = "kodeblue-upgrade"

// States of an upgrade.
const (
	Waiting    = "waiting"    // asked for; starts once no learning or agent session runs
	Installing = "installing" // handed to the root helper
	Done       = "done"       // the server runs the version asked for
	Failed     = "failed"
)

// InstallTimeout is how long an install may take before the daemon reports
// it as failed (the install restarts the daemon when it succeeds).
const InstallTimeout = 20 * time.Minute

// Status is one upgrade's progress.
type Status struct {
	To     string    `json:"to"`
	From   string    `json:"from,omitempty"`
	State  string    `json:"state"`
	Detail string    `json:"detail,omitempty"`
	By     string    `json:"by,omitempty"`
	At     time.Time `json:"at"`
}

var versionRe = regexp.MustCompile(`^v(\d{1,4})\.(\d{1,4})\.(\d{1,4})$`)

// Valid reports whether v names a release (v1.2.3).
func Valid(v string) bool { return versionRe.MatchString(v) }

func parse(v string) ([3]int, bool) {
	var out [3]int
	// A build from a commit after a tag (v0.1.6-3-gabc, git describe) is
	// that release plus changes: compare it as the release.
	if i := strings.IndexByte(v, '-'); i > 0 {
		v = v[:i]
	}
	m := versionRe.FindStringSubmatch(v)
	if m == nil {
		return out, false
	}
	for i := range out {
		out[i], _ = strconv.Atoi(m[i+1])
	}
	return out, true
}

// Newer reports whether release to is newer than the running version from.
// A development build ("dev") is never upgraded from the hub.
func Newer(to, from string) bool {
	t, ok := parse(to)
	if !ok || !Valid(to) {
		return false
	}
	f, ok := parse(from)
	if !ok {
		return false
	}
	for i := range t {
		if t[i] != f[i] {
			return t[i] > f[i]
		}
	}
	return false
}

// Check says why a server running from may not upgrade to to, or nil.
func Check(to, from string) error {
	switch {
	case !Valid(to):
		return fmt.Errorf("%q is not a release version (v1.2.3)", to)
	case to == from:
		return fmt.Errorf("this server already runs %s", to)
	case !Newer(to, from):
		if _, ok := parse(from); !ok {
			return fmt.Errorf("this server runs a development build (%s); upgrade it on the server", from)
		}
		return fmt.Errorf("%s is older than %s, which this server runs; downgrades are refused", to, from)
	}
	return nil
}

// Read returns the upgrade in dir's status file, or nil.
func Read(dir string) *Status {
	b, err := os.ReadFile(filepath.Join(dir, StatusFile))
	if err != nil {
		return nil
	}
	var s Status
	if json.Unmarshal(b, &s) != nil || s.To == "" {
		return nil
	}
	return &s
}

// Write replaces dir's status file. uid >= 0 hands the file to that user
// (root writes it for the kodeblue user, who reads and rewrites it).
func Write(dir string, s Status, uid int) error {
	b, _ := json.Marshal(s)
	tmp := filepath.Join(dir, StatusFile+".tmp")
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	if uid >= 0 {
		_ = os.Chown(tmp, uid, -1)
	}
	return os.Rename(tmp, filepath.Join(dir, StatusFile))
}

// Options for Apply.
type Options struct {
	ReleaseURL string // directory of release directories (DefaultReleaseURL)
	Version    string // the release to install
	Running    string // the version running now
	Arch       string // default runtime.GOARCH
	StateDir   string // where the status file lives
	StatusUID  int    // owner for the status file (-1: leave it)
	By         string // who asked
	Client     *http.Client
	// Install runs the unpacked release's installer; default runs
	// sh <dir>/kodeblue/deploy/install.sh.
	Install func(ctx context.Context, dir string) error
	Log     io.Writer
}

// Apply downloads the release, checks it against the release's SHA256SUMS,
// unpacks it and runs its installer, which swaps the binaries and units and
// restarts kodeblue (an upgrade keeps the config, keys and state). It must
// run as root. Progress and failure go to the status file.
func Apply(ctx context.Context, o Options) (err error) {
	if o.Arch == "" {
		o.Arch = runtime.GOARCH
	}
	if o.ReleaseURL == "" {
		o.ReleaseURL = DefaultReleaseURL
	}
	if o.Client == nil {
		o.Client = &http.Client{Timeout: 10 * time.Minute}
	}
	if o.Log == nil {
		o.Log = io.Discard
	}
	if o.Install == nil {
		o.Install = RunInstaller(o.Log)
	}
	st := Status{To: o.Version, From: o.Running, State: Installing, By: o.By, At: time.Now().UTC()}
	step := func(detail string) {
		st.Detail, st.At = detail, time.Now().UTC()
		fmt.Fprintln(o.Log, detail)
		if o.StateDir != "" {
			_ = Write(o.StateDir, st, o.StatusUID)
		}
	}
	defer func() {
		if err != nil {
			st.State = Failed
			step(err.Error())
		}
	}()
	if err := Check(o.Version, o.Running); err != nil {
		return err
	}
	base, err := releaseBase(o.ReleaseURL, o.Version)
	if err != nil {
		return err
	}
	tmp, err := os.MkdirTemp("", "kodeblue-upgrade-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	name := "kodeblue-linux-" + o.Arch + ".tar.gz"
	step(fmt.Sprintf("downloading %s from %s", name, base))
	tarball, err := Download(ctx, o.Client, base, name, tmp)
	if err != nil {
		return err
	}
	if err := Extract(tarball, tmp); err != nil {
		return fmt.Errorf("unpacking %s: %w", name, err)
	}
	step(fmt.Sprintf("installing %s (checked against the release's SHA256SUMS)", o.Version))
	if err := o.Install(ctx, tmp); err != nil {
		return fmt.Errorf("the %s installer failed: %w (journalctl -u %s)", o.Version, err, Unit)
	}
	return nil
}

// releaseBase is the release's directory: https only, except to this host.
func releaseBase(raw, version string) (string, error) {
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(raw), "/"))
	if err != nil || u.Host == "" || u.User != nil {
		return "", fmt.Errorf("release_url %q is not a valid URL", raw)
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || !((ip != nil && ip.IsLoopback()) || u.Hostname() == "localhost") {
			return "", errors.New("release_url must be https:// (plain http only to localhost)")
		}
	}
	u.Path = path.Join(u.Path, version)
	return u.String(), nil
}

// Size bounds for what a release server can send.
const (
	maxSums    = 64 << 10
	maxTarball = 512 << 20
)

// Download fetches base/SHA256SUMS and base/name into dir and checks the
// file against its listed hash. Redirects keep to the base's scheme (GitHub
// redirects downloads to its CDN).
func Download(ctx context.Context, c *http.Client, base, name, dir string) (string, error) {
	scheme := strings.SplitN(base, ":", 2)[0]
	cc := *c
	cc.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("too many redirects")
		}
		if r.URL.Scheme != scheme {
			return fmt.Errorf("redirect to %s refused", r.URL.Scheme)
		}
		return nil
	}
	get := func(file string, limit int64, w io.Writer) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/"+file, nil)
		if err != nil {
			return err
		}
		resp, err := cc.Do(req)
		if err != nil {
			return fmt.Errorf("download of %s: %w", file, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("download of %s: HTTP %d (is %s a published release?)", file, resp.StatusCode, path.Base(base))
		}
		n, err := io.Copy(w, io.LimitReader(resp.Body, limit+1))
		if err != nil {
			return fmt.Errorf("download of %s: %w", file, err)
		}
		if n > limit {
			return fmt.Errorf("download of %s: larger than %d bytes", file, limit)
		}
		return nil
	}
	var sums strings.Builder
	if err := get("SHA256SUMS", maxSums, &sums); err != nil {
		return "", err
	}
	want := ""
	for _, line := range strings.Split(sums.String(), "\n") {
		if f := strings.Fields(line); len(f) == 2 && strings.TrimPrefix(f[1], "*") == name {
			want = strings.ToLower(f[0])
		}
	}
	if len(want) != 64 {
		return "", fmt.Errorf("the release's SHA256SUMS does not list %s", name)
	}
	dst := filepath.Join(dir, name)
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	err = get(name, maxTarball, io.MultiWriter(f, h))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return "", fmt.Errorf("%s does not match the release's SHA256SUMS (got %s, want %s)", name, got, want)
	}
	return dst, nil
}

// Extract unpacks a release tarball into dir: only regular files and
// directories under kodeblue/, nothing that leaves dir.
func Extract(tarball, dir string) error {
	f, err := os.Open(tarball)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	var total int64
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		name := path.Clean(h.Name)
		if name != "kodeblue" && !strings.HasPrefix(name, "kodeblue/") {
			return fmt.Errorf("unexpected entry %q", h.Name)
		}
		dst := filepath.Join(dir, filepath.FromSlash(name))
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(dst, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			total += h.Size
			if total > maxTarball*2 {
				return errors.New("release unpacks too large")
			}
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
				return err
			}
			out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, os.FileMode(h.Mode)&0o755)
			if err != nil {
				return err
			}
			_, err = io.Copy(out, io.LimitReader(tr, h.Size))
			if cerr := out.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("unexpected entry type in %q", h.Name)
		}
	}
	for _, need := range []string{"kodeblue/kodeblue", "kodeblue/kodeblue-engine", "kodeblue/deploy/install.sh"} {
		if _, err := os.Stat(filepath.Join(dir, need)); err != nil {
			return fmt.Errorf("the release has no %s", need)
		}
	}
	return nil
}

// RunInstaller runs the release's own install.sh, which upgrades a server
// already set up: it keeps the config, keys and state, opens a maintenance
// window for the binary swap and restarts kodeblue. With no terminal it asks
// nothing.
func RunInstaller(log io.Writer) func(ctx context.Context, dir string) error {
	return func(ctx context.Context, dir string) error {
		cmd := exec.CommandContext(ctx, "/bin/sh", filepath.Join(dir, "kodeblue", "deploy", "install.sh"))
		cmd.Env = append(os.Environ(), "KODEBLUE_UNPACKED=1")
		cmd.Stdout, cmd.Stderr = log, log
		return cmd.Run()
	}
}
