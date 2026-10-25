package sensors

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// PackageIndex answers "which package owns this file" and "does this file
// still match what the package shipped". That second question is the single
// biggest false-positive killer: a changed /usr/bin/sudo that matches the
// package manager's own checksum is an upgrade, not a rootkit.
type PackageIndex struct {
	mu        sync.Mutex
	kind      string // dpkg | apk | rpm | none
	loadedAt  time.Time
	stamp     time.Time
	installed map[string]string
	owners    map[string]string // path -> package
	sums      map[string]string // path -> checksum ("md5:<hex>" | "sha1b64:<b64>")
	sumsHash  map[string]string // package -> digest of its whole checksum list
}

// LoadPackageIndex detects the package manager and loads its database.
func LoadPackageIndex(env *Env) *PackageIndex {
	idx := &PackageIndex{}
	idx.reload(env)
	return idx
}

func (p *PackageIndex) dbPath(env *Env) string {
	switch p.kind {
	case "dpkg":
		return env.Path("/var/lib/dpkg/status")
	case "apk":
		return env.Path("/lib/apk/db/installed")
	case "rpm":
		return env.Path("/var/lib/rpm")
	}
	return ""
}

// Refresh reloads the index if the package database changed since last load.
func (p *PackageIndex) Refresh(env *Env) {
	if p == nil {
		return
	}
	p.mu.Lock()
	stamp, ok := p.dbStamp(env)
	changed := ok && stamp.After(p.stamp)
	p.mu.Unlock()
	if changed {
		p.reload(env)
	}
}

// dbStamp is the newest modification time of the package database. For dpkg
// that includes the info directory, so a checksum list rewritten in place of
// the original (sed -i, an editor's save) is reloaded — and its digest change
// seen — without waiting for the next apt run.
func (p *PackageIndex) dbStamp(env *Env) (time.Time, bool) {
	path := p.dbPath(env)
	if path == "" {
		return time.Time{}, false
	}
	st, err := os.Stat(path)
	if err != nil {
		return time.Time{}, false
	}
	t := st.ModTime()
	if p.kind == "dpkg" {
		if di, err := os.Stat(env.Path("/var/lib/dpkg/info")); err == nil && di.ModTime().After(t) {
			t = di.ModTime()
		}
	}
	return t, true
}

func (p *PackageIndex) reload(env *Env) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.installed, p.owners, p.sums, p.sumsHash = map[string]string{}, map[string]string{}, map[string]string{}, map[string]string{}
	p.loadedAt = time.Now()
	switch {
	case exists(env.Path("/var/lib/dpkg/status")):
		p.kind = "dpkg"
		p.loadDpkg(env)
	case exists(env.Path("/lib/apk/db/installed")):
		p.kind = "apk"
		p.loadApk(env)
	case exists(env.Path("/var/lib/rpm")):
		p.kind = "rpm"
		p.loadRpm()
	default:
		p.kind = "none"
	}
	if t, ok := p.dbStamp(env); ok {
		p.stamp = t
	}
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func (p *PackageIndex) loadDpkg(env *Env) {
	f, err := os.Open(env.Path("/var/lib/dpkg/status"))
	if err != nil {
		return
	}
	var name, ver, status string
	flush := func() {
		// "installed" is the steady state, but mid-transaction states
		// (unpacked, half-configured, half-installed, triggers-*) also have
		// the package's files and its new version on disk. Treating them as
		// "" would make a genuine apt run look like tampering for the minutes
		// before it finishes. "not-installed" / "config-files" have no files.
		if name != "" && ver != "" && pkgStatePresent(status) {
			p.installed[name] = ver
		}
		name, ver, status = "", "", ""
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			flush()
		case strings.HasPrefix(line, "Package: "):
			name = strings.TrimPrefix(line, "Package: ")
		case strings.HasPrefix(line, "Version: "):
			ver = strings.TrimPrefix(line, "Version: ")
		case strings.HasPrefix(line, "Status: "):
			status = strings.TrimPrefix(line, "Status: ")
		}
	}
	flush()
	f.Close()
	info := env.Path("/var/lib/dpkg/info")
	lists, _ := filepath.Glob(filepath.Join(info, "*.list"))
	for _, l := range lists {
		pkg := strings.SplitN(strings.TrimSuffix(filepath.Base(l), ".list"), ":", 2)[0]
		b, err := os.ReadFile(l)
		if err != nil {
			continue
		}
		for _, path := range strings.Split(string(b), "\n") {
			if path != "" && path != "/." {
				p.owners[path] = pkg
			}
		}
	}
	sums, _ := filepath.Glob(filepath.Join(info, "*.md5sums"))
	for _, s := range sums {
		b, err := os.ReadFile(s)
		if err != nil {
			continue
		}
		pkg := strings.SplitN(strings.TrimSuffix(filepath.Base(s), ".md5sums"), ":", 2)[0]
		p.sumsHash[pkg] = short(hashString(p.sumsHash[pkg] + string(b)))
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) == 2 {
				p.sums["/"+f[1]] = "md5:" + f[0]
			}
		}
	}
}

func (p *PackageIndex) loadApk(env *Env) {
	f, err := os.Open(env.Path("/lib/apk/db/installed"))
	if err != nil {
		return
	}
	defer f.Close()
	var pkg, dir, file string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if len(line) < 2 || line[1] != ':' {
			if line == "" {
				pkg, dir, file = "", "", ""
			}
			continue
		}
		v := line[2:]
		switch line[0] {
		case 'P':
			pkg = v
		case 'V':
			p.installed[pkg] = v
		case 'F':
			dir = "/" + v
		case 'R':
			file = filepath.Join(dir, v)
			p.owners[file] = pkg
		case 'Z':
			if file != "" && strings.HasPrefix(v, "Q1") {
				p.sums[file] = "sha1b64:" + v[2:]
				p.sumsHash[pkg] = short(hashString(p.sumsHash[pkg] + file + " " + v))
			}
		}
	}
}

func (p *PackageIndex) loadRpm() {
	out, err := exec.Command("rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n").Output()
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.SplitN(line, "\t", 2)
		if len(f) == 2 {
			p.installed[f[0]] = f[1]
		}
	}
}

// Kind returns dpkg, apk, rpm or none.
func (p *PackageIndex) Kind() string {
	if p == nil {
		return "none"
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.kind
}

// Installed returns a copy of the installed package map.
func (p *PackageIndex) Installed() map[string]string {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[string]string, len(p.installed))
	for k, v := range p.installed {
		out[k] = v
	}
	return out
}

// Version returns the installed version of pkg, or "" when it is not (fully)
// installed.
func (p *PackageIndex) Version(pkg string) string {
	if p == nil || pkg == "" {
		return ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.installed[pkg]
}

// SumsDigest returns a digest of pkg's whole checksum list, or "" when the
// package manager keeps none for it.
func (p *PackageIndex) SumsDigest(pkg string) string {
	if p == nil {
		return ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sumsHash[pkg]
}

// Owner returns the package that installed path, or "".
func (p *PackageIndex) Owner(path string) string {
	if p == nil || path == "" {
		return ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if o := p.owners[path]; o != "" {
		return o
	}
	// /bin -> /usr/bin merged-usr systems list the unmerged path.
	if strings.HasPrefix(path, "/usr/") {
		return p.owners[strings.TrimPrefix(path, "/usr")]
	}
	return p.owners["/usr"+path]
}

// HasSums reports whether the package manager shipped a checksum for path.
func (p *PackageIndex) HasSums(path string) bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.lookupSum(path)
	return ok
}

func (p *PackageIndex) lookupSum(path string) (string, bool) {
	if s, ok := p.sums[path]; ok {
		return s, true
	}
	if strings.HasPrefix(path, "/usr/") {
		s, ok := p.sums[strings.TrimPrefix(path, "/usr")]
		return s, ok
	}
	s, ok := p.sums["/usr"+path]
	return s, ok
}

// Verify reports whether the file on disk matches the package checksum.
func (p *PackageIndex) Verify(env *Env, path string) bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	want, ok := p.lookupSum(path)
	p.mu.Unlock()
	if !ok {
		return false
	}
	f, err := os.Open(env.Path(path))
	if err != nil {
		return false
	}
	defer f.Close()
	switch {
	case strings.HasPrefix(want, "md5:"):
		h := md5.New()
		_, _ = io.Copy(h, f)
		return hex.EncodeToString(h.Sum(nil)) == strings.TrimPrefix(want, "md5:")
	case strings.HasPrefix(want, "sha1b64:"):
		h := sha1.New()
		_, _ = io.Copy(h, f)
		return base64.StdEncoding.EncodeToString(h.Sum(nil)) == strings.TrimPrefix(want, "sha1b64:")
	}
	return false
}

// RecentActivity reports package-manager activity since t (dpkg/apt logs),
// returning the touched package names. Used to explain file changes.
func (p *PackageIndex) RecentActivity(env *Env, since time.Time) []string {
	var out []string
	for _, log := range []string{"/var/log/dpkg.log", "/var/log/apk.log", "/var/log/dnf.rpm.log", "/var/log/yum.log"} {
		b, err := os.ReadFile(env.Path(log))
		if err != nil {
			continue
		}
		lines := strings.Split(string(b), "\n")
		if len(lines) > 4000 {
			lines = lines[len(lines)-4000:]
		}
		for _, line := range lines {
			// dpkg: "2026-10-19 10:01:02 upgrade openssh-server:amd64 1:9.6 1:9.7"
			if len(line) < 20 {
				continue
			}
			ts, err := time.ParseInLocation("2006-01-02 15:04:05", line[:19], time.Local)
			if err != nil || ts.Before(since) {
				continue
			}
			f := strings.Fields(line[19:])
			if len(f) >= 2 && (f[0] == "install" || f[0] == "upgrade" || f[0] == "remove" || f[0] == "configure") {
				out = append(out, strings.SplitN(f[1], ":", 2)[0])
			}
		}
	}
	return out
}

func itoa(i int) string { return strconv.Itoa(i) }

func atoi(s string) (int, error) { return strconv.Atoi(s) }

// pkgStatePresent reports whether a dpkg "Status:" line ("<want> <eflag>
// <state>") means the package's files are on disk at the stated version.
func pkgStatePresent(status string) bool {
	f := strings.Fields(status)
	if len(f) == 0 {
		return false
	}
	switch f[len(f)-1] {
	case "installed", "unpacked", "half-configured", "half-installed", "triggers-awaited", "triggers-pending":
		return true
	}
	return false
}
