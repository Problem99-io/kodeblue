// Package versions reports how up to date the server is: the distribution
// and how long it is supported, the running kernel and whether a reboot is
// waiting, the package updates the package manager already knows about
// (security ones apart), and the container images that run. It reads local
// state only; refreshing the package lists is the system's own apt timer.
package versions

import (
	"bufio"
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Report is the server's software versions at one moment.
type Report struct {
	OS        string    `json:"os"` // PRETTY_NAME
	ID        string    `json:"id"`
	VersionID string    `json:"version_id"`
	Codename  string    `json:"codename,omitempty"`
	EOL       time.Time `json:"eol,omitzero"` // end of standard support
	ESM       time.Time `json:"esm,omitzero"` // end of extended (paid) support, Ubuntu only

	Kernel         string   `json:"kernel"`
	RebootRequired bool     `json:"reboot_required,omitempty"`
	RebootFor      []string `json:"reboot_for,omitempty"`

	// PackageManager is apt when updates could be listed.
	PackageManager string    `json:"package_manager,omitempty"`
	Updates        []Update  `json:"updates,omitempty"`
	ListsUpdated   time.Time `json:"lists_updated,omitzero"`
	UpdatesErr     string    `json:"updates_error,omitempty"`

	Images []string `json:"images,omitempty"`
}

// Update is a package with a newer version available.
type Update struct {
	Package  string `json:"package"`
	From     string `json:"from"`
	To       string `json:"to"`
	Source   string `json:"source"` // e.g. noble-security
	Security bool   `json:"security"`
}

// Env says where to read; Root "" or "/" is this host.
type Env struct {
	Root string
	// Run runs a command and returns its output (tests replace it).
	Run func(ctx context.Context, argv ...string) ([]byte, error)
}

func (e Env) path(p string) string {
	if e.Root == "" || e.Root == "/" {
		return p
	}
	return filepath.Join(e.Root, p)
}

func (e Env) run(ctx context.Context, argv ...string) ([]byte, error) {
	if e.Run != nil {
		return e.Run(ctx, argv...)
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	return cmd.Output()
}

// Take reads the versions. images are the running containers' images.
func Take(ctx context.Context, e Env, images []string) Report {
	var r Report
	if b, err := os.ReadFile(e.path("/etc/os-release")); err == nil {
		kv := ParseOSRelease(string(b))
		r.OS, r.ID, r.VersionID = kv["PRETTY_NAME"], kv["ID"], kv["VERSION_ID"]
		r.Codename = kv["VERSION_CODENAME"]
		if r.Codename == "" {
			r.Codename = kv["UBUNTU_CODENAME"]
		}
	}
	if b, err := os.ReadFile(e.path("/usr/share/distro-info/" + r.ID + ".csv")); err == nil && r.ID != "" {
		r.EOL, r.ESM = SupportEnds(string(b), r.VersionID, r.Codename)
	}
	if b, err := os.ReadFile(e.path("/proc/sys/kernel/osrelease")); err == nil {
		r.Kernel = strings.TrimSpace(string(b))
	}
	if _, err := os.Stat(e.path("/var/run/reboot-required")); err == nil {
		r.RebootRequired = true
		if b, err := os.ReadFile(e.path("/var/run/reboot-required.pkgs")); err == nil {
			r.RebootFor = uniq(strings.Fields(string(b)))
		}
	}
	if _, err := os.Stat(e.path("/var/lib/dpkg/status")); err == nil {
		r.PackageManager = "apt"
		r.ListsUpdated = newestMtime(e.path("/var/lib/apt/lists"))
		if e.Root == "" || e.Root == "/" {
			out, err := e.run(ctx, "apt-get", "-s", "-q", "dist-upgrade")
			if err != nil && len(out) == 0 {
				r.UpdatesErr = err.Error()
			}
			r.Updates = ParseAptSimulation(string(out))
		} else {
			r.UpdatesErr = "not listed: the host is mounted at " + e.Root
		}
	}
	r.Images = append(r.Images, images...)
	sort.Strings(r.Images)
	return r
}

// ParseOSRelease reads KEY=value lines, unquoting values.
func ParseOSRelease(s string) map[string]string {
	kv := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok || strings.HasPrefix(k, "#") {
			continue
		}
		kv[k] = strings.Trim(v, `"'`)
	}
	return kv
}

// SupportEnds finds a release's end of support in distro-info-data's CSV
// (version,codename,series,created,release,eol[,eol-server][,eol-esm]…).
// For Ubuntu the server end (eol-server) wins over the desktop one when set.
func SupportEnds(csvText, versionID, codename string) (eol, esm time.Time) {
	rows, err := csv.NewReader(strings.NewReader(csvText)).ReadAll()
	if err != nil || len(rows) < 2 {
		return
	}
	col := map[string]int{}
	for i, h := range rows[0] {
		col[strings.TrimSpace(h)] = i
	}
	get := func(row []string, name string) time.Time {
		i, ok := col[name]
		if !ok || i >= len(row) {
			return time.Time{}
		}
		t, _ := time.Parse("2006-01-02", strings.TrimSpace(row[i]))
		return t
	}
	for _, row := range rows[1:] {
		v := strings.TrimSpace(row[col["version"]])
		series := ""
		if i, ok := col["series"]; ok && i < len(row) {
			series = strings.TrimSpace(row[i])
		}
		// Ubuntu versions read "24.04 LTS"; Debian's are "12".
		if f := strings.Fields(v); (len(f) == 0 || f[0] != versionID) && (codename == "" || series != codename) {
			continue
		}
		eol = get(row, "eol")
		if s := get(row, "eol-server"); !s.IsZero() {
			eol = s
		}
		esm = get(row, "eol-esm")
		return
	}
	return
}

// instRe reads apt-get -s lines: "Inst pkg [old] (new Origin:release/pocket [arch])".
// A package not installed yet has no [old].
var instRe = regexp.MustCompile(`^Inst (\S+) (?:\[([^\]]*)\] )?\((\S+) ([^\[)]*)`)

// ParseAptSimulation reads the packages an apt-get -s upgrade would install.
func ParseAptSimulation(out string) []Update {
	var l []Update
	for _, line := range strings.Split(out, "\n") {
		m := instRe.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		src := strings.TrimSpace(m[4])
		u := Update{Package: m[1], From: m[2], To: m[3], Source: src}
		for _, s := range strings.Split(src, ",") {
			if strings.Contains(s, "-security") || strings.Contains(s, "security.") || strings.Contains(strings.ToLower(s), "security:") {
				u.Security = true
			}
		}
		l = append(l, u)
	}
	return l
}

func newestMtime(dir string) time.Time {
	var newest time.Time
	ents, err := os.ReadDir(dir)
	if err != nil {
		return newest
	}
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), "Release") {
			continue
		}
		if i, err := e.Info(); err == nil && i.ModTime().After(newest) {
			newest = i.ModTime()
		}
	}
	return newest
}

func uniq(l []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range l {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// Security lists the security updates.
func (r Report) Security() []Update {
	var l []Update
	for _, u := range r.Updates {
		if u.Security {
			l = append(l, u)
		}
	}
	return l
}

// Text is the report for the reviewer's digest.
func (r Report) Text(now time.Time) string {
	var b strings.Builder
	name := r.OS
	if name == "" {
		name = "unknown (no /etc/os-release)"
	}
	fmt.Fprintf(&b, "- OS: %s", name)
	switch {
	case r.EOL.IsZero():
		b.WriteString("; support end not known locally (no distro-info data): judge it yourself")
	case now.After(r.EOL):
		fmt.Fprintf(&b, "; standard support ENDED %s", r.EOL.Format("2006-01-02"))
		if !r.ESM.IsZero() {
			fmt.Fprintf(&b, " (extended security maintenance, if subscribed, until %s)", r.ESM.Format("2006-01-02"))
		}
	default:
		fmt.Fprintf(&b, "; supported until %s (%d days)", r.EOL.Format("2006-01-02"), int(r.EOL.Sub(now).Hours()/24))
	}
	b.WriteString("\n")
	fmt.Fprintf(&b, "- Kernel running: %s", orDash(r.Kernel))
	if r.RebootRequired {
		fmt.Fprintf(&b, "; a REBOOT is pending to load updates (%s)", orDash(strings.Join(r.RebootFor, ", ")))
	}
	b.WriteString("\n")
	if r.PackageManager != "" {
		sec := r.Security()
		fmt.Fprintf(&b, "- Package updates available: %d, of which %d security", len(r.Updates), len(sec))
		if !r.ListsUpdated.IsZero() {
			age := now.Sub(r.ListsUpdated)
			fmt.Fprintf(&b, " (package lists refreshed %s ago", roundAge(age))
			if age > 3*24*time.Hour {
				b.WriteString(": STALE, so this may miss updates; the apt-daily timer may be off")
			}
			b.WriteString(")")
		}
		if r.UpdatesErr != "" {
			fmt.Fprintf(&b, "; listing failed: %s", r.UpdatesErr)
		}
		b.WriteString("\n")
		for i, u := range sec {
			if i >= 40 {
				fmt.Fprintf(&b, "  … %d more security updates\n", len(sec)-40)
				break
			}
			fmt.Fprintf(&b, "  - %s %s → %s (%s)\n", u.Package, orDash(u.From), u.To, u.Source)
		}
	}
	if len(r.Images) > 0 {
		fmt.Fprintf(&b, "- Container images running: %s\n", strings.Join(r.Images, ", "))
	}
	return b.String()
}

func roundAge(d time.Duration) string {
	switch {
	case d < time.Hour:
		return "under an hour"
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%d days", int(d.Hours()/24))
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
