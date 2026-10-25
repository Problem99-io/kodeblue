package sensors

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// persistenceCollector hashes every place an attacker can make something run
// again later: cron, systemd units, init scripts, shell profiles, the dynamic
// loader preload list, PAM, udev and MOTD hooks.
type persistenceCollector struct{}

func (persistenceCollector) Name() string { return "persistence" }
func (persistenceCollector) Every() int   { return 1 }

var persistenceGlobs = []string{
	"/etc/crontab", "/etc/cron.d/*", "/etc/cron.hourly/*", "/etc/cron.daily/*", "/etc/cron.weekly/*", "/etc/cron.monthly/*",
	"/var/spool/cron/*", "/var/spool/cron/crontabs/*", "/etc/anacrontab",
	"/etc/systemd/system/*", "/etc/systemd/system/*/*", "/etc/systemd/user/*", "/usr/lib/systemd/system/*.service", "/lib/systemd/system/*.service",
	"/etc/rc.local", "/etc/init.d/*",
	"/etc/profile", "/etc/profile.d/*", "/etc/bash.bashrc", "/etc/environment",
	"/root/.bashrc", "/root/.profile", "/root/.bash_profile", "/root/.ssh/rc", "/etc/ssh/sshrc",
	"/etc/ld.so.preload", "/etc/ld.so.conf", "/etc/ld.so.conf.d/*",
	"/etc/pam.d/*", "/etc/security/*.conf",
	"/etc/udev/rules.d/*", "/etc/update-motd.d/*",
	"/etc/modules", "/etc/modules-load.d/*", "/etc/modprobe.d/*",
	"/etc/hosts", "/etc/resolv.conf", "/etc/nsswitch.conf",
}

func (persistenceCollector) Collect(ctx context.Context, env *Env) ([]Item, []Event, error) {
	paths := globFiles(env, persistenceGlobs...)
	for _, p := range readPasswd(env) {
		if p.Home == "" || p.Home == "/" || !loginShell(p.Shell) {
			continue
		}
		paths = append(paths, globFiles(env,
			filepath.Join(p.Home, ".bashrc"), filepath.Join(p.Home, ".profile"), filepath.Join(p.Home, ".bash_profile"),
			filepath.Join(p.Home, ".config/systemd/user/*"), filepath.Join(p.Home, ".config/autostart/*"))...)
	}
	items := make([]Item, 0, len(paths))
	for _, path := range paths {
		attrs := map[string]string{}
		if pkg := env.Pkg.Owner(path); pkg != "" {
			attrs["package"] = pkg
			if env.Pkg.Verify(env, path) {
				attrs["package_verified"] = "true"
			}
		}
		items = append(items, Item{Key: path, Value: short(hashFile(env.Path(path))), Attrs: attrs})
	}
	return items, nil, nil
}

// integrityCollector hashes binaries attackers like to trojan, plus any extra
// files configured or added by the learner.
type integrityCollector struct{ extra []string }

func (integrityCollector) Name() string { return "integrity" }
func (integrityCollector) Every() int   { return 1 }

var integrityTargets = []string{
	"sshd", "sudo", "su", "login", "passwd", "ps", "ls", "netstat", "ss", "top", "find", "lsof", "bash", "sh", "dash",
	"crontab", "systemctl", "useradd", "usermod", "chattr", "id", "who", "w", "last", "curl", "wget", "openssl",
}

func (c integrityCollector) Collect(ctx context.Context, env *Env) ([]Item, []Event, error) {
	seen := map[string]bool{}
	var paths []string
	for _, name := range integrityTargets {
		for _, dir := range []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
			p := filepath.Join(dir, name)
			real, err := filepath.EvalSymlinks(env.Path(p))
			if err != nil {
				continue
			}
			if env.Root != "" && env.Root != "/" {
				real = "/" + strings.TrimPrefix(strings.TrimPrefix(real, env.Root), "/")
			}
			if !seen[real] {
				seen[real] = true
				paths = append(paths, real)
			}
		}
	}
	paths = append(paths, globFiles(env, c.extra...)...)
	var items []Item
	for _, p := range paths {
		attrs := map[string]string{}
		if pkg := env.Pkg.Owner(p); pkg != "" {
			attrs["package"] = pkg
			if env.Pkg.Verify(env, p) {
				attrs["package_verified"] = "true"
			} else if env.Pkg.HasSums(p) {
				attrs["package_verified"] = "false"
			}
		}
		items = append(items, Item{Key: p, Value: short(hashFile(env.Path(p))), Attrs: attrs})
	}
	return items, nil, nil
}

// suidCollector walks the filesystem for setuid/setgid files. It is the most
// expensive collector, so it runs every few sweeps.
type suidCollector struct{}

func (suidCollector) Name() string { return "suid" }
func (suidCollector) Every() int   { return 10 }

var skipWalk = map[string]bool{"/proc": true, "/sys": true, "/dev": true, "/run": true, "/var/lib/docker": true, "/var/lib/containerd": true, "/snap": true, "/nix": true, "/var/lib/kodeblue": true}

// suidRoots are walked in order of where a planted setuid file is most
// likely, so a walk cut short by the timeout has covered those first. A root
// nested in an earlier one (/var/tmp in /var) is walked only once.
var suidRoots = []string{"/tmp", "/var/tmp", "/dev/shm", "/home", "/root", "/etc", "/opt", "/srv", "/usr/local", "/var", "/bin", "/sbin", "/usr", "/lib"}

func (suidCollector) Collect(ctx context.Context, env *Env) ([]Item, []Event, error) {
	return walkSUID(ctx, env, suidRoots)
}

func walkSUID(ctx context.Context, env *Env, roots []string) ([]Item, []Event, error) {
	var items []Item
	var truncated []string
	walked := map[string]bool{}
	// Give each not-yet-walked root an equal slice of the remaining time, so a
	// single huge world-writable root (a packed /tmp) cannot burn the whole
	// budget before the walk reaches system roots. A root that overruns its
	// slice is cut short and recorded, and the walk moves on to the next.
	deadline, hasDeadline := ctx.Deadline()
	for i, top := range roots {
		if ctx.Err() != nil {
			// A partial walk must not look healthy: report what was missed.
			truncated = append(truncated, roots[i:]...)
			break
		}
		rootDeadline := time.Time{}
		if hasDeadline {
			if remaining := time.Until(deadline); remaining > 0 {
				rootDeadline = time.Now().Add(remaining / time.Duration(len(roots)-i))
			}
		}
		rootCut := false
		_ = filepath.WalkDir(env.Path(top), func(path string, d fs.DirEntry, err error) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if !rootDeadline.IsZero() && time.Now().After(rootDeadline) {
				rootCut = true
				return filepath.SkipAll
			}
			if err != nil {
				return nil
			}
			rel := path
			if env.Root != "" && env.Root != "/" {
				rel = "/" + strings.TrimPrefix(strings.TrimPrefix(path, env.Root), "/")
			}
			if d.IsDir() {
				if skipWalk[rel] || walked[rel] {
					return filepath.SkipDir
				}
				return nil
			}
			if d.Type()&fs.ModeSymlink != 0 || !d.Type().IsRegular() {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			mode := info.Mode()
			if mode&(fs.ModeSetuid|fs.ModeSetgid) == 0 {
				return nil
			}
			kind := "setuid"
			if mode&fs.ModeSetuid == 0 {
				kind = "setgid"
			}
			owner := ""
			if st, ok := info.Sys().(*syscall.Stat_t); ok {
				owner = itoa(int(st.Uid))
			}
			attrs := map[string]string{"mode": mode.String(), "owner_uid": owner}
			if pkg := env.Pkg.Owner(rel); pkg != "" {
				attrs["package"] = pkg
			}
			items = append(items, Item{Key: rel, Value: kind, Attrs: attrs})
			return nil
		})
		if ctx.Err() != nil {
			truncated = append(truncated, roots[i:]...)
			break
		}
		if rootCut {
			truncated = append(truncated, top)
			continue
		}
		walked[top] = true
	}
	if len(truncated) > 0 {
		return items, nil, fmt.Errorf("%w: SUID walk did not fully examine %s (timed out)", ErrPartial, strings.Join(dedupeStrings(truncated), ", "))
	}
	return items, nil, nil
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// tmpExecCollector reports executable regular files in world-writable
// directories, which legitimate software almost never leaves behind.
type tmpExecCollector struct{}

func (tmpExecCollector) Name() string { return "tmp_exec" }
func (tmpExecCollector) Every() int   { return 2 }

func (tmpExecCollector) Collect(ctx context.Context, env *Env) ([]Item, []Event, error) {
	var items []Item
	for _, top := range []string{"/tmp", "/var/tmp", "/dev/shm"} {
		root := env.Path(top)
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || ctx.Err() != nil {
				return nil
			}
			depth := strings.Count(strings.TrimPrefix(path, root), "/")
			if d.IsDir() {
				if depth > 4 {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			info, err := d.Info()
			if err != nil || info.Mode().Perm()&0o111 == 0 {
				return nil
			}
			rel := top + strings.TrimPrefix(path, root)
			items = append(items, Item{Key: rel, Value: short(hashFile(path)), Attrs: map[string]string{"size": itoa(int(info.Size())), "magic": fileMagic(path)}})
			return nil
		})
	}
	return items, nil, nil
}

func fileMagic(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	b := make([]byte, 4)
	n, _ := f.Read(b)
	b = b[:n]
	switch {
	case len(b) == 4 && string(b) == "\x7fELF":
		return "elf"
	case len(b) >= 2 && string(b[:2]) == "#!":
		return "script"
	}
	return "data"
}

// moduleCollector reports loaded kernel modules.
type moduleCollector struct{}

func (moduleCollector) Name() string { return "kernel_module" }
func (moduleCollector) Every() int   { return 1 }

func (moduleCollector) Collect(ctx context.Context, env *Env) ([]Item, []Event, error) {
	b, err := os.ReadFile(env.Path("/proc/modules"))
	if err != nil {
		return nil, nil, err
	}
	var items []Item
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		attrs := map[string]string{}
		if len(f) >= 7 && strings.Contains(f[len(f)-1], "(") {
			attrs["taint"] = f[len(f)-1]
		}
		items = append(items, Item{Key: f[0], Attrs: attrs})
	}
	return items, nil, nil
}

// packageCollector reports installed packages and versions. Package changes
// are rarely interesting on their own, but they explain other changes. The
// value also carries a digest of the package's checksum list, so a list that
// is rewritten without an upgrade (to make a trojaned binary "verify") shows.
type packageCollector struct{}

func (packageCollector) Name() string { return "package" }
func (packageCollector) Every() int   { return 5 }

func (packageCollector) Collect(ctx context.Context, env *Env) ([]Item, []Event, error) {
	pkgs := env.Pkg.Installed()
	if len(pkgs) == 0 {
		return nil, nil, os.ErrNotExist
	}
	items := make([]Item, 0, len(pkgs))
	for name, ver := range pkgs {
		if sums := env.Pkg.SumsDigest(name); sums != "" {
			ver += " sums:" + sums
		}
		items = append(items, Item{Key: name, Value: ver})
	}
	return items, nil, nil
}

// containerCollector reports running containers (image + name) when a docker
// or podman CLI is available.
type containerCollector struct{}

func (containerCollector) Name() string { return "container" }
func (containerCollector) Every() int   { return 2 }

func (containerCollector) Collect(ctx context.Context, env *Env) ([]Item, []Event, error) {
	var bin string
	for _, b := range []string{"docker", "podman"} {
		if p, err := exec.LookPath(b); err == nil {
			bin = p
			break
		}
	}
	if bin == "" {
		return nil, nil, nil
	}
	out, err := exec.CommandContext(ctx, bin, "ps", "--format", "{{.Names}}\t{{.Image}}\t{{.Ports}}").Output()
	if err != nil {
		return nil, nil, nil // daemon not running is not an error for us
	}
	var items []Item
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.SplitN(line, "\t", 3)
		if len(f) < 2 {
			continue
		}
		ports := ""
		if len(f) == 3 {
			ports = f[2]
		}
		// Compose names end in -1, -2…; strip the replica index from identity.
		items = append(items, Item{Key: f[1] + "#" + trimReplica(f[0]), Value: ports, Attrs: map[string]string{"name": f[0]}})
	}
	return items, nil, nil
}

func trimReplica(name string) string {
	if i := strings.LastIndexAny(name, "-_"); i > 0 {
		if _, err := atoi(name[i+1:]); err == nil {
			return name[:i]
		}
	}
	return name
}
