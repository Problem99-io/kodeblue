package sensors

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"
)

type passwdEntry struct {
	Name, UID, GID, Home, Shell string
}

func readPasswd(env *Env) []passwdEntry {
	f, err := os.Open(env.Path("/etc/passwd"))
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []passwdEntry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Split(sc.Text(), ":")
		if len(parts) < 7 || strings.HasPrefix(parts[0], "#") {
			continue
		}
		out = append(out, passwdEntry{Name: parts[0], UID: parts[2], GID: parts[3], Home: parts[5], Shell: parts[6]})
	}
	return out
}

func loadUserNames(env *Env) map[string]string {
	out := map[string]string{}
	for _, p := range readPasswd(env) {
		if _, ok := out[p.UID]; !ok {
			out[p.UID] = p.Name
		}
	}
	return out
}

func loginShell(shell string) bool {
	return !strings.HasSuffix(shell, "nologin") && !strings.HasSuffix(shell, "/false") && shell != "" && !strings.HasSuffix(shell, "/sync")
}

// accountCollector reports local accounts (with their uid and whether they can
// log in), membership of privileged groups, and whether each account has a
// usable password hash. Hashes themselves are never read into items.
type accountCollector struct{}

func (accountCollector) Name() string { return "account" }
func (accountCollector) Every() int   { return 1 }

var privilegedGroups = map[string]bool{"root": true, "sudo": true, "wheel": true, "adm": true, "docker": true, "lxd": true, "disk": true, "shadow": true}

func (accountCollector) Collect(ctx context.Context, env *Env) ([]Item, []Event, error) {
	entries := readPasswd(env)
	if entries == nil {
		return nil, nil, os.ErrNotExist
	}
	passwordState := map[string]string{}
	if f, err := os.Open(env.Path("/etc/shadow")); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			parts := strings.Split(sc.Text(), ":")
			if len(parts) < 2 {
				continue
			}
			switch {
			case parts[1] == "":
				passwordState[parts[0]] = "empty"
			case strings.HasPrefix(parts[1], "!") || strings.HasPrefix(parts[1], "*"):
				passwordState[parts[0]] = "locked"
			default:
				passwordState[parts[0]] = "set"
			}
		}
		f.Close()
	}
	var items []Item
	for _, p := range entries {
		login := "nologin"
		if loginShell(p.Shell) {
			login = "login"
		}
		pw := passwordState[p.Name]
		if pw == "" {
			pw = "unknown"
		}
		items = append(items, Item{
			Key:   "user/" + p.Name,
			Value: "uid=" + p.UID + " " + login + " password=" + pw,
			Attrs: map[string]string{"uid": p.UID, "gid": p.GID, "home": p.Home, "shell": p.Shell},
		})
	}
	if f, err := os.Open(env.Path("/etc/group")); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			parts := strings.Split(sc.Text(), ":")
			if len(parts) < 4 || !privilegedGroups[parts[0]] {
				continue
			}
			for _, m := range strings.Split(parts[3], ",") {
				if m = strings.TrimSpace(m); m != "" {
					items = append(items, Item{Key: "group/" + parts[0] + "/" + m})
				}
			}
		}
		f.Close()
	}
	// sudoers is configuration, hashed as a whole per file.
	for _, path := range globFiles(env, "/etc/sudoers", "/etc/sudoers.d/*") {
		items = append(items, Item{Key: "sudoers" + path, Value: short(hashFile(env.Path(path)))})
	}
	return items, nil, nil
}

// sshKeyCollector reports every authorized key line per account, keyed by the
// key's fingerprint so reordering a file is not a change.
type sshKeyCollector struct{}

func (sshKeyCollector) Name() string { return "ssh_key" }
func (sshKeyCollector) Every() int   { return 1 }

func (sshKeyCollector) Collect(ctx context.Context, env *Env) ([]Item, []Event, error) {
	var items []Item
	homes := map[string]string{"root": "/root"}
	for _, p := range readPasswd(env) {
		if p.Home != "" && p.Home != "/" && p.Home != "/nonexistent" {
			homes[p.Name] = p.Home
		}
	}
	for user, home := range homes {
		for _, name := range []string{"authorized_keys", "authorized_keys2"} {
			path := filepath.Join(home, ".ssh", name)
			b, err := os.ReadFile(env.Path(path))
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(b), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				comment := ""
				fields := strings.Fields(line)
				// options may precede the key type; the comment is the last
				// field after the base64 blob.
				for idx, f := range fields {
					if strings.HasPrefix(f, "ssh-") || strings.HasPrefix(f, "ecdsa-") || strings.HasPrefix(f, "sk-") {
						if idx+2 < len(fields) {
							comment = strings.Join(fields[idx+2:], " ")
						}
						break
					}
				}
				items = append(items, Item{
					Key:   user + "/" + short(hashString(line)),
					Attrs: map[string]string{"file": path, "comment": comment, "has_options": boolStr(!strings.HasPrefix(fields[0], "ssh-") && !strings.HasPrefix(fields[0], "ecdsa-") && !strings.HasPrefix(fields[0], "sk-"))},
				})
			}
		}
	}
	// sshd configuration affects who can get in at all.
	for _, path := range globFiles(env, "/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/*") {
		items = append(items, Item{Key: "sshd_config" + path, Value: short(hashFile(env.Path(path)))})
	}
	return items, nil, nil
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// globFiles expands host-absolute globs under env.Root and returns
// host-absolute regular-file paths.
func globFiles(env *Env, patterns ...string) []string {
	var out []string
	for _, pat := range patterns {
		matches, _ := filepath.Glob(env.Path(pat))
		for _, m := range matches {
			st, err := os.Stat(m)
			if err != nil || !st.Mode().IsRegular() {
				continue
			}
			rel := m
			if env.Root != "" && env.Root != "/" {
				rel = "/" + strings.TrimPrefix(strings.TrimPrefix(m, env.Root), "/")
			}
			out = append(out, rel)
		}
	}
	return out
}
