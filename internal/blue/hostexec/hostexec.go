// Package hostexec runs read-only inspection commands on the host for agents
// and for agent-authored monitors. Commands are argv (never a shell string),
// the binary must be on an allowlist, and arguments that turn a reader into a
// writer or executor (find -exec, journalctl --vacuum, systemctl stop, …) are
// rejected. This is the boundary that keeps a prompt-injected model — logs and
// file contents are attacker-controlled — from turning kodeblue into a
// foothold. State-changing actions go through internal/blue/respond instead.
package hostexec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// policy for one allowlisted binary.
type policy struct {
	// verbs, if set, requires the first non-flag argument to be one of these.
	verbs []string
	// denyArgs are rejected anywhere (exact or prefix match for "--x=" forms).
	denyArgs []string
	// allowOnlyFlags, if set, restricts every flag to this set.
	allowOnlyFlags []string
	// metadata commands read a file's mode, owner, size and name, never its
	// content, so they may name a secret path: whether a key file is readable
	// by everyone is a question about the file, not its secret.
	metadata bool
}

var allow = map[string]policy{
	"ps": {}, "ss": {}, "netstat": {}, "lsof": {}, "ls": {metadata: true}, "stat": {metadata: true}, "file": {}, "id": {}, "who": {}, "w": {},
	"last": {}, "lastb": {}, "lastlog": {}, "uptime": {}, "df": {}, "du": {}, "mount": {allowOnlyFlags: []string{"-l", "-t"}},
	"head": {}, "tail": {denyArgs: []string{"-f", "-F", "--follow"}}, "grep": {}, "egrep": {}, "zgrep": {}, "wc": {}, "sort": {denyArgs: []string{"-o", "--output"}}, "uniq": {},
	"sha256sum": {}, "sha1sum": {}, "md5sum": {}, "readlink": {metadata: true}, "realpath": {metadata: true}, "strings": {}, "uname": {}, "hostname": {allowOnlyFlags: []string{"-f", "-I", "-s"}},
	"getent": {verbs: getentDatabases, allowOnlyFlags: []string{"-i", "--no-idn", "-A", "--no-addrconfig"}}, "lsmod": {}, "modinfo": {}, "lsattr": {metadata: true}, "getcap": {metadata: true}, "date": {allowOnlyFlags: []string{"-u", "-R", "-I", "--iso-8601"}}, "free": {}, "top": {allowOnlyFlags: []string{"-b", "-n", "-n1", "-o", "-c"}},
	"pstree": {}, "ip": {verbs: []string{"addr", "a", "route", "r", "link", "l", "neigh", "n", "rule"}, denyArgs: []string{"add", "del", "delete", "set", "flush", "change", "replace", "exec"}},
	"find":       {denyArgs: []string{"-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprint0", "-fprintf", "-fls"}},
	"journalctl": {denyArgs: []string{"--rotate", "--vacuum-size", "--vacuum-time", "--vacuum-files", "--flush", "--sync", "--relinquish-var", "--smart-relinquish-var", "--setup-keys", "-f", "--follow", "--update-catalog"}},
	"systemctl":  {verbs: []string{"status", "list-units", "list-unit-files", "list-timers", "list-sockets", "is-active", "is-enabled", "is-failed", "cat", "show", "list-dependencies"}},
	"crontab":    {allowOnlyFlags: []string{"-l", "-u"}},
	"docker":     {verbs: []string{"ps", "inspect", "images", "logs", "top", "diff", "version", "info", "port", "stats"}, denyArgs: []string{"-f", "--follow"}},
	"podman":     {verbs: []string{"ps", "inspect", "images", "logs", "top", "diff", "version", "info", "port"}, denyArgs: []string{"-f", "--follow"}},
	"dpkg":       {allowOnlyFlags: []string{"-l", "-L", "-S", "-s", "-V", "--verify", "--list", "--listfiles", "--search", "--status", "--get-selections"}},
	"debsums":    {allowOnlyFlags: []string{"-c", "-s", "-a", "-e", "-l"}},
	"rpm":        {allowOnlyFlags: []string{"-q", "-qa", "-qf", "-ql", "-qi", "-V", "-Va", "--verify", "--query", "-a", "-f", "-l", "-i"}},
	"apk":        {verbs: []string{"info", "verify", "audit", "list", "policy"}},
	// apt reads the package lists (refreshed by the system's apt timer):
	// installed and candidate versions, pending upgrades. apt-get only
	// simulates (see check): -s prints what an upgrade would install.
	"apt":             {verbs: []string{"list", "policy", "show"}, allowOnlyFlags: []string{"--upgradable", "--installed", "-a", "--all-versions", "-q", "-qq"}},
	"apt-cache":       {verbs: []string{"policy", "show", "madison"}, allowOnlyFlags: []string{"-q", "-qq"}},
	"apt-get":         {verbs: []string{"upgrade", "dist-upgrade", "full-upgrade"}, allowOnlyFlags: aptSimulate},
	"iptables":        {allowOnlyFlags: []string{"-L", "-S", "-n", "-v", "-t", "--line-numbers", "-x"}},
	"ip6tables":       {allowOnlyFlags: []string{"-L", "-S", "-n", "-v", "-t", "--line-numbers", "-x"}},
	"nft":             {verbs: []string{"list"}},
	"ufw":             {verbs: []string{"status"}},
	"fail2ban-client": {verbs: []string{"status"}},
	"sshd":            {allowOnlyFlags: []string{"-T"}},
	"auditctl":        {allowOnlyFlags: []string{"-l", "-s"}},
	"ausearch":        {},
	"aureport":        {},
	"timedatectl":     {verbs: []string{"status", "show"}},
	"loginctl":        {verbs: []string{"list-sessions", "list-users", "show-session", "show-user", "session-status", "user-status"}},
	"getfacl":         {},
	"cat":             {}, // host_read is preferred; cat is here for monitors piping-free checks
}

// aptSimulate are apt-get's flags here; the first five make it simulate,
// and one of them is required.
var aptSimulate = []string{"-s", "--simulate", "--just-print", "--dry-run", "--no-act", "-q", "-qq", "-V"}

func hasAny(args, flags []string) bool {
	for _, a := range args {
		for _, f := range flags {
			if a == f {
				return true
			}
		}
	}
	return false
}

// getentDatabases are the getent databases an agent may query: accounts,
// groups and network names. shadow and gshadow hold password hashes, and
// getent -s (which takes a separate value the verb check would mistake for
// the database) is not among the allowed flags.
var getentDatabases = []string{"passwd", "group", "hosts", "ahosts", "ahostsv4", "ahostsv6", "services", "protocols", "networks", "rpc", "ethers", "netgroup", "initgroups", "aliases"}

// secretPaths are never readable through kodeblue, whatever the tool. SSH
// host keys end in _key (their .pub halves stay readable); user keys with
// the default names match /.ssh/id_ wherever the home is.
var secretPaths = []string{"/etc/shadow", "/etc/gshadow", "/etc/shadow-", "/etc/gshadow-", "/etc/kodeblue/", "/var/lib/kodeblue/secrets", "/root/.ssh/id_", "/.ssh/id_", "/ssh_host_", "/etc/dropbear/", "/proc/self/environ", "/etc/ssl/private/", ".pem", ".key", "/environ"}

// IsSecretPath reports whether path must never be read by an agent: one of
// secretPaths, an app's .env file (.env, *.env, .env.*), or a file a systemd
// unit loads with EnvironmentFile=.
func IsSecretPath(path string) bool {
	clean := filepath.Clean(path)
	for _, s := range secretPaths {
		if strings.Contains(clean, s) {
			// Public keys are fine.
			if strings.HasSuffix(clean, ".pub") {
				return false
			}
			return true
		}
	}
	if base := filepath.Base(clean); base == ".env" || strings.HasSuffix(base, ".env") || strings.HasPrefix(base, ".env.") {
		return true
	}
	for _, f := range unitEnvFiles() {
		if ok, _ := filepath.Match(f, clean); ok {
			return true
		}
	}
	return false
}

// unitDirs are where systemd units and their *.d drop-ins live (tests point
// it elsewhere).
var unitDirs = []string{"/etc/systemd/system", "/run/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system"}

var (
	envFilesMu  sync.Mutex
	envFilesAt  time.Time
	envFiles    []string
	specifierRe = regexp.MustCompile(`%[A-Za-z]`)
)

// unitEnvFiles returns the files units load with EnvironmentFile=, as glob
// patterns (a template's %i becomes *), plus where symlinked ones lead. It
// rescans at most once a minute so Validate stays cheap.
func unitEnvFiles() []string {
	envFilesMu.Lock()
	defer envFilesMu.Unlock()
	if time.Since(envFilesAt) < time.Minute {
		return envFiles
	}
	envFiles, envFilesAt = nil, time.Now()
	for _, d := range unitDirs {
		units, _ := filepath.Glob(filepath.Join(d, "*"))
		dropins, _ := filepath.Glob(filepath.Join(d, "*.d", "*.conf"))
		for _, u := range append(units, dropins...) {
			if st, err := os.Stat(u); err != nil || !st.Mode().IsRegular() || st.Size() > 1<<20 {
				continue
			}
			b, _ := os.ReadFile(u)
			for _, l := range strings.Split(string(b), "\n") {
				k, v, ok := strings.Cut(l, "=")
				if !ok || strings.TrimSpace(k) != "EnvironmentFile" {
					continue
				}
				// "-" means the file may be missing.
				v = strings.Trim(strings.TrimPrefix(strings.TrimSpace(v), "-"), `"`)
				if !filepath.IsAbs(v) {
					continue
				}
				envFiles = append(envFiles, specifierRe.ReplaceAllString(filepath.Clean(v), "*"))
				if real, err := filepath.EvalSymlinks(v); err == nil && real != filepath.Clean(v) {
					envFiles = append(envFiles, real)
				}
			}
		}
	}
	return envFiles
}

// Validate checks argv against the allowlist without running it.
func Validate(argv []string) error {
	if len(argv) == 0 {
		return errors.New("empty command")
	}
	bin := filepath.Base(argv[0])
	if argv[0] != bin && !strings.HasPrefix(argv[0], "/usr/") && !strings.HasPrefix(argv[0], "/bin/") && !strings.HasPrefix(argv[0], "/sbin/") {
		return fmt.Errorf("command must be a bare allowlisted name, got %q", argv[0])
	}
	p, ok := allow[bin]
	if !ok {
		return fmt.Errorf("%q is not on the read-only allowlist (allowed: %s)", bin, strings.Join(Allowed(), ", "))
	}
	args := argv[1:]
	for _, a := range args {
		if strings.ContainsAny(a, "\x00\n") {
			return errors.New("arguments may not contain NUL or newlines")
		}
		for _, d := range p.denyArgs {
			if a == d || strings.HasPrefix(a, d+"=") {
				return fmt.Errorf("argument %q is not allowed for %s (it can modify state or block)", a, bin)
			}
		}
		if !p.metadata {
			if err := checkSecretArg(a); err != nil {
				return err
			}
		}
	}
	// Recursive grep over /etc or / would sweep secret files into the model's
	// context; listing with find (names only) is the supported way to search.
	if bin == "grep" || bin == "egrep" || bin == "zgrep" {
		for _, a := range args {
			if a == "--recursive" || a == "--dereference-recursive" || strings.HasPrefix(a, "--directories") || a == "-d" ||
				(strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && strings.ContainsAny(a, "rR")) {
				return fmt.Errorf("recursive grep is not allowed; list files with find, then grep specific files")
			}
		}
	}
	// Process and service environments carry credentials (API keys,
	// database passwords), and kodeblue may read every process's.
	switch bin {
	case "apt-get":
		if !hasAny(args, aptSimulate[:5]) {
			return fmt.Errorf("apt-get only simulates here: add -s (it prints what an upgrade would install and changes nothing)")
		}
	case "ps":
		if err := checkPS(args); err != nil {
			return err
		}
	case "systemctl":
		// Output redaction (redactOutput) finds Environment= by its key;
		// --value and -P print values without keys.
		for _, a := range args {
			if a == "--value" || (strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && strings.Contains(a, "P")) {
				return fmt.Errorf("%q is not allowed for systemctl (it prints property values without their names, so environments cannot be redacted); use -p NAME", a)
			}
		}
	case "docker", "podman":
		// Default inspect output is JSON whose Env arrays redactOutput
		// redacts; a --format template could print them in any shape, so
		// only plain field references away from the environment are allowed.
		// -f (follow for logs, format for inspect) is refused in any cluster.
		for i, a := range args {
			if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && strings.Contains(a, "f") {
				return fmt.Errorf("%q is not allowed for %s (follow, or a format without --format)", a, bin)
			}
			tmpl, ok := strings.CutPrefix(a, "--format=")
			if a == "--format" {
				tmpl, ok = "", true
				if i+1 < len(args) {
					tmpl = args[i+1]
				}
			}
			if ok {
				if err := checkTemplate(tmpl); err != nil {
					return fmt.Errorf("%s --format %q: %v", bin, tmpl, err)
				}
			}
		}
	}
	if len(p.allowOnlyFlags) > 0 {
		for _, a := range args {
			if !strings.HasPrefix(a, "-") {
				continue
			}
			ok := false
			for _, f := range p.allowOnlyFlags {
				if a == f || strings.HasPrefix(a, f+"=") {
					ok = true
					break
				}
			}
			if !ok {
				return fmt.Errorf("flag %q is not allowed for %s (allowed: %s)", a, bin, strings.Join(p.allowOnlyFlags, " "))
			}
		}
	}
	if len(p.verbs) > 0 {
		verb := ""
		for _, a := range args {
			if !strings.HasPrefix(a, "-") {
				verb = a
				break
			}
		}
		okVerb := false
		for _, v := range p.verbs {
			if verb == v {
				okVerb = true
				break
			}
		}
		if !okVerb {
			return fmt.Errorf("%s requires one of: %s", bin, strings.Join(p.verbs, ", "))
		}
	}
	return nil
}

// argPaths returns what in argument a may name a file: a itself, the value
// of a --flag=value, or for a short-flag cluster (-f/etc/shadow, -nfetc/x)
// every possible attached value, since which letters are flags depends on
// the tool.
func argPaths(a string) []string {
	switch {
	case strings.HasPrefix(a, "--"):
		if _, v, ok := strings.Cut(a, "="); ok {
			return []string{v}
		}
		return nil
	case strings.HasPrefix(a, "-"):
		var out []string
		for i := 2; i < len(a); i++ {
			out = append(out, a[i:])
		}
		return out
	}
	return []string{a}
}

// workDir is the commands' working directory (tests point it elsewhere).
var workDir = "/"

// checkSecretArg refuses an argument that names a secret path, directly, as
// a flag's value, relative to the commands' working directory, or through a
// symlink (including /proc/<pid>/cwd and fd links). A relative candidate
// names a file only if one exists there; otherwise it is a pattern or a
// value (grep environ …), not a path.
func checkSecretArg(a string) error {
	for _, c := range argPaths(a) {
		path := c
		if !filepath.IsAbs(c) {
			path = filepath.Join(workDir, c)
			if _, err := os.Lstat(path); err != nil {
				continue
			}
		}
		if IsSecretPath(path) {
			return fmt.Errorf("%q is a protected secret path", a)
		}
		if real, err := filepath.EvalSymlinks(path); err == nil && IsSecretPath(real) {
			return fmt.Errorf("%q resolves to a protected secret path", a)
		}
	}
	return nil
}

// ps options that take a value (the rest of the cluster, or else the next
// argument), which ps never parses as options: UNIX (-o …), BSD (o …) and
// GNU (--sort …) forms. t is left out because its BSD form takes an
// optional value, so the argument after it may still be options.
const (
	psUnixValue = "CGgpqsUuoOD"
	psBSDValue  = "OkoUpq"
)

var psLongValue = []string{"--format", "--group", "--Group", "--pid", "--ppid", "--quick-pid", "--sid", "--tty", "--user", "--User", "--sort", "--date-format", "--delimiter", "--cols", "--columns", "--width", "--lines", "--rows"}

// checkPS refuses the ways ps prints other processes' environments: the BSD
// e modifier in a dashless option cluster (ps auxe, ps eww; the UNIX -e
// selects every process and is fine) and the environ format keyword. Run
// sets neither PS_PERSONALITY nor CMD_ENV, so procps never reparses a dash
// option as BSD (that needs the bsd or old personality).
func checkPS(args []string) error {
	for _, a := range args {
		if strings.Contains(strings.ToLower(a), "environ") {
			return errors.New("ps may not print process environments (environ)")
		}
	}
	for i := 0; i < len(args); i++ {
		a, next := args[i], false
		switch {
		case strings.HasPrefix(a, "--"):
			next = !strings.Contains(a, "=") && contains(psLongValue, a)
		case strings.HasPrefix(a, "-"):
			for j := 1; j < len(a); j++ {
				if strings.IndexByte(psUnixValue, a[j]) >= 0 {
					next = j == len(a)-1
					break
				}
			}
		case a != "" && (a[0] >= 'a' && a[0] <= 'z' || a[0] >= 'A' && a[0] <= 'Z'):
			for j := 0; j < len(a); j++ {
				if a[j] == 'e' {
					return fmt.Errorf("ps %q: the e modifier prints process environments", a)
				}
				if strings.IndexByte(psBSDValue, a[j]) >= 0 {
					next = j == len(a)-1
					break
				}
			}
		}
		if next {
			i++ // the option's value, not options
		}
	}
	return nil
}

// A docker/podman --format template may only reference fields, optionally
// through json: {{.HostConfig.Privileged}}, {{json .Mounts}}.
var (
	tmplActionRe = regexp.MustCompile(`\{\{-?\s*(.*?)\s*-?\}\}`)
	tmplFieldRe  = regexp.MustCompile(`^(?:json\s+)?((?:\.[A-Za-z0-9_]+)+)$`)
)

// checkTemplate refuses a template that could print a container's
// environment: anything but field references, a field named like Env (or
// podman's CreateCommand, which holds the -e values), and a whole Config
// object (it contains Env).
func checkTemplate(tmpl string) error {
	actions := tmplActionRe.FindAllStringSubmatch(tmpl, -1)
	if len(actions) == 0 || strings.Count(tmpl, "{{") != len(actions) {
		return errors.New("only templates of field references such as {{.State.Status}} or {{json .Mounts}} are allowed")
	}
	for _, m := range actions {
		f := tmplFieldRe.FindStringSubmatch(m[1])
		if f == nil {
			return fmt.Errorf("{{%s}}: only field references such as {{.State.Status}} or {{json .Mounts}} are allowed", m[1])
		}
		segs := strings.Split(strings.TrimPrefix(f[1], "."), ".")
		for _, s := range segs {
			if l := strings.ToLower(s); strings.Contains(l, "env") || l == "createcommand" {
				return fmt.Errorf("{{%s}}: container environments are not readable", m[1])
			}
		}
		if strings.HasSuffix(strings.ToLower(segs[len(segs)-1]), "config") {
			return fmt.Errorf("{{%s}}: a whole config object includes the environment; name its fields", m[1])
		}
	}
	return nil
}

const redacted = "[redacted by kodeblue]"

var (
	// systemd's Environment= and EnvironmentFile(s)= at a line's start or
	// after grep's file:N: / file-N- prefix (UnsetEnvironment= and
	// PassEnvironment= hold names only).
	unitEnvRe = regexp.MustCompile(`(?:^|[\s:"'-])(?:Environment|EnvironmentFiles?)\s*=`)
	jsonEnvRe = regexp.MustCompile(`"(?:Env|CreateCommand)"\s*:\s*\[`)
	// A credential-like name, then = or a YAML/JSON/header colon (a bare
	// colon followed by a non-space is grep's file: prefix, as in
	// common-auth:3:), then its value. Names alone stay readable:
	// PasswordAuthentication yes, Failed password for, (sshd:auth):, and
	// sudo's PWD= (the working directory; MYSQL_PWD= is caught by _pwd).
	credRe = regexp.MustCompile(`(?i)((?:passw(?:or)?d|[_-]pwd|secret|token|api[-_]?key|access[-_]?key|private[-_]?key|credentials?|auth)[\w-]*(?:\s*=\s*|\s*:\s+|["']\s*:\s*))("[^"]*"?|'[^']*'?|(?:(?:bearer|basic|token)\s+)?[^\s"',;&{\[][^\s"',;&]*)`)
	// --password VALUE, a separate argument in a command line.
	credFlagRe = regexp.MustCompile(`(?i)((?:^|\s)--[\w-]*(?:passw(?:or)?d|secret|token|api[-_]?key)[\w-]*\s+)([^\s"',;&-][^\s"',;&]*)`)
	// mysql's -pVALUE, only on lines that mention mysql or mariadb.
	mysqlPassRe = regexp.MustCompile(`(\s-p)(\S+)`)
	// scheme://user:password@host
	urlPassRe = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/@]+:)([^\s@/]+)(@)`)
	// A crypt(3) hash in a shadow-format line: name:$id$…, maybe locked (!).
	shadowRe   = regexp.MustCompile(`([\w.-]+:)(!*\$[0-9a-z]{1,8}\$[^:\s]*)`)
	pemBeginRe = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`)
	pemEndRe   = regexp.MustCompile(`-----END [A-Z0-9 ]*PRIVATE KEY-----`)
	// A line of a PEM body (base64, or an encrypted key's headers), maybe
	// behind grep's file:N: prefix.
	pemBodyRe = regexp.MustCompile(`^(?:[^\s:]*[:-](?:\d+[:-])?)?(?:[A-Za-z0-9+/=]*|Proc-Type: .*|DEK-Info: .*)$`)
)

// redactOutput removes secrets from what host_exec and host_read return,
// whichever command or path produced it (a symlink can be swapped between
// the check and the read): private key blocks, shadow-format password
// hashes, systemd Environment=/EnvironmentFile(s)= values, the Env (and
// podman CreateCommand) arrays of docker/podman inspect JSON, and values
// given to credential-like names (--password=, DB_PASSWORD=, "api_key":,
// URL passwords), keeping the names. Output may be truncated, so it works
// line by line.
// Redact applies host_exec's output redaction (environments, credentials,
// private keys, password hashes) to text read from the host by other means,
// such as monitor output.
func Redact(s string) string { return redactOutput(s) }

func redactOutput(out string) string {
	lines := redactKeys(strings.Split(out, "\n"))
	cont := false // inside a unit's Environment= continued with \
	in := false   // inside an Env array that began on an earlier line
	for i, l := range lines {
		orig := l
		l, in = redactEnvArrays(l, in)
		if loc := unitEnvRe.FindStringIndex(l); loc != nil {
			if strings.TrimSpace(l[loc[1]:]) != "" {
				l = l[:loc[1]] + redacted
			}
			cont = strings.HasSuffix(orig, `\`)
		} else if cont {
			cont = strings.HasSuffix(orig, `\`)
			l = redacted
		}
		l = shadowRe.ReplaceAllString(l, "${1}"+redacted)
		l = urlPassRe.ReplaceAllString(l, "${1}"+redacted+"${3}")
		l = redactCredentials(l)
		l = credFlagRe.ReplaceAllString(l, "${1}"+redacted)
		if low := strings.ToLower(l); strings.Contains(low, "mysql") || strings.Contains(low, "mariadb") {
			l = mysqlPassRe.ReplaceAllString(l, "${1}"+redacted)
		}
		lines[i] = l
	}
	return strings.Join(lines, "\n")
}

// redactCredentials replaces each credRe value, keeping its quotes.
func redactCredentials(l string) string {
	ms := credRe.FindAllStringSubmatchIndex(l, -1)
	if ms == nil {
		return l
	}
	var b strings.Builder
	last := 0
	for _, m := range ms {
		q := ""
		if v := l[m[4]:m[5]]; v[0] == '"' || v[0] == '\'' {
			q = v[:1]
		}
		b.WriteString(l[last:m[3]] + q + redacted + q)
		last = m[1]
	}
	return b.String() + l[last:]
}

// redactKeys replaces the bodies of PEM private keys with one redacted
// line, keeping the BEGIN and END lines. A block cut short (no END) ends at
// the first line that is not key material, and one that began before the
// output did (an offset read) is recognized by its END line.
func redactKeys(lines []string) []string {
	out := make([]string, 0, len(lines))
	in := false
	for _, l := range lines {
		if in {
			if pemEndRe.MatchString(l) {
				out, in = append(out, l), false
				continue
			}
			if pemBodyRe.MatchString(l) {
				continue
			}
			in = false
		}
		if b := pemBeginRe.FindStringIndex(l); b != nil {
			rest := l[b[1]:]
			switch e := pemEndRe.FindStringIndex(rest); {
			case e != nil: // the whole key on one line, as in JSON
				out = append(out, l[:b[1]]+redacted+rest[e[0]:])
			case rest == "":
				out, in = append(out, l, redacted), true
			default:
				out, in = append(out, l[:b[1]]+redacted), true
			}
			continue
		}
		if pemEndRe.MatchString(l) {
			n := len(out)
			for n > 0 && out[n-1] != "" && pemBodyRe.MatchString(out[n-1]) {
				n--
			}
			if n < len(out) {
				out = append(out[:n], redacted)
			}
		}
		out = append(out, l)
	}
	return out
}

// redactEnvArrays redacts the docker/podman inspect Env arrays in line l;
// in says whether one is open from an earlier line, and the result whether
// one is still open at its end.
func redactEnvArrays(l string, in bool) (string, bool) {
	var b strings.Builder
	for l != "" {
		if !in {
			loc := jsonEnvRe.FindStringIndex(l)
			if loc == nil {
				b.WriteString(l)
				break
			}
			b.WriteString(l[:loc[1]])
			l, in = l[loc[1]:], true
		}
		var done string
		done, l, in = redactEnvArray(l)
		b.WriteString(done)
	}
	return b.String(), in
}

// redactEnvArray redacts the values of the JSON strings in s, which starts
// inside an Env array, up to the array's closing bracket. It returns the
// redacted part, the rest of s after the bracket, and whether the array is
// still open at the end of s (output is line by line, maybe truncated).
func redactEnvArray(s string) (done, rest string, open bool) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ']':
			b.WriteByte(']')
			return b.String(), s[i+1:], false
		case '"':
			j := i + 1
			for j < len(s) && s[j] != '"' {
				if s[j] == '\\' {
					j++
				}
				j++
			}
			str := s[i:min(j+1, len(s))]
			if eq := strings.IndexByte(str, '='); eq > 0 {
				str = str[:eq+1] + redacted + `"` // keep the name
			}
			b.WriteString(str)
			i = j
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String(), "", true
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// Allowed lists allowlisted binaries.
func Allowed() []string {
	out := make([]string, 0, len(allow))
	for k := range allow {
		out = append(out, k)
	}
	sortStrings(out)
	return out
}

// Result of running a command.
type Result struct {
	ExitCode  int    `json:"exit_code"`
	Stdout    string `json:"stdout"`
	Stderr    string `json:"stderr,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
	TimedOut  bool   `json:"timed_out,omitempty"`
}

// Run validates and executes argv with a timeout and output cap.
func Run(ctx context.Context, argv []string, timeout time.Duration, maxBytes int) (Result, error) {
	if err := Validate(argv); err != nil {
		return Result{}, err
	}
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	if maxBytes <= 0 {
		maxBytes = 16 * 1024
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "SYSTEMD_PAGER=", "PAGER=cat", "SYSTEMD_COLORS=0"}
	cmd.Dir = workDir
	cmd.Stdin = nil
	var stdout, stderr capBuffer
	stdout.max, stderr.max = maxBytes, 4096
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	res := Result{Stdout: redactOutput(stdout.String()), Stderr: redactOutput(stderr.String()), Truncated: stdout.over}
	if ctx.Err() == context.DeadlineExceeded {
		res.TimedOut = true
	}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			res.ExitCode = ee.ExitCode()
			return res, nil
		}
		if res.TimedOut {
			res.ExitCode = -1
			return res, nil
		}
		return res, err
	}
	return res, nil
}

type capBuffer struct {
	bytes.Buffer
	max  int
	over bool
}

func (c *capBuffer) Write(p []byte) (int, error) {
	room := c.max - c.Len()
	if room <= 0 {
		c.over = true
		return len(p), nil
	}
	if len(p) > room {
		c.over = true
		c.Buffer.Write(p[:room])
		return len(p), nil
	}
	return c.Buffer.Write(p)
}

// ReadFile reads up to maxBytes of a host file starting at offset, refusing
// secret paths and redacting secrets from what it returns, as Run does.
func ReadFile(path string, offset int64, maxBytes int) (string, int64, bool, error) {
	if !filepath.IsAbs(path) {
		return "", 0, false, errors.New("path must be absolute")
	}
	if IsSecretPath(path) {
		return "", 0, false, fmt.Errorf("%s is a protected secret path", path)
	}
	real, err := filepath.EvalSymlinks(path)
	if err == nil && IsSecretPath(real) {
		return "", 0, false, fmt.Errorf("%s resolves to a protected secret path", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return "", 0, false, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", 0, false, err
	}
	if st.IsDir() {
		return "", 0, false, errors.New("is a directory; use host_list")
	}
	if maxBytes <= 0 || maxBytes > 64*1024 {
		maxBytes = 64 * 1024
	}
	if offset < 0 {
		offset = st.Size() + offset // negative offset = from end
		if offset < 0 {
			offset = 0
		}
	}
	buf := make([]byte, maxBytes)
	n, _ := f.ReadAt(buf, offset)
	return redactOutput(string(bytes.ToValidUTF8(buf[:n], []byte("?")))), st.Size(), offset+int64(n) < st.Size(), nil
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
