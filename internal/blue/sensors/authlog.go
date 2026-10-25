package sensors

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CursorStore remembers how far each log has been read, so events are emitted
// once and a restart does not replay history.
type CursorStore struct {
	mu   sync.Mutex
	path string
	m    map[string]cursor
}

type cursor struct {
	Inode  uint64 `json:"inode"`
	Offset int64  `json:"offset"`
	Since  string `json:"since,omitempty"` // journald cursor
	// PrevInode and PrevOffset follow the file rotated away from, which a
	// writer may still append to until it reopens its log.
	PrevInode  uint64 `json:"prev_inode,omitempty"`
	PrevOffset int64  `json:"prev_offset,omitempty"`
	// Head is a hash of the file's first HeadLen bytes (up to headLen,
	// all of them read): a file truncated in place and written past the
	// old offset since starts differently.
	HeadLen int64  `json:"head_len,omitempty"`
	Head    string `json:"head,omitempty"`
}

// NewCursorStore loads cursors from path (created on first Save).
func NewCursorStore(path string) *CursorStore {
	c := &CursorStore{path: path, m: map[string]cursor{}}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &c.m)
	}
	return c
}

func (c *CursorStore) get(k string) (cursor, bool) {
	if c == nil {
		return cursor{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.m[k]
	return v, ok
}

func (c *CursorStore) set(k string, v cursor) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.m[k] = v
	c.mu.Unlock()
}

// Save persists cursors atomically.
func (c *CursorStore) Save() error {
	if c == nil || c.path == "" {
		return nil
	}
	c.mu.Lock()
	b, _ := json.Marshal(c.m)
	c.mu.Unlock()
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}

// authLogCollector turns authentication logs into events: logins, failures,
// sudo, account changes. It reads /var/log/auth.log or /var/log/secure
// incrementally, falling back to journald when neither exists.
type authLogCollector struct {
	p authParser // remembers connections across sweeps
}

func (*authLogCollector) Name() string { return "auth" }
func (*authLogCollector) Every() int   { return 1 }

// authIdents are the syslog identifiers whose lines the auth sensor parses.
// OpenSSH 9.8 moved per-connection logging from sshd to sshd-session, and
// 10.0 split pre-authentication off into sshd-auth.
var authIdents = []string{"sshd", "sshd-session", "sshd-auth", "sudo", "su", "useradd", "usermod", "passwd", "chpasswd"}

var (
	// reLogLine is a syslog file line (traditional or RFC 3339 timestamp) or
	// journalctl -o short-iso: timestamp, host, program[pid]: message. Every
	// pattern below runs on the message alone, anchored at its start, so text
	// a remote user controls (a user name, a command) can never pose as the
	// start of another program's line.
	reLogLine = regexp.MustCompile(`^(?:[A-Z][a-z]{2} +\d{1,2} \d\d:\d\d:\d\d|\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?) \S+ ([^\s\[\]:]+)(?:\[(\d+)\])?: (.*)$`)
	// rsyslog's RepeatedMsgReduction folds identical consecutive messages
	// into the first one and this, written right after it.
	reRepeated = regexp.MustCompile(`^message repeated (\d+) times: \[ ?(.*)\]$`)

	// sshd writes "<keyword> <user> from <ip> port <n> ssh2", and only
	// publickey and hostbased lines go on with ": <key>" (a key ID, a
	// certificate's ID and CA, any fingerprint hash). The user name is
	// whatever a remote client sent, cut by sshd at its first ':' (BSD
	// auth's user:style), so the address is read from where sshd put it:
	// the end of the line, or the first " port <n> ssh2: ", which a name
	// without a ':' cannot contain. A success is for a real account, whose
	// name has no spaces.
	reAccepted  = regexp.MustCompile(`^Accepted (\S+) for (\S+) from (\S+) port (\d+)(?: ssh2)?(?:: .*)?$`)
	reFailed    = regexp.MustCompile(`^Failed (\S+) for (invalid user )?(.*) from (\S+) port (\d+)(?: ssh2)?$`)
	reFailedKey = regexp.MustCompile(`^Failed (publickey|hostbased) for (invalid user )?(.*?) from (\S+) port (\d+) ssh2: .+$`)
	reInvalid   = regexp.MustCompile(`^Invalid user (.*) from (\S+)(?: port (\d+))?$`)

	reSudo       = regexp.MustCompile(`^\s*(\S+) : .*?(?:USER=(\S+) ; )?COMMAND=(.*)$`)
	reSudoFail   = regexp.MustCompile(`^\s*(\S+) : (?:\d+ )?(incorrect password attempts?|user NOT in sudoers|authentication failure)`)
	reUserAdd    = regexp.MustCompile(`^new user: name=([^,]+), UID=(\d+)`)
	reGroupMod   = regexp.MustCompile(`^add '([^']+)' to (?:shadow )?group '([^']+)'`)
	rePasswd     = regexp.MustCompile(`^pam_unix\([\w-]+:chauthtok\): password changed for (\S+)$`)
	reSessionSu  = regexp.MustCompile(`^pam_unix\(su(?:-l)?:session\): session opened for user ([^\s(]+)(?:\(uid=\d+\))? by ([^\s(]*)(\(uid=\d+\))?`)
	reSyslogTime = regexp.MustCompile(`^(\w{3}\s+\d+\s+\d\d:\d\d:\d\d)`)
	reISOTime    = regexp.MustCompile(`^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?)`)
	reHostname   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]*$`)
	reEscaped    = regexp.MustCompile(`\\[0-7]{3}`) // sshd's vis(3) escape of a control character
)

// maxRepeat bounds the events one "message repeated" line adds. rsyslog
// folds only identical messages of one process, and an sshd process is one
// connection, which MaxAuthTries (6 by default) ends well before this.
const maxRepeat = 20

// maxRepeatPerParse bounds what "message repeated" lines add in one sweep.
const maxRepeatPerParse = 1000

func (c *authLogCollector) Collect(ctx context.Context, env *Env) ([]Item, []Event, error) {
	for _, path := range []string{"/var/log/auth.log", "/var/log/secure"} {
		lines, err := TailNew(env, path)
		if err == nil {
			return nil, c.p.parse(lines), nil
		}
	}
	lines, err := journalNew(ctx, env)
	if err != nil {
		return nil, nil, err
	}
	return nil, c.p.parse(lines), nil
}

// tailNew returns lines appended to a log since the stored cursor. On first
// sight of a log it starts at the end: history is the learner's job, not an
// alert source.
func TailNew(env *Env, path string) ([]string, error) { return TailNewFrom(env, path, false) }

// TailNewFrom is TailNew, except that a file seen for the first time is read
// from its start when fromStart is set: a log that rotated into a new file
// name, whose first lines are new.
func TailNewFrom(env *Env, path string, fromStart bool) ([]string, error) {
	return TailNewAs(env, path, path, fromStart)
}

// maxTailRead bounds what one sweep reads from one file.
const maxTailRead = 4 << 20

// TailNewAs is TailNewFrom with its own cursor, named key: readers that share
// a file (several monitors on one access log, a monitor on the auth log the
// auth sensor also reads) each see every new line. A cursor follows the
// file's inode, so a key may move to a newer file and read it from the start.
// When the file was rotated by renaming, the rest of the old file is read
// first (it is found by inode among path.1, path-20261024 and the like), and
// it stays followed until the next rotation: a writer that has not reopened
// its log yet still appends there. When it was truncated in place
// (copytruncate), the rest is read from the copy that starts like it did.
// Lines written between logrotate's copy and its truncation are lost to
// every reader.
func TailNewAs(env *Env, key, path string, fromStart bool) ([]string, error) {
	f, err := os.Open(env.Path(path))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	inode := fileInode(st)
	cur, ok := env.State.get(key)
	start := cur.Offset
	next := cursor{Inode: inode}
	var lines []string
	switch {
	case !ok && !fromStart:
		next.Offset = st.Size()
		next.HeadLen, next.Head = headOf(f, next.Offset)
		env.State.set(key, next)
		return nil, nil
	case !ok:
		start = 0
	case cur.Inode != inode:
		// Rotated: finish the file the cursor was on.
		lines, next.PrevOffset = readRotated(env, path, cur.Inode, cur.Offset)
		if next.PrevOffset >= 0 {
			next.PrevInode = cur.Inode
		}
		start = 0
	case st.Size() < cur.Offset || cur.HeadLen > 0 && !sameHead(f, cur):
		lines = readCopy(env, path, cur)
		start = 0
	default:
		if cur.PrevInode != 0 {
			var old []string
			old, next.PrevOffset = readRotated(env, path, cur.PrevInode, cur.PrevOffset)
			if next.PrevOffset >= 0 {
				next.PrevInode = cur.PrevInode
			}
			lines = old
		}
	}
	if next.PrevInode == 0 {
		next.PrevOffset = 0
	}
	got, read, err := readLines(f, start)
	if err != nil {
		return nil, err
	}
	next.Offset = start + read
	next.HeadLen, next.Head = headOf(f, next.Offset)
	env.State.set(key, next)
	return append(lines, got...), nil
}

// headLen is how much of a file's start a cursor remembers.
const headLen = 256

// headOf hashes the first min(n, headLen) bytes of f.
func headOf(f *os.File, n int64) (int64, string) {
	n = min(n, headLen)
	if n <= 0 {
		return 0, ""
	}
	b := make([]byte, n)
	if _, err := f.ReadAt(b, 0); err != nil {
		return 0, ""
	}
	h := sha256.Sum256(b)
	return n, hex.EncodeToString(h[:])
}

// sameHead reports whether f still starts as it did at cur.
func sameHead(f *os.File, cur cursor) bool {
	n, h := headOf(f, cur.HeadLen)
	return n == cur.HeadLen && h == cur.Head
}

// readCopy finds the copy logrotate's copytruncate made next to path (the
// file that starts as path did at cur and is at least as long) and reads it
// from cur's offset on.
func readCopy(env *Env, path string, cur cursor) []string {
	if cur.HeadLen == 0 {
		return nil
	}
	names, _ := filepath.Glob(env.Path(path) + "?*")
	for _, name := range names {
		if compressed(name) {
			continue
		}
		f, err := os.Open(name)
		if err != nil {
			continue
		}
		st, err := f.Stat()
		if err != nil || !st.Mode().IsRegular() || st.Size() < cur.Offset || !sameHead(f, cur) {
			f.Close()
			continue
		}
		lines, _, _ := readLines(f, cur.Offset)
		f.Close()
		return lines
	}
	return nil
}

func compressed(name string) bool {
	switch filepath.Ext(name) {
	case ".gz", ".xz", ".bz2", ".zst", ".lz4":
		return true
	}
	return false
}

// readLines reads the complete lines of f from offset start: a partial
// trailing line is re-read next sweep.
func readLines(f *os.File, start int64) ([]string, int64, error) {
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return nil, 0, err
	}
	r := bufio.NewReader(io.LimitReader(f, maxTailRead))
	var lines []string
	var read int64
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			break
		}
		read += int64(len(line))
		lines = append(lines, strings.TrimRight(line, "\n"))
	}
	return lines, read, nil
}

// readRotated finds the rotated file with inode next to path and reads it
// from offset on. It returns the new offset, or -1 when the file is gone
// (compressed, removed): nothing more can be read from it.
func readRotated(env *Env, path string, inode uint64, offset int64) ([]string, int64) {
	if inode == 0 {
		return nil, -1
	}
	names, _ := filepath.Glob(env.Path(path) + "?*")
	for _, name := range names {
		if compressed(name) {
			continue
		}
		f, err := os.Open(name)
		if err != nil {
			continue
		}
		st, err := f.Stat()
		if err != nil || !st.Mode().IsRegular() || fileInode(st) != inode {
			f.Close()
			continue
		}
		if st.Size() < offset {
			offset = 0
		}
		lines, read, err := readLines(f, offset)
		f.Close()
		if err != nil {
			return nil, -1
		}
		return lines, offset + read
	}
	return nil, -1
}

func journalNew(ctx context.Context, env *Env) ([]string, error) {
	if _, err := exec.LookPath("journalctl"); err != nil {
		return nil, err
	}
	cur, ok := env.State.get("journal")
	args := append([]string{"--no-pager", "-o", "short-iso", "--show-cursor"}, identArgs()...)
	if ok && cur.Since != "" {
		args = append(args, "--after-cursor", cur.Since)
	} else {
		args = append(args, "-n", "0")
	}
	out, err := exec.CommandContext(ctx, "journalctl", args...).Output()
	if err != nil {
		return nil, err
	}
	var lines []string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "-- cursor: ") {
			env.State.set("journal", cursor{Since: strings.TrimPrefix(line, "-- cursor: ")})
			continue
		}
		if line != "" && !strings.HasPrefix(line, "-- ") {
			lines = append(lines, line)
		}
	}
	return lines, nil
}

// identArgs is journalctl's filter for authIdents.
func identArgs() []string {
	var args []string
	for _, id := range authIdents {
		args = append(args, "-t", id)
	}
	return args
}

// authParser turns auth log lines into events. It remembers sshd's
// "Invalid user" lines until that connection's first failed attempt, so an
// attempt on an unknown account counts once, not twice.
type authParser struct {
	mu      sync.Mutex
	invalid map[string]bool // program[pid] ip port of an "Invalid user" line
	prev    string          // program[pid] and message of the last line
}

func parseAuthLines(lines []string) []Event {
	var p authParser
	return p.parse(lines)
}

func (p *authParser) parse(lines []string) []Event {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.invalid == nil || len(p.invalid) > 10000 {
		p.invalid = map[string]bool{}
	}
	var out []Event
	now := time.Now()
	repeated := 0
	for _, line := range lines {
		m := reLogLine.FindStringSubmatch(line)
		if m == nil {
			p.prev = ""
			continue
		}
		prog, pid, msg := m[1], m[2], m[3]
		proc := prog + "[" + pid + "]"
		n := 1
		if r := reRepeated.FindStringSubmatch(msg); r != nil {
			// A count counts only right after the line it folds, from the
			// same process; anything else is not rsyslog's.
			n, _ = strconv.Atoi(r[1])
			n = min(n, maxRepeat, maxRepeatPerParse-repeated)
			msg = r[2]
			folds := p.prev == proc+" "+msg
			p.prev = ""
			if !folds || n <= 0 {
				continue
			}
			repeated += n
		} else {
			p.prev = proc + " " + msg
		}
		ts := parseLogTime(line, now)
		add := func(kind, subject string, attrs map[string]string) {
			short := line
			if len(short) > 300 {
				short = short[:300]
			}
			for range n {
				out = append(out, Event{Kind: kind, Time: ts, Subject: subject, Message: short, Attrs: attrs})
			}
		}
		switch prog {
		case "sshd", "sshd-session", "sshd-auth":
			p.sshd(proc, msg, &n, add)
		case "sudo":
			if m := reSudoFail.FindStringSubmatch(msg); m != nil {
				add("sudo_failure", m[1], map[string]string{"user": m[1], "reason": m[2]})
			} else if m := reSudo.FindStringSubmatch(msg); m != nil {
				target := m[2]
				if target == "" {
					target = "root"
				}
				add("sudo", m[1], map[string]string{"user": m[1], "as": target, "command": truncate(m[3], 200)})
			}
		case "su":
			if m := reSessionSu.FindStringSubmatch(msg); m != nil {
				by := m[2]
				if by == "" && m[3] == "(uid=0)" {
					by = "root"
				}
				add("su_session", m[1], map[string]string{"user": m[1], "by": by})
			}
		case "useradd":
			if m := reUserAdd.FindStringSubmatch(msg); m != nil {
				add("user_added", m[1], map[string]string{"user": m[1], "uid": m[2]})
			}
		case "usermod":
			if m := reGroupMod.FindStringSubmatch(msg); m != nil {
				add("group_added", m[1], map[string]string{"user": m[1], "group": m[2]})
			}
		case "passwd", "chpasswd":
			if m := rePasswd.FindStringSubmatch(msg); m != nil {
				add("password_changed", m[1], map[string]string{"user": m[1]})
			}
		}
	}
	return out
}

// sshd parses one sshd message; conn names the process that logged it. A
// line whose address is not one is dropped, a success whose user name is
// not one is dropped, and a failure keeps counting against its address with
// the user left out.
func (p *authParser) sshd(conn, msg string, n *int, add func(kind, subject string, attrs map[string]string)) {
	if m := reAccepted.FindStringSubmatch(msg); m != nil {
		if validUser(m[2]) && validHost(m[3]) {
			add("login_success", m[2]+"@"+m[3], map[string]string{"method": m[1], "user": m[2], "ip": m[3]})
		}
		return
	}
	if m := reInvalid.FindStringSubmatch(msg); m != nil {
		if !validHost(m[2]) {
			return
		}
		if m[3] != "" {
			p.invalid[conn+" "+m[2]+" "+m[3]] = true
		}
		add("login_invalid_user", m[2], userAttrs(m[1], map[string]string{"ip": m[2]}))
		return
	}
	var m []string
	if strings.HasPrefix(msg, "Failed publickey ") || strings.HasPrefix(msg, "Failed hostbased ") {
		m = reFailedKey.FindStringSubmatch(msg)
	} else {
		m = reFailed.FindStringSubmatch(msg)
	}
	if m == nil || !validHost(m[4]) {
		return
	}
	if m[2] != "" {
		// The connection's "Invalid user" line already counted its first
		// attempt.
		if k := conn + " " + m[4] + " " + m[5]; p.invalid[k] {
			delete(p.invalid, k)
			if *n--; *n == 0 {
				return
			}
		}
	}
	add("login_failure", m[4], userAttrs(m[3], map[string]string{"method": m[1], "ip": m[4]}))
}

// userAttrs adds user to attrs when it can be an account name; otherwise it
// marks the name as malformed, so a remote guess never reaches a model as a
// user name.
func userAttrs(user string, attrs map[string]string) map[string]string {
	if user == "" || validUser(user) {
		attrs["user"] = user
	} else {
		attrs["user"] = "?"
		attrs["user_malformed"] = "true"
	}
	return attrs
}

// validUser reports whether name can be an account sshd logs: no spaces,
// control characters or escapes of them, and none of the characters a log
// line's own structure uses.
func validUser(name string) bool {
	if name == "" || len(name) > 100 || reEscaped.MatchString(name) {
		return false
	}
	for _, r := range name {
		if r <= ' ' || r == 0x7f || r == '[' || r == ']' || r == ':' {
			return false
		}
	}
	return true
}

// validHost reports whether s is an address (or, with UseDNS, a host name).
func validHost(s string) bool {
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}
	return len(s) <= 253 && reHostname.MatchString(s)
}

func parseLogTime(line string, now time.Time) time.Time {
	if m := reISOTime.FindString(line); m != "" {
		for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05-0700", "2006-01-02T15:04:05.999999-07:00"} {
			if t, err := time.Parse(layout, m); err == nil {
				return t
			}
		}
	}
	if m := reSyslogTime.FindString(line); m != "" {
		if t, err := time.ParseInLocation("Jan _2 15:04:05", strings.Join(strings.Fields(m), " "), time.Local); err == nil {
			t = t.AddDate(now.Year(), 0, 0)
			if t.After(now.Add(24 * time.Hour)) {
				t = t.AddDate(-1, 0, 0)
			}
			return t
		}
	}
	return now
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// loadCollector reports processes holding a large share of CPU across two
// samples — the cheapest signal for miners. One item per hot executable.
type loadCollector struct {
	mu   sync.Mutex
	prev map[int]uint64
	at   time.Time
}

func (*loadCollector) Name() string { return "cpu_hog" }
func (*loadCollector) Every() int   { return 1 }

func (c *loadCollector) Collect(ctx context.Context, env *Env) ([]Item, []Event, error) {
	procs, err := readProcs(env)
	if err != nil {
		return nil, nil, err
	}
	ticks := map[int]uint64{}
	exes := map[int]Process{}
	for _, p := range procs {
		b, err := os.ReadFile(env.Path(filepath.Join("/proc", strconv.Itoa(p.PID), "stat")))
		if err != nil {
			continue
		}
		s := string(b)
		if i := strings.LastIndex(s, ")"); i > 0 {
			f := strings.Fields(s[i+1:])
			if len(f) > 13 {
				u, _ := strconv.ParseUint(f[11], 10, 64)
				st, _ := strconv.ParseUint(f[12], 10, 64)
				ticks[p.PID] = u + st
				exes[p.PID] = p
			}
		}
	}
	c.mu.Lock()
	prev, at := c.prev, c.at
	c.prev, c.at = ticks, time.Now()
	c.mu.Unlock()
	if prev == nil {
		return nil, nil, nil
	}
	elapsed := time.Since(at).Seconds()
	if elapsed < 1 {
		return nil, nil, nil
	}
	const hz = 100.0
	var items []Item
	for pid, t := range ticks {
		before, ok := prev[pid]
		if !ok || t < before {
			continue
		}
		pct := float64(t-before) / hz / elapsed * 100
		if pct < 80 {
			continue
		}
		p := exes[pid]
		items = append(items, Item{Key: p.Exe + "@" + p.User, Attrs: map[string]string{"cpu_percent": strconv.Itoa(int(pct)), "pid": strconv.Itoa(pid), "cmdline": p.Cmdline}})
	}
	return items, nil, nil
}

// AuthHistory reads the auth log history that is still on disk (current and
// first rotated file, or 14 days of journal) so the learning phase knows which
// accounts normally log in from where. It does not move the live cursor.
func AuthHistory(ctx context.Context, env *Env) []Event {
	var lines []string
	for _, path := range []string{"/var/log/auth.log.1", "/var/log/auth.log", "/var/log/secure.1", "/var/log/secure"} {
		b, err := os.ReadFile(env.Path(path))
		if err != nil {
			continue
		}
		if len(b) > 32<<20 {
			b = b[len(b)-32<<20:]
		}
		lines = append(lines, strings.Split(string(b), "\n")...)
	}
	if len(lines) == 0 {
		if _, err := exec.LookPath("journalctl"); err == nil {
			args := append([]string{"--no-pager", "-o", "short-iso", "--since", "-14d"}, identArgs()...)
			out, err := exec.CommandContext(ctx, "journalctl", args...).Output()
			if err == nil {
				lines = strings.Split(string(out), "\n")
			}
		}
	}
	return parseAuthLines(lines)
}
