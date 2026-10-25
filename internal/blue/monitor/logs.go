package monitor

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/hostexec"
	"github.com/Problem99-io/kodeblue/internal/blue/sensors"
)

// maxSeen bounds how many group values a new_values monitor remembers.
const maxSeen = 10000

var archiveRe = regexp.MustCompile(`\.(gz|bz2|xz|zst|zip)$`)

func validLogRegexes(s Spec) error {
	if _, err := regexp.Compile(s.Pattern); err != nil {
		return fmt.Errorf("pattern: %v", err)
	}
	if s.FilePattern != "" {
		if _, err := regexp.Compile(s.FilePattern); err != nil {
			return fmt.Errorf("file_pattern: %v", err)
		}
	}
	if s.GroupBy != "" {
		re, err := regexp.Compile(s.GroupBy)
		if err != nil {
			return fmt.Errorf("group_by: %v", err)
		}
		if re.NumSubexp() < 1 {
			return errors.New("group_by needs a capture group, e.g. ^(\\S+) for the client address at the start of an access log line")
		}
	}
	if s.NewValues && s.GroupBy == "" {
		return errors.New("new_values needs group_by: the value that must not be new")
	}
	if s.KnownValues != nil && !s.NewValues {
		return errors.New("known_values only applies with new_values")
	}
	return nil
}

// logFile picks the file a log monitor reads. For a directory it is the most
// recently written regular file (matching file_pattern, compressed archives
// left out); fresh reports that this file replaced the one read before, so
// it is read from the start.
func (r *Runner) logFile(s Spec, path string) (file string, fresh bool, err error) {
	file, dir, err := r.pickLog(s, path)
	if err != nil || !dir {
		return file, false, err
	}
	key := "monitor_logfile:" + s.ID
	prev := r.st.Get(key)
	if prev != file {
		_ = r.st.Set(key, file)
	}
	return file, prev != "" && prev != file, nil
}

// pickLog is the file a log monitor on path reads (dir: path is a directory
// and file its newest log), refusing a secret.
func (r *Runner) pickLog(s Spec, path string) (file string, dir bool, err error) {
	st, err := os.Stat(r.env.Path(path))
	if err != nil {
		return "", false, err
	}
	if !st.IsDir() {
		return path, false, r.refuseSecret(path)
	}
	var nameRe *regexp.Regexp
	if s.FilePattern != "" {
		if nameRe, err = r.re(s.FilePattern); err != nil {
			return "", false, err
		}
	}
	entries, err := os.ReadDir(r.env.Path(path))
	if err != nil {
		return "", false, err
	}
	var best string
	var bestTime time.Time
	for _, e := range entries {
		name := e.Name()
		if !e.Type().IsRegular() || (nameRe != nil && !nameRe.MatchString(name)) {
			continue
		}
		if nameRe == nil && archiveRe.MatchString(name) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if best == "" || info.ModTime().After(bestTime) {
			best, bestTime = name, info.ModTime()
		}
	}
	if best == "" {
		return "", false, fmt.Errorf("no log file in %s", path)
	}
	file = filepath.Join(path, best)
	return file, true, r.refuseSecret(file)
}

// evalLog counts lines matching s.Pattern in what was appended since the last
// check, in total or per group_by value, or with new_values reports values it
// has not seen before.
func (r *Runner) evalLog(s Spec) (bool, string) {
	path, err := r.expand(s.Path)
	if err != nil {
		return true, err.Error() // a stopped service is not a log alert
	}
	file, fresh, err := r.logFile(s, path)
	if err != nil {
		return true, "log unreadable: " + err.Error() // absence is not a failure
	}
	lines, err := sensors.TailNewAs(r.env, "monitor:"+s.ID, file, fresh)
	if err != nil {
		return true, "log unreadable: " + err.Error()
	}
	re, err := r.re(s.Pattern)
	if err != nil {
		return false, err.Error()
	}
	var group *regexp.Regexp
	if s.GroupBy != "" {
		if group, err = r.re(s.GroupBy); err != nil {
			return false, err.Error()
		}
	}
	if s.NewValues {
		return r.newValues(s, file, re, group, lines)
	}
	keyOf := func(l string) string {
		if group == nil {
			return ""
		}
		if m := group.FindStringSubmatch(l); len(m) > 1 {
			return m[1]
		}
		return "?"
	}

	now := time.Now()
	window := time.Duration(s.WindowSeconds) * time.Second
	samples := map[string]string{}
	r.mu.Lock()
	for _, l := range lines {
		if !re.MatchString(l) {
			continue
		}
		k := keyOf(l)
		r.logs[s.ID+"\x00"+k] = append(r.logs[s.ID+"\x00"+k], now)
		if samples[k] == "" {
			samples[k] = l
		}
	}
	type over struct {
		key string
		n   int
	}
	var hot []over
	total := 0
	for k, hits := range r.logs {
		g, ok := strings.CutPrefix(k, s.ID+"\x00")
		if !ok {
			continue
		}
		cut := 0
		for cut < len(hits) && now.Sub(hits[cut]) > window {
			cut++
		}
		if hits = hits[cut:]; len(hits) == 0 {
			delete(r.logs, k)
			continue
		}
		r.logs[k] = hits
		total += len(hits)
		if len(hits) >= s.Threshold {
			hot = append(hot, over{g, len(hits)})
			delete(r.logs, k) // report once, then count afresh
		}
	}
	if len(hot) > 0 {
		r.fail[s.ID] = s.ConsecutiveFailures - 1 // log alerts are instant
	}
	r.mu.Unlock()
	if len(hot) == 0 {
		if group != nil {
			return true, fmt.Sprintf("%d matches in window across all groups, none over %d (reading %s)", total, s.Threshold, file)
		}
		return true, fmt.Sprintf("%d matches in window (reading %s)", total, file)
	}
	sort.Slice(hot, func(i, j int) bool { return hot[i].n > hot[j].n })
	if group == nil {
		return false, fmt.Sprintf("%d matches in %s in %s; sample: %s", hot[0].n, window, file, truncate(samples[""], 500))
	}
	var parts []string
	for i, h := range hot {
		if i == 5 {
			parts = append(parts, fmt.Sprintf("… %d more", len(hot)-5))
			break
		}
		p := fmt.Sprintf("%s: %d matches in %s", h.key, h.n, window)
		if smp := samples[h.key]; smp != "" {
			p += "; sample: " + truncate(smp, 300)
		}
		parts = append(parts, p)
	}
	return false, "in " + file + ": " + strings.Join(parts, " | ")
}

// newValues reports group values in matching lines that the monitor has not
// seen before. The first run learns the values already in the file.
func (r *Runner) newValues(s Spec, file string, re, group *regexp.Regexp, lines []string) (bool, string) {
	key := "monitor_seen:" + s.ID
	seen := map[string]bool{}
	var list []string
	if v := r.st.Get(key); v != "" {
		_ = json.Unmarshal([]byte(v), &list)
	} else if s.KnownValues != nil {
		list = append(list, *s.KnownValues...)
	} else if b, err := readHead(r.env.Path(file), 8<<20); err == nil {
		// First sight: what the log already shows is the known population.
		for _, l := range strings.Split(string(b), "\n") {
			if m := group.FindStringSubmatch(l); len(m) > 1 && re.MatchString(l) && !seen[m[1]] {
				seen[m[1]] = true
				list = append(list, m[1])
			}
		}
	}
	for _, v := range list {
		seen[v] = true
	}
	var fresh []string
	sample := ""
	for _, l := range lines {
		if !re.MatchString(l) {
			continue
		}
		m := group.FindStringSubmatch(l)
		if len(m) < 2 || seen[m[1]] {
			continue
		}
		seen[m[1]] = true
		list = append(list, m[1])
		fresh = append(fresh, m[1])
		if sample == "" {
			sample = l
		}
	}
	if len(list) > maxSeen {
		list = list[len(list)-maxSeen:]
	}
	b, _ := json.Marshal(list)
	_ = r.st.Set(key, string(b))
	if len(fresh) == 0 {
		return true, fmt.Sprintf("no new values (%d known; reading %s)", len(list), file)
	}
	r.mu.Lock()
	r.fail[s.ID] = s.ConsecutiveFailures - 1
	r.mu.Unlock()
	if len(fresh) > 10 {
		fresh = append(fresh[:10], fmt.Sprintf("… %d more", len(fresh)-10))
	}
	return false, fmt.Sprintf("first time seen in %s: %s; sample: %s", file, strings.Join(fresh, ", "), truncate(sample, 500))
}

// readHead reads up to n bytes from the start of path.
func readHead(path string, n int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, n))
}

// LogBacktest runs a log monitor's pattern over the end of the log it would
// read (up to 2 MB) and says what it finds, so a pattern can be checked
// against today's traffic before the monitor is saved: a pattern that
// already matches legitimate requests needs tightening.
func (r *Runner) LogBacktest(s Spec) string {
	return hostexec.Redact(r.logBacktest(s))
}

func (r *Runner) logBacktest(s Spec) string {
	path, err := r.expand(s.Path)
	if err != nil {
		return "backtest: " + err.Error()
	}
	file, err := r.newestLog(s, path)
	if err != nil {
		return "backtest: " + err.Error()
	}
	b, err := readTail(r.env.Path(file), 2<<20)
	if err != nil {
		return "backtest: " + err.Error()
	}
	re, err := r.re(s.Pattern)
	if err != nil {
		return "backtest: " + err.Error()
	}
	var group *regexp.Regexp
	if s.GroupBy != "" {
		if group, err = r.re(s.GroupBy); err != nil {
			return "backtest: " + err.Error()
		}
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	counts := map[string]int{}
	matches := 0
	sample := ""
	for _, l := range lines {
		if !re.MatchString(l) {
			continue
		}
		matches++
		if sample == "" {
			sample = l
		}
		if group != nil {
			k := "?"
			if m := group.FindStringSubmatch(l); len(m) > 1 {
				k = m[1]
			}
			counts[k]++
		}
	}
	out := fmt.Sprintf("backtest on the last %d lines of %s: %d matching", len(lines), file, matches)
	if group != nil && len(counts) > 0 {
		type kv struct {
			k string
			n int
		}
		var top []kv
		for k, n := range counts {
			top = append(top, kv{k, n})
		}
		sort.Slice(top, func(i, j int) bool { return top[i].n > top[j].n || top[i].n == top[j].n && top[i].k < top[j].k })
		var parts []string
		for i, t := range top {
			if i == 5 {
				parts = append(parts, fmt.Sprintf("… %d more", len(top)-5))
				break
			}
			parts = append(parts, fmt.Sprintf("%s=%d", t.k, t.n))
		}
		out += fmt.Sprintf(" from %d distinct values (%s)", len(counts), strings.Join(parts, ", "))
		if s.NewValues && s.KnownValues == nil {
			out += "; these values count as known when the monitor starts unless known_values says otherwise"
		} else if s.NewValues {
			var fresh []string
			known := map[string]bool{}
			for _, v := range *s.KnownValues {
				known[v] = true
			}
			for _, t := range top {
				if !known[t.k] {
					fresh = append(fresh, t.k)
				}
			}
			sort.Strings(fresh)
			if len(fresh) > 0 {
				out += "; not in known_values, so they alert on their next matching line: " + strings.Join(fresh, ", ")
			}
		} else if top[0].n >= s.Threshold {
			out += fmt.Sprintf("; at least %s reaches the threshold of %d over the whole period", top[0].k, s.Threshold)
		}
	} else if !s.NewValues && matches >= s.Threshold {
		out += fmt.Sprintf("; at least %d over the whole period, the threshold", s.Threshold)
	}
	if sample != "" {
		out += "; first match: " + truncate(sample, 300)
	}
	return out
}

// newestLog is the file logFile would read, without recording it (the
// backtest runs without a store).
func (r *Runner) newestLog(s Spec, path string) (string, error) {
	file, _, err := r.pickLog(s, path)
	return file, err
}

// refuseSecret stops a log monitor from reading a secret: its matching
// lines reach findings and monitor_test's output. file is checked as named
// and after resolving symlinks, since a log path may be a directory, contain
// {pid:…} or be a link.
func (r *Runner) refuseSecret(file string) error {
	if hostexec.IsSecretPath(file) {
		return fmt.Errorf("%s is a secret path", file)
	}
	if real, err := filepath.EvalSymlinks(r.env.Path(file)); err == nil && hostexec.IsSecretPath(real) {
		return fmt.Errorf("%s resolves to a secret path", file)
	}
	return nil
}

// readTail reads up to n bytes from the end of path, from a line start.
func readTail(path string, n int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	off := st.Size() - n
	if off < 0 {
		off = 0
	}
	b := make([]byte, st.Size()-off)
	k, err := f.ReadAt(b, off)
	if k == 0 && err != nil && err != io.EOF {
		return nil, err
	}
	b = b[:k]
	if off > 0 {
		if i := strings.IndexByte(string(b), '\n'); i >= 0 {
			b = b[i+1:]
		}
	}
	return b, nil
}
