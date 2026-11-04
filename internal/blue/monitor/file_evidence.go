package monitor

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Problem99-io/kodeblue/internal/blue/hostexec"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

type fileObservation struct {
	states  map[string]string
	changes []store.FileChange
}

// evalFiles keeps the existing fileState, preview and target selection. Only
// reference persistence is staged so the compared evidence cannot be lost.
func (r *Runner) evalFiles(s Spec) (bool, string) {
	observation := &fileObservation{states: map[string]string{}}
	var previews []string
	var targets []Reflex
	for _, path := range s.Paths {
		real, err := r.expand(path)
		if err != nil {
			return false, err.Error()
		}
		hash, listing := r.fileState(r.env.Path(real))
		key := "monitor_file:" + s.ID + ":" + path
		before, err := r.st.ReadState(key)
		if err != nil {
			return false, "file evidence: cannot read reference"
		}
		oldListing, err := r.st.ReadState(key + ":ls")
		if err != nil {
			return false, "file evidence: cannot read listing"
		}
		observation.states[key], observation.states[key+":ls"] = hash, listing
		if before == "" || before == "unreadable" && strings.HasPrefix(hash, "dir:") {
			continue
		}
		if before == hash {
			continue
		}
		what := path
		if delta := diffListings(splitLines(oldListing), splitLines(listing)); delta != "" {
			what += " (" + delta + ")"
		}
		if tail := appended(r.env.Path(real), splitLines(oldListing), splitLines(listing)); tail != "" {
			what += "; " + tail
		}
		previews = append(previews, what)
		observation.changes = append(observation.changes, comparedChanges(path, before, hash, oldListing, listing)...)
		for _, rel := range newFiles(splitLines(oldListing), splitLines(listing)) {
			targets = append(targets, Reflex{Action: "quarantine_file", Params: map[string]string{"path": real + "/" + rel}, Why: fmt.Sprintf("new file %s appeared in %s", rel, path)})
		}
	}
	// Bound retained evidence, not its display preview. Do not advance references
	// when it cannot be saved. Existing severity and failure routing still apply.
	at := time.Now().UTC().Format(time.RFC3339Nano)
	for i := range observation.changes {
		observation.changes[i].ObservedAt = at
	}
	data, err := json.Marshal(observation.changes)
	if err != nil || len(data) > 4<<20 {
		return false, "file evidence exceeds 4 MiB; reference retained"
	}
	r.fileObservation = observation
	r.targets = targets
	if len(previews) > 0 {
		r.mu.Lock()
		r.fail[s.ID] = s.ConsecutiveFailures - 1
		r.mu.Unlock()
		return false, "changed: " + strings.Join(previews, ", ")
	}
	return true, "unchanged"
}

func comparedChanges(path, before, after, oldListing, listing string) []store.FileChange {
	var changes []store.FileChange
	if strings.HasPrefix(before, "dir:") && strings.HasPrefix(after, "dir:") {
		entries := func(ls string) (map[string]string, bool) {
			m := map[string]string{}
			for _, line := range splitLines(ls) {
				name, _, _ := strings.Cut(line, "\t")
				if strings.Count(line, "\t") != 3 || !utf8.ValidString(line) {
					return nil, false
				}
				if _, exists := m[name]; exists {
					return nil, false
				}
				m[name] = line
			}
			return m, true
		}
		old, oldOK := entries(oldListing)
		cur, curOK := entries(listing)
		if !oldOK || !curOK {
			// Unusual names can make the old listing format ambiguous. Preserve
			// raw line differences instead of overwriting colliding parsed names.
			changes = comparedLines(path, oldListing, listing)
		} else {
			names := map[string]bool{}
			for n := range old {
				names[n] = true
			}
			for n := range cur {
				names[n] = true
			}
			ordered := make([]string, 0, len(names))
			for n := range names {
				ordered = append(ordered, n)
			}
			sort.Strings(ordered)
			for _, name := range ordered {
				if old[name] != cur[name] {
					changes = append(changes, store.FileChange{Path: path, Name: name, Kind: "entry", Before: old[name], After: cur[name]})
				}
			}
		}
	} else {
		// A file, disappearance, or file/directory transition is represented by the
		// exact signatures compared by the existing evaluator, plus entry changes
		// when a directory listing is available on either side.
		changes = append(changes, store.FileChange{Path: path, Kind: "signature", Before: before, After: after})
		if oldListing != "" || listing != "" {
			changes = append(changes, comparedChanges(path, "dir:before", "dir:after", oldListing, listing)...)
		}
	}
	for i := range changes {
		c := &changes[i]
		if c.ObjectID == "" {
			c.ObjectID = hashStr(c.Path + "\x00" + c.Name + "\x00" + c.Kind)
		}
		c.Path = hostexec.Redact(c.Path)
		c.Name = hostexec.Redact(c.Name)
		c.Before = hostexec.Redact(c.Before)
		c.After = hostexec.Redact(c.After)
		if !utf8.ValidString(c.Before) || !utf8.ValidString(c.After) {
			c.Encoding = "base64"
			c.Before = base64.StdEncoding.EncodeToString([]byte(c.Before))
			c.After = base64.StdEncoding.EncodeToString([]byte(c.After))
		}
	}
	return changes
}

func comparedLines(path, before, after string) []store.FileChange {
	counts := map[string]int{}
	for _, line := range splitLines(before) {
		counts[line]--
	}
	for _, line := range splitLines(after) {
		counts[line]++
	}
	lines := make([]string, 0, len(counts))
	for line := range counts {
		lines = append(lines, line)
	}
	sort.Strings(lines)
	var changes []store.FileChange
	for _, line := range lines {
		count := counts[line]
		for count != 0 {
			c := store.FileChange{Path: path, Kind: "listing_line", ObjectID: hashStr(path + "\x00listing_line\x00" + line)}
			if count < 0 {
				c.Before = line
				count++
			} else {
				c.After = line
				count--
			}
			changes = append(changes, c)
		}
	}
	return changes
}
