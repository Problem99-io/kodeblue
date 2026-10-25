// Package sensors is kodeblue's zero-token layer: deterministic collectors that
// read the host's security-relevant state straight from /proc, /etc and the
// package database. A sweep runs every collector and returns a Snapshot of
// normalized Items. Nothing here talks to a model; the baseline and detector
// decide what (if anything) in a snapshot is worth a model's attention.
package sensors

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Item is one observed fact. Key is a stable identity that deliberately leaves
// out volatile parts (PIDs, ephemeral ports, timestamps) so the same thing
// observed twice gets the same key. Value is the part whose change matters
// (a hash, an owner, a mode). Attrs carries context for humans and models.
type Item struct {
	Collector string            `json:"collector"`
	Key       string            `json:"key"`
	Value     string            `json:"value,omitempty"`
	Attrs     map[string]string `json:"attrs,omitempty"`
}

// ID is the globally unique identity of an item across collectors.
func (i Item) ID() string { return i.Collector + "|" + i.Key }

// Event is a point-in-time occurrence (a login, a sudo, a useradd) read from
// logs. Events are not baselined as state; they are scored individually.
type Event struct {
	Collector string            `json:"collector"`
	Kind      string            `json:"kind"`
	Time      time.Time         `json:"time"`
	Subject   string            `json:"subject"` // user, IP, path — the thing it is about
	Message   string            `json:"message"`
	Attrs     map[string]string `json:"attrs,omitempty"`
}

// Snapshot is the result of one sweep.
type Snapshot struct {
	Taken    time.Time         `json:"taken"`
	Items    []Item            `json:"items"`
	Events   []Event           `json:"events,omitempty"`
	Errors   map[string]string `json:"errors,omitempty"` // collector -> error
	Duration time.Duration     `json:"duration"`
	// Ran lists the collectors that produced a full result this sweep. Items of
	// a collector that did not run must not be reported as "disappeared".
	Ran []string `json:"ran"`
}

// Env lets collectors run against a different root (tests, or a host
// filesystem mounted into a container at /host).
type Env struct {
	Root   string // "/" normally
	Logger *slog.Logger
	State  *CursorStore // log offsets, so events are read once
	Pkg    *PackageIndex
}

// Path joins a host-absolute path onto the configured root.
func (e *Env) Path(p string) string {
	if e.Root == "" || e.Root == "/" {
		return p
	}
	return filepath.Join(e.Root, p)
}

// Collector produces items and/or events.
type Collector interface {
	Name() string
	// Every reports how many base sweeps apart this collector runs. Expensive
	// collectors (filesystem walks) run every N sweeps; cheap ones every sweep.
	Every() int
	Collect(ctx context.Context, env *Env) ([]Item, []Event, error)
}

// CollectTimeout bounds one collector run. Collectors that watch their
// context return what they have by then; one blocked in a read the kernel
// does not interrupt (hung storage, a dead network filesystem) is left
// running and reported stuck, so it cannot stop the sweep.
const CollectTimeout = 60 * time.Second

// collectGrace is how long a collector has after its timeout to return.
const collectGrace = 2 * time.Second

// ErrPartial marks a collector error that still came with usable items (a
// walk cut short by its timeout that returned what it had reached). The items
// are kept and the error is reported, but the collector does not count as
// having run, so nothing it did not reach is treated as gone. A collector
// that never returns at all is reported stuck (see collect), not partial.
var ErrPartial = errors.New("partial result")

// Registry holds the enabled collectors.
type Registry struct {
	collectors []Collector
	sweep      int
	off        map[string]bool
	// timeout and grace are CollectTimeout and collectGrace unless a test
	// shortens them.
	timeout time.Duration
	grace   time.Duration
	mu      sync.Mutex
	stuck   map[string]*stuckRun
}

// stuckRun is a collector run that outlived its timeout. It keeps going on
// its own goroutine; the collector is not started again until it returns,
// and the next sweep that has the collector due uses its late result.
type stuckRun struct {
	since time.Time
	done  bool
	res   collectResult
}

type collectResult struct {
	items  []Item
	events []Event
	err    error
}

// Stuck lists the collectors whose run has not returned, with when it
// started.
func (r *Registry) Stuck() map[string]time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[string]time.Time{}
	for name, s := range r.stuck {
		if !s.done {
			out[name] = s.since
		}
	}
	return out
}

// SetOff turns collectors off (or back on) for later sweeps. Their baseline
// items are left alone: detection only compares collectors that ran.
func (r *Registry) SetOff(names map[string]bool) { r.off = names }

// NewRegistry returns the default collector set, filtered by the enabled list
// (empty = all) and with critical file paths extended by extraFiles.
func NewRegistry(enabled []string, extraFiles []string) *Registry {
	all := []Collector{
		&processCollector{},
		&listenerCollector{},
		&outboundCollector{},
		&accountCollector{},
		&sshKeyCollector{},
		&persistenceCollector{},
		&integrityCollector{extra: extraFiles},
		&suidCollector{},
		&moduleCollector{},
		&packageCollector{},
		&tmpExecCollector{},
		&containerCollector{},
		&authLogCollector{},
		&loadCollector{},
	}
	if len(enabled) == 0 {
		return &Registry{collectors: all}
	}
	want := map[string]bool{}
	for _, n := range enabled {
		want[strings.TrimSpace(n)] = true
	}
	var out []Collector
	for _, c := range all {
		if want[c.Name()] {
			out = append(out, c)
		}
	}
	return &Registry{collectors: out}
}

// Names lists the collectors in the registry.
func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.collectors))
	for _, c := range r.collectors {
		out = append(out, c.Name())
	}
	return out
}

// Sweep runs the collectors that are due this sweep. force runs every
// collector regardless of cadence (learning, on-demand).
func (r *Registry) Sweep(ctx context.Context, env *Env, force bool) Snapshot {
	start := time.Now()
	r.sweep++
	snap := Snapshot{Taken: start, Errors: map[string]string{}}
	if env.Pkg == nil {
		env.Pkg = LoadPackageIndex(env)
	}
	for _, c := range r.collectors {
		if r.off[c.Name()] {
			continue
		}
		if !force && c.Every() > 1 && (r.sweep-1)%c.Every() != 0 {
			continue
		}
		res := r.collect(ctx, c, env)
		items, events, err := res.items, res.events, res.err
		if err != nil {
			snap.Errors[c.Name()] = err.Error()
			if env.Logger != nil {
				env.Logger.Debug("collector failed", "collector", c.Name(), "error", err)
			}
			if !errors.Is(err, ErrPartial) {
				continue
			}
		}
		for idx := range items {
			items[idx].Collector = c.Name()
		}
		for idx := range events {
			events[idx].Collector = c.Name()
		}
		snap.Items = append(snap.Items, items...)
		snap.Events = append(snap.Events, events...)
		if err == nil {
			snap.Ran = append(snap.Ran, c.Name())
		}
	}
	sort.Slice(snap.Items, func(a, b int) bool { return snap.Items[a].ID() < snap.Items[b].ID() })
	snap.Items = dedupe(snap.Items)
	snap.Duration = time.Since(start)
	return snap
}

// collect runs c within the timeout, or hands back the late result of an
// earlier run that was stuck.
func (r *Registry) collect(ctx context.Context, c Collector, env *Env) collectResult {
	name := c.Name()
	r.mu.Lock()
	if s := r.stuck[name]; s != nil {
		defer r.mu.Unlock()
		if !s.done {
			return collectResult{err: fmt.Errorf("stuck: its run from %s has not returned (a read that never completes: hung storage or network filesystem?)", s.since.UTC().Format(time.RFC3339))}
		}
		delete(r.stuck, name)
		return s.res
	}
	r.mu.Unlock()
	start := time.Now()
	timeout, grace := r.timeout, r.grace
	if timeout <= 0 {
		timeout = CollectTimeout
	}
	if grace <= 0 {
		grace = collectGrace
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	out := make(chan collectResult, 1)
	go func() {
		defer cancel()
		var res collectResult
		res.items, res.events, res.err = safeCollect(cctx, c, env)
		out <- res
	}()
	select {
	case res := <-out:
		return res
	case <-cctx.Done():
	}
	select {
	case res := <-out:
		return res
	case <-time.After(grace):
	}
	s := &stuckRun{since: start}
	r.mu.Lock()
	if r.stuck == nil {
		r.stuck = map[string]*stuckRun{}
	}
	r.stuck[name] = s
	r.mu.Unlock()
	go func() {
		res := <-out
		r.mu.Lock()
		s.done, s.res = true, res
		r.mu.Unlock()
	}()
	if env.Logger != nil {
		env.Logger.Warn("collector stuck: sweeping without it until it returns", "collector", name, "after", timeout)
	}
	return collectResult{err: fmt.Errorf("stuck: no result after %s; skipped until it returns", timeout)}
}

func safeCollect(ctx context.Context, c Collector, env *Env) (items []Item, events []Event, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("collector panic: %v", r)
		}
	}()
	return c.Collect(ctx, env)
}

func dedupe(items []Item) []Item {
	if len(items) < 2 {
		return items
	}
	out := items[:1]
	for _, it := range items[1:] {
		if it.ID() == out[len(out)-1].ID() {
			continue
		}
		out = append(out, it)
	}
	return out
}

// hashFile returns the hex sha256 of a file, or "" if unreadable.
func hashFile(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	buf := make([]byte, 64*1024)
	for {
		n, rerr := f.Read(buf)
		h.Write(buf[:n])
		if rerr != nil {
			break
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

func hashString(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func short(h string) string {
	if len(h) > 16 {
		return h[:16]
	}
	return h
}
