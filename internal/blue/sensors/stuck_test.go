package sensors

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// blocking ignores its context and waits for release, like a read on hung
// storage: the kernel does not interrupt it.
type blocking struct {
	release chan struct{}
	calls   atomic.Int32
}

func (*blocking) Name() string { return "blocking" }
func (*blocking) Every() int   { return 1 }
func (b *blocking) Collect(context.Context, *Env) ([]Item, []Event, error) {
	b.calls.Add(1)
	<-b.release
	return []Item{{Key: "late"}}, nil, nil
}

type quick struct{}

func (quick) Name() string { return "quick" }
func (quick) Every() int   { return 1 }
func (quick) Collect(context.Context, *Env) ([]Item, []Event, error) {
	return []Item{{Key: "now"}}, nil, nil
}

// patient watches its context and returns what it has at the deadline.
type patient struct{}

func (patient) Name() string { return "patient" }
func (patient) Every() int   { return 1 }
func (patient) Collect(ctx context.Context, _ *Env) ([]Item, []Event, error) {
	<-ctx.Done()
	return []Item{{Key: "partial"}}, nil, nil
}

func testRegistry(cs ...Collector) *Registry {
	return &Registry{collectors: cs, timeout: 50 * time.Millisecond, grace: 50 * time.Millisecond}
}

func keys(s Snapshot) map[string]bool {
	out := map[string]bool{}
	for _, it := range s.Items {
		out[it.ID()] = true
	}
	return out
}

func TestSweepGoesOnWithoutAStuckCollector(t *testing.T) {
	b := &blocking{release: make(chan struct{})}
	r := testRegistry(b, quick{})
	env := &Env{Pkg: &PackageIndex{}}

	start := time.Now()
	s := r.Sweep(context.Background(), env, false)
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("sweep waited %s for a stuck collector", took)
	}
	if !keys(s)["quick|now"] {
		t.Fatalf("the other collectors' items are missing: %v", s.Items)
	}
	if strings.Join(s.Ran, ",") != "quick" {
		t.Fatalf("ran = %v; a stuck collector must not count as ran (its items would read as gone)", s.Ran)
	}
	if !strings.Contains(s.Errors["blocking"], "stuck") {
		t.Fatalf("errors = %v", s.Errors)
	}
	if _, ok := r.Stuck()["blocking"]; !ok {
		t.Fatal("blocking not reported stuck")
	}

	// Still stuck: skipped, not started a second time.
	s = r.Sweep(context.Background(), env, false)
	if b.calls.Load() != 1 {
		t.Fatalf("stuck collector started %d times", b.calls.Load())
	}
	if !strings.Contains(s.Errors["blocking"], "has not returned") || !keys(s)["quick|now"] {
		t.Fatalf("second sweep: errors %v items %v", s.Errors, s.Items)
	}

	// The read returns: the next sweep takes the late result.
	close(b.release)
	deadline := time.Now().Add(2 * time.Second)
	for len(r.Stuck()) > 0 {
		if time.Now().After(deadline) {
			t.Fatal("still stuck after release")
		}
		time.Sleep(5 * time.Millisecond)
	}
	s = r.Sweep(context.Background(), env, false)
	if !keys(s)["blocking|late"] || len(s.Errors) != 0 {
		t.Fatalf("late result not used: items %v errors %v", s.Items, s.Errors)
	}
	if b.calls.Load() != 1 {
		t.Fatalf("late result ran the collector again (%d calls)", b.calls.Load())
	}

	// And it is back to normal.
	s = r.Sweep(context.Background(), env, false)
	if b.calls.Load() != 2 || !keys(s)["blocking|late"] {
		t.Fatalf("after recovery: %d calls, items %v", b.calls.Load(), s.Items)
	}
}

func TestCollectorThatWatchesItsContextIsNotStuck(t *testing.T) {
	r := testRegistry(patient{})
	s := r.Sweep(context.Background(), &Env{Pkg: &PackageIndex{}}, false)
	if !keys(s)["patient|partial"] || len(r.Stuck()) != 0 {
		t.Fatalf("items %v stuck %v errors %v", s.Items, r.Stuck(), s.Errors)
	}
}
