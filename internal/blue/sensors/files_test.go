package sensors

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setuidFile(t *testing.T, root, path string) {
	t.Helper()
	full := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(full, 0o755|os.ModeSetuid); err != nil {
		t.Fatal(err)
	}
}

// stopAfter is a context whose Err turns non-nil after n checks: a walk that
// runs out of time part-way.
type stopAfter struct {
	context.Context
	n int
}

func (c *stopAfter) Err() error {
	if c.n <= 0 {
		return context.DeadlineExceeded
	}
	c.n--
	return nil
}

func TestSUIDWalkOrderAndOverlap(t *testing.T) {
	root := t.TempDir()
	setuidFile(t, root, "/var/tmp/.x/sh")
	setuidFile(t, root, "/usr/local/bin/helper")
	setuidFile(t, root, "/usr/bin/sudo")
	items, _, err := suidCollector{}.Collect(context.Background(), &Env{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, it := range items {
		keys = append(keys, it.Key)
	}
	// High-risk roots first, nested roots walked once.
	want := "/var/tmp/.x/sh,/usr/local/bin/helper,/usr/bin/sudo"
	if strings.Join(keys, ",") != want {
		t.Fatalf("got %v, want %s", keys, want)
	}
}

func TestSUIDWalkTimeoutIsReported(t *testing.T) {
	root := t.TempDir()
	setuidFile(t, root, "/tmp/.x/sh")
	for i := 0; i < 50; i++ {
		setuidFile(t, root, filepath.Join("/usr/bin", "f"+itoa(i)))
	}
	items, _, err := walkSUID(&stopAfter{Context: context.Background(), n: 12}, &Env{Root: root}, suidRoots)
	if !errors.Is(err, ErrPartial) || !strings.Contains(err.Error(), "/usr") {
		t.Fatalf("a truncated walk must say so and name what it missed, got %v", err)
	}
	if len(items) == 0 || items[0].Key != "/tmp/.x/sh" {
		t.Fatalf("the high-risk roots must be covered before the timeout, got %+v", items)
	}
}

type partialCollector struct{}

func (partialCollector) Name() string { return "suid" }
func (partialCollector) Every() int   { return 1 }
func (partialCollector) Collect(ctx context.Context, env *Env) ([]Item, []Event, error) {
	return []Item{{Key: "/tmp/.x/sh", Value: "setuid"}}, nil, errors.Join(ErrPartial, errors.New("walk stopped"))
}

func TestSweepKeepsPartialItemsButNotRan(t *testing.T) {
	r := &Registry{collectors: []Collector{partialCollector{}}}
	snap := r.Sweep(context.Background(), &Env{Root: t.TempDir()}, true)
	if len(snap.Items) != 1 || snap.Items[0].Collector != "suid" {
		t.Fatalf("partial items dropped: %+v", snap.Items)
	}
	if len(snap.Ran) != 0 || snap.Errors["suid"] == "" {
		t.Fatalf("partial collector must be reported, not counted as ran: ran=%v errors=%v", snap.Ran, snap.Errors)
	}
}
