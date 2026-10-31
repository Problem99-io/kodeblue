package hublink

import (
	"testing"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
)

type sharedAgent struct {
	phaseAgent
	changed int
}

func (a *sharedAgent) SharedBlocksChanged() { a.changed++ }

// A list of shared blocks is kept and handed to the daemon once per
// version, and only where root accepts shared blocks; the status reports
// the version kept, so the hub sends the next one only when it changes.
func TestSharedBlocksSavedOncePerVersion(t *testing.T) {
	l, _ := newSettingsLink(t)
	a := &sharedAgent{phaseAgent: phaseAgent{phase: "watching"}}
	l.agent = a
	sb := &hubproto.SharedBlocks{Version: "v1", Blocks: []hubproto.SharedBlock{{ID: "sb_1", IP: "203.0.113.7", Server: "web-1", At: time.Now()}}}
	l.saveSharedBlocks(sb)
	l.saveSharedBlocks(sb)
	if a.changed != 1 {
		t.Fatalf("SharedBlocksChanged calls: %d", a.changed)
	}
	if got := LoadSharedBlocks(l.st); got.Version != "v1" || len(got.Blocks) != 1 || got.Blocks[0].IP != "203.0.113.7" {
		t.Fatalf("saved: %+v", got)
	}
	if s := l.status(); !s.AcceptsSharedBlocks || s.SharedBlocksVersion != "v1" {
		t.Fatalf("status: %v %q", s.AcceptsSharedBlocks, s.SharedBlocksVersion)
	}

	l.cfg.Hub.AcceptSharedBlocks = false
	l.saveSharedBlocks(&hubproto.SharedBlocks{Version: "v2"})
	if a.changed != 1 || LoadSharedBlocks(l.st).Version != "v1" {
		t.Fatal("a list was taken with accept_shared_blocks = false")
	}
	if s := l.status(); s.AcceptsSharedBlocks || s.SharedBlocksVersion != "" {
		t.Fatalf("status without shared blocks: %v %q", s.AcceptsSharedBlocks, s.SharedBlocksVersion)
	}
}
