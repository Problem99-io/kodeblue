package api

import (
	"sync"
	"testing"
	"time"

	internal "github.com/Problem99-io/kodeblue/internal"
)

type dispatchGuardLoop struct {
	*mockAgentLoop
	mu      sync.Mutex
	entered chan struct{}
}

func (g *dispatchGuardLoop) LockSessionDispatch() func() {
	close(g.entered)
	g.mu.Lock()
	return g.mu.Unlock
}

func TestStatusCannotCombinePreDispatchRunWithPostDispatchQueue(t *testing.T) {
	deps, loop := setupTestDeps(t)
	id := internal.SessionID("dispatch-status")
	if err := deps.Sessions.Create(&internal.Session{ID: id, Status: internal.SessionActive, CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	guard := &dispatchGuardLoop{mockAgentLoop: loop, entered: make(chan struct{})}
	deps.AgentLoop = guard
	guard.mu.Lock() // Queue dispatch has consumed the report but has not claimed its loop run yet.
	unlocked := false
	defer func() {
		if !unlocked {
			guard.mu.Unlock()
		}
	}()
	result := make(chan *sessionRuntimeStatusResponse, 1)
	errors := make(chan error, 1)
	go func() {
		s, err := buildSessionRuntimeStatus(deps, id)
		if err != nil {
			errors <- err
			return
		}
		result <- s
	}()
	select {
	case s := <-result:
		t.Fatalf("status escaped an unfinished dispatch: %#v", s)
	case err := <-errors:
		t.Fatal(err)
	case <-guard.entered:
	case <-time.After(time.Second):
		t.Fatal("status never reached dispatch guard")
	}
	runID := internal.RunID("continuation")
	if err := deps.Runs.Create(&internal.Run{ID: runID, SessionID: id, Status: internal.RunRunning, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	loop.running[string(runID)] = true
	guard.mu.Unlock()
	unlocked = true
	select {
	case s := <-result:
		if !s.IsRunning || s.Status != "running" || s.ActiveRunID != string(runID) {
			t.Fatalf("continuation was reported terminal: %#v", s)
		}
	case err := <-errors:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("status did not resume after dispatch")
	}
}
