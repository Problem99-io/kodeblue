package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	internal "github.com/Problem99-io/kodeblue/internal"
	"github.com/Problem99-io/kodeblue/internal/agent"
	"github.com/Problem99-io/kodeblue/internal/api"
	"github.com/Problem99-io/kodeblue/internal/logging"
	"github.com/Problem99-io/kodeblue/internal/policy"
	"github.com/Problem99-io/kodeblue/internal/provider"
	"github.com/Problem99-io/kodeblue/internal/state"
	"github.com/Problem99-io/kodeblue/internal/tools"
)

// neverEndingProvider streams tokens forever until its context is cancelled —
// a stand-in for a long model turn the user wants to interrupt.
type neverEndingProvider struct{}

func (neverEndingProvider) Name() string { return "neverending" }

func (neverEndingProvider) Stream(ctx context.Context, _ *provider.Request) (<-chan provider.StreamEvent, error) {
	ch := make(chan provider.StreamEvent)
	go func() {
		defer close(ch)
		for {
			select {
			case <-ctx.Done():
				return
			case ch <- provider.StreamEvent{Type: provider.EventToken, Content: "tick "}:
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	return ch, nil
}

func (neverEndingProvider) CountTokens(_ context.Context, _ *provider.Request) (*provider.Usage, error) {
	return &provider.Usage{}, nil
}

// abortTestRig wires the REAL agent loop, the REAL agentLoopAdapter and the
// REAL HTTP router — the exact chain a UI "stop" travels through.
type abortTestRig struct {
	router    http.Handler
	runRepo   *state.RunRepo
	eventRepo *state.EventRepo
	loop      *agent.Loop
}

func newAbortTestRig(t *testing.T) *abortTestRig {
	t.Helper()

	projectRoot := t.TempDir()
	db, err := state.NewDB(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("create db: %v", err)
	}
	if err := db.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	sessionRepo := state.NewSessionRepo(db)
	runRepo := state.NewRunRepo(db)
	messageRepo := state.NewMessageRepo(db)
	queueRepo := state.NewQueueRepo(db)
	eventRepo := state.NewEventRepo(db)
	agentRepo := state.NewAgentRepo(db)

	slogger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	logger := &logging.Logger{Logger: slogger}

	cfg := policy.DefaultConfig()
	cfg.Paths.ProjectRoot = projectRoot
	toolGuard, err := policy.NewToolGuard(cfg)
	if err != nil {
		t.Fatalf("tool guard: %v", err)
	}

	providerRegistry := provider.NewRegistry()
	providerRegistry.Register("neverending", neverEndingProvider{})
	toolRegistry := tools.NewRegistry()

	eventHub := api.NewEventHub(slogger)
	eventSink := func(e internal.Event) { _ = eventRepo.Append(&e) }

	compactor := agent.NewCompactor(cfg.Agent.CompactionThresholdRatio, cfg.Agent.CompactionModel, eventSink)
	loop := agent.NewLoop(toolRegistry, toolGuard, compactor, eventSink)

	adapter := &agentLoopAdapter{
		loop:             loop,
		compactor:        compactor,
		providerRegistry: providerRegistry,
		toolRegistry:     toolRegistry,
		cfg:              cfg,
		sessionRepo:      sessionRepo,
		agentRepo:        agentRepo,
		runRepo:          runRepo,
		messageRepo:      messageRepo,
		queueRepo:        queueRepo,
		eventSink:        eventSink,
		logger:           logger,
	}

	deps := &api.Dependencies{
		DB:           db,
		Sessions:     sessionRepo,
		Runs:         runRepo,
		Messages:     messageRepo,
		Queue:        queueRepo,
		Events:       eventRepo,
		Questions:    state.NewPendingQuestionRepo(db),
		Providers:    providerRegistry,
		AgentLoop:    adapter,
		MessageQueue: adapter,
		EventHub:     eventHub,
		Logger:       slogger,
		ProjectRoot:  projectRoot,
	}

	return &abortTestRig{router: api.NewRouter(deps), runRepo: runRepo, eventRepo: eventRepo, loop: loop}
}

func (r *abortTestRig) do(t *testing.T, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	w := httptest.NewRecorder()
	r.router.ServeHTTP(w, httptest.NewRequest(method, path, reader))
	return w
}

// TestAbortStopsALiveRun is the regression test for the UI stop button: send a
// message that starts a long-running turn, then POST the abort endpoint the UI
// calls, and assert the run actually stops.
func TestAbortStopsALiveRun(t *testing.T) {
	rig := newAbortTestRig(t)

	w := rig.do(t, "POST", "/v1/sessions", map[string]any{"provider": "neverending", "model": "m"})
	if w.Code != http.StatusOK && w.Code != http.StatusCreated {
		t.Fatalf("create session: %d %s", w.Code, w.Body.String())
	}
	var session internal.Session
	json.NewDecoder(w.Body).Decode(&session)

	w = rig.do(t, "POST", "/v1/sessions/"+string(session.ID)+"/messages", map[string]any{"content": "go"})
	if w.Code != http.StatusAccepted {
		t.Fatalf("send message: %d %s", w.Code, w.Body.String())
	}
	var run internal.Run
	json.NewDecoder(w.Body).Decode(&run)

	// Wait until the run is genuinely inside the loop, not merely dispatched:
	// message.started is emitted from Run, after registration. This keeps the
	// test on the steady-state path; the dispatch window has its own test below.
	deadline := time.Now().Add(3 * time.Second)
	for !rig.runEmitted(t, run.ID, internal.EventMessageStarted) {
		if time.Now().After(deadline) {
			t.Fatal("run never became live")
		}
		time.Sleep(5 * time.Millisecond)
	}

	w = rig.do(t, "POST", "/v1/sessions/"+string(session.ID)+"/abort", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("abort returned %d: %s", w.Code, w.Body.String())
	}

	// The run must actually stop.
	deadline = time.Now().Add(5 * time.Second)
	for rig.loop.IsRunning(run.ID) {
		if time.Now().After(deadline) {
			t.Fatal("BUG: abort returned 200 but the run is still live 5s later")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// And its persisted status must be aborted, not left as running.
	rig.awaitRunStatus(t, run.ID, internal.RunAborted)
}

// TestAbortDuringRunStartupWindow covers pressing stop in the window between
// the run row being created with status=running and the loop goroutine
// registering the run's cancel func.
//
// This is the dangerous case: Loop.Abort returns false, so handleAbort takes
// its "stale row" branch — it marks the run aborted in the store and answers
// 200 OK. The goroutine then starts the agent anyway. From then on the run is
// live but no store row says running, so every later abort answers 409, which
// the backend maps to success. The run becomes permanently unstoppable.
func TestAbortDuringRunStartupWindow(t *testing.T) {
	rig := newAbortTestRig(t)

	w := rig.do(t, "POST", "/v1/sessions", map[string]any{"provider": "neverending", "model": "m"})
	var session internal.Session
	json.NewDecoder(w.Body).Decode(&session)

	w = rig.do(t, "POST", "/v1/sessions/"+string(session.ID)+"/messages", map[string]any{"content": "go"})
	if w.Code != http.StatusAccepted {
		t.Fatalf("send message: %d %s", w.Code, w.Body.String())
	}
	var run internal.Run
	json.NewDecoder(w.Body).Decode(&run)

	// Abort immediately — do NOT wait for the loop to register.
	w = rig.do(t, "POST", "/v1/sessions/"+string(session.ID)+"/abort", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("abort returned %d: %s", w.Code, w.Body.String())
	}

	// The abort reported success, so the run must actually be dead.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if !rig.loop.IsRunning(run.ID) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("BUG: abort answered 200 OK but the run started anyway and is still live — it can never be stopped, every later abort answers 409 which the backend reports as success")
		}
		time.Sleep(10 * time.Millisecond)
	}

	rig.awaitRunStatus(t, run.ID, internal.RunAborted)

	// A run stopped during dispatch must take the same path as one stopped a
	// moment later: the user's message is still recorded, and run.aborted fires.
	events, err := rig.eventRepo.GetByRun(run.ID)
	if err != nil {
		t.Fatalf("get events: %v", err)
	}
	seen := map[string]bool{}
	for _, e := range events {
		seen[e.Type] = true
	}
	if !seen[internal.EventMessageStarted] {
		t.Error("BUG: the user's message was dropped for a run stopped during dispatch")
	}
	if !seen[internal.EventRunAborted] {
		t.Error("BUG: no run.aborted event — the SSE bridge never finalizes and the UI stays running")
	}
}

func (r *abortTestRig) runEmitted(t *testing.T, runID internal.RunID, eventType string) bool {
	t.Helper()
	events, err := r.eventRepo.GetByRun(runID)
	if err != nil {
		t.Fatalf("get events: %v", err)
	}
	for _, e := range events {
		if e.Type == eventType {
			return true
		}
	}
	return false
}

func (r *abortTestRig) awaitRunStatus(t *testing.T, runID internal.RunID, want internal.RunStatus) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		stored, err := r.runRepo.Get(runID)
		if err != nil {
			t.Fatalf("get run: %v", err)
		}
		if stored.Status == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("BUG: run status is %q, expected %q", stored.Status, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
