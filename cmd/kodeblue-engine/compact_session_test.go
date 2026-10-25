package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
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

// summaryGateProvider answers ordinary turns at once and holds every
// compaction summary request until release is closed (or the request is
// cancelled), signalling summaryStarted when one begins.
type summaryGateProvider struct {
	summaryStarted chan struct{}
	release        chan struct{}
	reply          string
	once           sync.Once
}

func isSummaryRequest(req *provider.Request) bool {
	if len(req.Messages) == 0 {
		return false
	}
	return strings.HasPrefix(req.Messages[len(req.Messages)-1].Content, "The conversation so far is approaching the context window.")
}

func (p *summaryGateProvider) Name() string { return "gate" }

func (p *summaryGateProvider) Stream(ctx context.Context, req *provider.Request) (<-chan provider.StreamEvent, error) {
	ch := make(chan provider.StreamEvent, 4)
	summary := isSummaryRequest(req)
	go func() {
		defer close(ch)
		if !summary {
			ch <- provider.StreamEvent{Type: provider.EventToken, Content: p.reply}
			ch <- provider.StreamEvent{Type: provider.EventDone, Usage: &provider.Usage{InputTokens: 10, OutputTokens: 2}}
			return
		}
		ch <- provider.StreamEvent{Type: provider.EventToken, Content: "Current Task:\n- triage sshd brute force"}
		p.once.Do(func() { close(p.summaryStarted) })
		select {
		case <-p.release:
			ch <- provider.StreamEvent{Type: provider.EventDone}
		case <-ctx.Done():
		}
	}()
	return ch, nil
}

func (p *summaryGateProvider) CountTokens(context.Context, *provider.Request) (*provider.Usage, error) {
	return &provider.Usage{InputTokens: 40_000}, nil
}

type compactRig struct {
	db       *state.DB
	adapter  *agentLoopAdapter
	messages *state.MessageRepo
	runs     *state.RunRepo
	events   *state.EventRepo
	provider *summaryGateProvider
	session  *internal.Session
}

func newCompactRig(t *testing.T, seed int) *compactRig {
	t.Helper()
	db, err := state.NewDB(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	slogger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	cfg := policy.DefaultConfig()
	cfg.Paths.ProjectRoot = t.TempDir()
	guard, err := policy.NewToolGuard(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p := &summaryGateProvider{summaryStarted: make(chan struct{}), release: make(chan struct{}), reply: "answer"}
	registry := provider.NewRegistry()
	registry.Register("gate", p)
	events := state.NewEventRepo(db)
	sink := func(e internal.Event) { _ = events.Append(&e) }
	compactor := agent.NewCompactor(cfg.Agent.CompactionThresholdRatio, "", sink)
	toolRegistry := tools.NewRegistry()
	rig := &compactRig{
		db:       db,
		messages: state.NewMessageRepo(db),
		runs:     state.NewRunRepo(db),
		events:   events,
		provider: p,
	}
	rig.adapter = &agentLoopAdapter{
		loop:             agent.NewLoop(toolRegistry, guard, compactor, sink),
		compactor:        compactor,
		providerRegistry: registry,
		toolRegistry:     toolRegistry,
		cfg:              cfg,
		sessionRepo:      state.NewSessionRepo(db),
		agentRepo:        state.NewAgentRepo(db),
		runRepo:          rig.runs,
		messageRepo:      rig.messages,
		queueRepo:        state.NewQueueRepo(db),
		eventSink:        sink,
		logger:           &logging.Logger{Logger: slogger},
	}
	now := time.Now()
	rig.session = &internal.Session{ID: internal.NewSessionID(), Status: internal.SessionActive, Provider: "gate", Model: "m", CreatedAt: now, UpdatedAt: now}
	if err := rig.adapter.sessionRepo.Create(rig.session); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < seed; i++ {
		role := "user"
		if i%2 == 1 {
			role = "assistant"
		}
		m := &internal.Message{ID: internal.NewMessageID(), Role: role, Content: fmt.Sprintf("seed-%d %s", i, strings.Repeat("auth log evidence ", 300)), CreatedAt: now}
		if err := rig.messages.Create(rig.session.ID, "", m); err != nil {
			t.Fatal(err)
		}
	}
	return rig
}

func (r *compactRig) active(t *testing.T) []internal.Message {
	t.Helper()
	got, err := r.messages.GetBySession(r.session.ID)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func (r *compactRig) awaitIdle(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		runs, err := r.runs.GetBySession(r.session.ID)
		if err != nil {
			t.Fatal(err)
		}
		busy := false
		for _, run := range runs {
			if run.Status == internal.RunRunning {
				busy = true
			}
		}
		if !busy {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("session never became idle")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestManualCompactionDuringNewMessageKeepsTheMessage(t *testing.T) {
	rig := newCompactRig(t, 30)
	type outcome struct {
		result api.CompactResult
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		result, err := rig.adapter.CompactSession(context.Background(), string(rig.session.ID), api.RunOptions{})
		done <- outcome{result, err}
	}()
	<-rig.provider.summaryStarted

	// A user message arrives while the summary is being written: it must
	// queue, not start a run against the history being rewritten.
	submitted, err := rig.adapter.SubmitUser(rig.session.ID, "NEW-QUESTION what about 198.51.100.9?", "", nil, api.RunOptions{InputSource: "direct_message"})
	if err != nil {
		t.Fatal(err)
	}
	if submitted.Status != "queued" {
		t.Fatalf("message during compaction was %q, want queued", submitted.Status)
	}
	// A caller that needs a run started now is refused, and nothing is queued.
	pendingBefore, _ := rig.adapter.queueRepo.PendingCount(rig.session.ID)
	if _, err := rig.adapter.SubmitUser(rig.session.ID, "must not queue", "", nil, api.RunOptions{RejectIfBusy: true}); err == nil {
		t.Fatal("reject_if_busy accepted a message while compaction held the session")
	}
	if pending, _ := rig.adapter.queueRepo.PendingCount(rig.session.ID); pending != pendingBefore {
		t.Fatalf("rejected message changed the inbox: %d -> %d", pendingBefore, pending)
	}
	if err := rig.adapter.RunAsync(string(rig.session.ID), string(internal.NewRunID()), "direct run", nil, api.RunOptions{}); err == nil {
		t.Fatal("a run started while compaction held the session")
	}
	// A writer that does not take the lease still cannot lose its message.
	stray := &internal.Message{ID: internal.NewMessageID(), Role: "user", Content: "STRAY-WRITE", CreatedAt: time.Now()}
	if err := rig.messages.Create(rig.session.ID, "", stray); err != nil {
		t.Fatal(err)
	}

	close(rig.provider.release)
	out := <-done
	if out.err != nil || !out.result.Compacted {
		t.Fatalf("compaction: %+v %v", out.result, out.err)
	}
	rig.awaitIdle(t)

	active := rig.active(t)
	if !agent.IsCompactionSummary(active[0].Content) {
		t.Fatalf("summary is not first on reload: %q", active[0].Content)
	}
	var joined strings.Builder
	for _, m := range active {
		joined.WriteString(m.Content + "\n")
	}
	for _, want := range []string{"STRAY-WRITE", "NEW-QUESTION", "answer"} {
		if !strings.Contains(joined.String(), want) {
			t.Fatalf("active history lost %q:\n%s", want, joined.String())
		}
	}
	// The queued question was delivered after the compaction, in order.
	last := active[len(active)-1]
	if last.Role != "assistant" || last.Content != "answer" {
		t.Fatalf("last active message = %s %q", last.Role, last.Content)
	}
}

func TestManualCompactionRefusedWhileSessionLeased(t *testing.T) {
	rig := newCompactRig(t, 30)
	lease, err := rig.runs.TryAcquireSessionRunLease(rig.session.ID)
	if err != nil || lease == nil {
		t.Fatalf("lease: %v", err)
	}
	defer lease.Release()
	_, err = rig.adapter.CompactSession(context.Background(), string(rig.session.ID), api.RunOptions{})
	if !errors.Is(err, api.ErrSessionBusy) {
		t.Fatalf("err = %v, want ErrSessionBusy", err)
	}
}

func TestManualCompactionCancelledKeepsHistory(t *testing.T) {
	rig := newCompactRig(t, 30)
	before := rig.active(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := rig.adapter.CompactSession(ctx, string(rig.session.ID), api.RunOptions{})
		done <- err
	}()
	<-rig.provider.summaryStarted
	cancel()
	if err := <-done; err == nil {
		t.Fatal("cancelled compaction reported success")
	}
	after := rig.active(t)
	if len(after) != len(before) {
		t.Fatalf("active history %d -> %d after a cancelled compaction", len(before), len(after))
	}
	for _, m := range after {
		if agent.IsCompactionSummary(m.Content) {
			t.Fatalf("cancelled compaction persisted a summary: %q", m.Content)
		}
	}
	// The lease was released: the session can run again.
	lease, err := rig.runs.TryAcquireSessionRunLease(rig.session.ID)
	if err != nil || lease == nil {
		t.Fatalf("lease not released after cancel: %v", err)
	}
	lease.Release()
}

func TestRunTranscriptSaveFailureFailsTheRun(t *testing.T) {
	rig := newCompactRig(t, 0)
	rig.provider.reply = "FAIL-PERSIST"
	if err := rig.db.Migrate(); err != nil {
		t.Fatal(err)
	}
	// Make the final transcript write fail the way a full disk would.
	if _, err := rig.db.Exec(`CREATE TRIGGER fail_persist BEFORE INSERT ON messages WHEN NEW.content = 'FAIL-PERSIST'
		BEGIN SELECT RAISE(ABORT, 'disk full'); END`); err != nil {
		t.Fatal(err)
	}
	runID := internal.NewRunID()
	if err := rig.runs.Create(&internal.Run{ID: runID, SessionID: rig.session.ID, Status: internal.RunRunning, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := rig.adapter.RunAsync(string(rig.session.ID), string(runID), "hello", nil, api.RunOptions{}); err != nil {
		t.Fatal(err)
	}
	rig.awaitIdle(t)
	run, err := rig.runs.Get(runID)
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != internal.RunFailed {
		t.Fatalf("run status = %s, want failed", run.Status)
	}
	terminal, err := rig.events.GetRunTerminal(rig.session.ID, runID)
	if err != nil || len(terminal) != 1 || terminal[0].Type != internal.EventRunFailed || !strings.Contains(string(terminal[0].Payload), "persist") {
		t.Fatalf("terminal event = %+v %v", terminal, err)
	}
}
