package main

import (
	"context"
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

type controlledQueueProvider struct {
	mu        sync.Mutex
	requests  []*provider.Request
	started   chan int
	gates     []chan struct{}
	responses map[int][]provider.StreamEvent
}

func newControlledQueueProvider(turns int) *controlledQueueProvider {
	gates := make([]chan struct{}, turns)
	for i := range gates {
		gates[i] = make(chan struct{})
	}
	return &controlledQueueProvider{started: make(chan int, turns), gates: gates}
}

func (p *controlledQueueProvider) Name() string { return "controlled-queue" }

func (p *controlledQueueProvider) Stream(ctx context.Context, req *provider.Request) (<-chan provider.StreamEvent, error) {
	p.mu.Lock()
	index := len(p.requests)
	copyReq := *req
	copyReq.Messages = append([]internal.Message(nil), req.Messages...)
	p.requests = append(p.requests, &copyReq)
	response := p.responses[index]
	p.mu.Unlock()
	ch := make(chan provider.StreamEvent, 2)
	go func() {
		defer close(ch)
		ch <- provider.StreamEvent{Type: provider.EventToken, Content: "partial "}
		p.started <- index
		select {
		case <-ctx.Done():
			return
		case <-p.gates[index]:
			for _, event := range response {
				ch <- event
			}
			ch <- provider.StreamEvent{Type: provider.EventDone, Usage: &provider.Usage{}}
		}
	}()
	return ch, nil
}

func (p *controlledQueueProvider) CountTokens(context.Context, *provider.Request) (*provider.Usage, error) {
	return &provider.Usage{}, nil
}

func (p *controlledQueueProvider) release(index int) { close(p.gates[index]) }

func (p *controlledQueueProvider) awaitStart(t *testing.T, want int) {
	t.Helper()
	select {
	case got := <-p.started:
		if got != want {
			t.Fatalf("provider start = %d, want %d", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for provider turn %d", want)
	}
}

func (p *controlledQueueProvider) request(index int) *provider.Request {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.requests[index]
}

type sessionQueueRig struct {
	db       *state.DB
	events   *state.EventRepo
	adapter  *agentLoopAdapter
	provider *controlledQueueProvider
	queue    *state.QueueRepo
	runs     *state.RunRepo
	messages *state.MessageRepo
	session  internal.SessionID
}

func newSessionQueueRig(t *testing.T, turns int) *sessionQueueRig {
	t.Helper()
	db, err := state.NewDB(t.TempDir() + "/queue.db")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	cfg := policy.DefaultConfig()
	cfg.Paths.ProjectRoot = t.TempDir()
	toolGuard, err := policy.NewToolGuard(cfg)
	if err != nil {
		t.Fatal(err)
	}
	providerImpl := newControlledQueueProvider(turns)
	providers := provider.NewRegistry()
	providers.Register(providerImpl.Name(), providerImpl)
	events := state.NewEventRepo(db)
	eventSink := func(event internal.Event) { _ = events.Append(&event) }
	// The loop and adapter share one registry so tests can register tools.
	toolRegistry := tools.NewRegistry()
	loop := agent.NewLoop(toolRegistry, toolGuard, nil, eventSink)
	sessions := state.NewSessionRepo(db)
	runs := state.NewRunRepo(db)
	messages := state.NewMessageRepo(db)
	queue := state.NewQueueRepo(db)
	session := &internal.Session{
		ID: internal.NewSessionID(), Status: internal.SessionActive,
		Provider: providerImpl.Name(), Model: "test-model", CWD: cfg.Paths.ProjectRoot,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := sessions.Create(session); err != nil {
		t.Fatal(err)
	}
	logger := &logging.Logger{Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))}
	adapter := &agentLoopAdapter{
		loop: loop, providerRegistry: providers, toolRegistry: toolRegistry, cfg: cfg,
		sessionRepo: sessions, agentRepo: state.NewAgentRepo(db), runRepo: runs,
		messageRepo: messages, queueRepo: queue, eventSink: eventSink, logger: logger,
	}
	return &sessionQueueRig{db: db, events: events, adapter: adapter, provider: providerImpl, queue: queue, runs: runs, messages: messages, session: session.ID}
}

func (r *sessionQueueRig) awaitRunStatus(t *testing.T, runID internal.RunID, want internal.RunStatus) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		run, err := r.runs.Get(runID)
		if err == nil && run != nil && run.Status == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("run %s did not reach %s", runID, want)
}

func TestSessionQueueExplicitDeliveryRecoversRunLeftByExitedRuntime(t *testing.T) {
	for _, action := range []string{"steer", "continue"} {
		t.Run(action, func(t *testing.T) {
			rig := newSessionQueueRig(t, 1)
			orphan := &internal.Run{ID: internal.NewRunID(), SessionID: rig.session, Status: internal.RunRunning, CreatedAt: time.Now().Add(-48 * time.Hour)}
			if err := rig.runs.Create(orphan); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 5; i++ {
				if _, _, err := rig.queue.EnqueueUnique(&internal.QueueItem{SessionID: rig.session, Source: internal.QueueItemSourceUser, ClientMessageID: fmt.Sprintf("client-%d", i), Content: fmt.Sprintf("pending item %d", i)}); err != nil {
					t.Fatal(err)
				}
			}
			if err := rig.queue.SetPaused(rig.session, action == "continue"); err != nil {
				t.Fatal(err)
			}
			var result api.QueueActionResult
			var err error
			if action == "steer" {
				result, err = rig.adapter.Steer(rig.session)
			} else {
				result, err = rig.adapter.Continue(rig.session)
			}
			if err != nil || result.Status != "started" {
				t.Fatalf("deliver five queued items after restart: %#v, %v", result, err)
			}
			rig.provider.awaitStart(t, 0)
			request := rig.provider.request(0)
			body := request.Messages[len(request.Messages)-1].Content
			for i := 0; i < 5; i++ {
				if strings.Count(body, fmt.Sprintf("pending item %d", i)) != 1 {
					t.Fatalf("item %d not delivered exactly once: %s", i, body)
				}
			}
			if pending, err := rig.queue.PendingCount(rig.session); err != nil || pending != 0 {
				t.Fatalf("pending = %d, %v", pending, err)
			}
			old, err := rig.runs.Get(orphan.ID)
			if err != nil || old.Status != internal.RunFailed || old.CompletedAt == nil {
				t.Fatalf("orphan run was not recovered: %#v, %v", old, err)
			}
			rig.provider.release(0)
			rig.awaitRunStatus(t, result.RunID, internal.RunCompleted)
		})
	}
}

func TestSessionQueueBatchesCurrentSnapshotAndDefersLaterArrivals(t *testing.T) {
	rig := newSessionQueueRig(t, 3)
	first, err := rig.adapter.SubmitUser(rig.session, "start", "client-1", nil, api.RunOptions{})
	if err != nil || first.Status != "started" {
		t.Fatalf("start first turn: %#v, %v", first, err)
	}
	rig.provider.awaitStart(t, 0)

	// A queued message carrying a model switch (clients may send a selection
	// with nearly every message) must wait for the turn to end.
	if queued, err := rig.adapter.SubmitUser(rig.session, "user follow-up", "client-2", []internal.Attachment{{MediaType: "text/plain", FileName: "note.txt", Data: "cGF5bG9hZA=="}}, api.RunOptions{Model: "new-model", ReasoningEffort: "high"}); err != nil || queued.Status != "queued" {
		t.Fatalf("queue user: %#v, %v", queued, err)
	}
	runs, err := rig.runs.GetBySession(rig.session)
	if err != nil || len(runs) != 1 || runs[0].ID != first.RunID || runs[0].Status != internal.RunRunning {
		t.Fatalf("queued message interrupted or replaced the turn: runs=%+v err=%v", runs, err)
	}

	// When the turn ends, the user message starts a fresh turn on its model.
	rig.provider.release(0)
	rig.awaitRunStatus(t, first.RunID, internal.RunCompleted)
	rig.provider.awaitStart(t, 1)
	userRequest := rig.provider.request(1)
	userMessage := userRequest.Messages[len(userRequest.Messages)-1]
	if userMessage.Content != "user follow-up" || userRequest.Model != "new-model" || len(userMessage.Attachments) != 1 {
		t.Fatalf("queued user turn: model=%q message=%+v", userRequest.Model, userMessage)
	}

	// Anything arriving after this snapshot waits for another run.
	if _, err := rig.adapter.SubmitUser(rig.session, "arrived during batch", "client-3", nil, api.RunOptions{}); err != nil {
		t.Fatal(err)
	}
	rig.provider.release(1)
	rig.provider.awaitStart(t, 2)
	third := rig.provider.request(2).Messages
	if got := third[len(third)-1].Content; got != "arrived during batch" {
		t.Fatalf("unexpected third batch:\n%s", got)
	}
	rig.provider.release(2)
}

func TestSessionQueueStopPausesAndContinueReleases(t *testing.T) {
	rig := newSessionQueueRig(t, 2)
	first, err := rig.adapter.SubmitUser(rig.session, "start", "", nil, api.RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	rig.provider.awaitStart(t, 0)
	if _, err := rig.adapter.SubmitUser(rig.session, "hold this", "", nil, api.RunOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := rig.adapter.Pause(rig.session); err != nil {
		t.Fatal(err)
	}
	if !rig.adapter.Abort(string(first.RunID)) {
		t.Fatal("abort did not find active run")
	}
	rig.awaitRunStatus(t, first.RunID, internal.RunAborted)
	select {
	case turn := <-rig.provider.started:
		t.Fatalf("paused queue unexpectedly started turn %d", turn)
	case <-time.After(100 * time.Millisecond):
	}
	if count, _ := rig.queue.PendingCount(rig.session); count != 1 {
		t.Fatalf("pending after stop = %d, want 1", count)
	}
	continued, err := rig.adapter.Continue(rig.session)
	if err != nil || continued.Status != "started" {
		t.Fatalf("continue: %#v, %v", continued, err)
	}
	rig.provider.awaitStart(t, 1)
	rig.provider.release(1)
}

func TestSessionQueueSteerInterruptsAndPreservesPartialOutput(t *testing.T) {
	rig := newSessionQueueRig(t, 2)
	first, err := rig.adapter.SubmitUser(rig.session, "start", "", nil, api.RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	rig.provider.awaitStart(t, 0)
	// Provider enqueue precedes recovery forwarding. Wait for actual persisted
	// model output before asserting that a subsequent steer preserves it.
	deadline := time.Now().Add(5 * time.Second)
	observed := false
	for time.Now().Before(deadline) {
		events, err := rig.events.GetByRun(first.RunID)
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range events {
			if event.Type == internal.EventModelToken {
				observed = true
			}
		}
		if observed {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !observed {
		t.Fatal("timed out waiting for persisted assistant prefix")
	}
	if _, err := rig.adapter.SubmitUser(rig.session, "steer now", "", nil, api.RunOptions{}); err != nil {
		t.Fatal(err)
	}
	action, err := rig.adapter.Steer(rig.session)
	if err != nil || action.Status != "interrupting" {
		t.Fatalf("steer: %#v, %v", action, err)
	}
	rig.awaitRunStatus(t, first.RunID, internal.RunInterrupted)
	rig.provider.awaitStart(t, 1)
	messages, err := rig.messages.GetAllBySession(rig.session)
	if err != nil {
		t.Fatal(err)
	}
	foundPartial := false
	for _, message := range messages {
		if message.Role == "assistant" && strings.Contains(message.Content, "partial") {
			foundPartial = true
		}
	}
	if !foundPartial {
		t.Fatal("steer discarded the streamed assistant prefix")
	}
	rig.provider.release(1)
}

func TestImmediateCallerNeverLeavesHiddenQueuedMessage(t *testing.T) {
	rig := newSessionQueueRig(t, 2)
	first, err := rig.adapter.SubmitUser(rig.session, "first", "first", nil, api.RunOptions{RejectIfBusy: true})
	if err != nil || first.Status != "started" {
		t.Fatalf("first: %#v %v", first, err)
	}
	rig.provider.awaitStart(t, 0)
	if _, err := rig.adapter.SubmitUser(rig.session, "must not arrive later", "rejected", nil, api.RunOptions{RejectIfBusy: true}); err == nil {
		t.Fatal("busy message accepted")
	}
	if n, _ := rig.queue.PendingCount(rig.session); n != 0 {
		t.Fatal("rejected message was queued")
	}
	rig.provider.release(0)
	rig.awaitRunStatus(t, first.RunID, internal.RunCompleted)
	if err := rig.adapter.Pause(rig.session); err != nil {
		t.Fatal(err)
	}
	second, err := rig.adapter.SubmitUser(rig.session, "new explicit turn", "new-turn", nil, api.RunOptions{RejectIfBusy: true})
	if err != nil || second.Status != "started" {
		t.Fatalf("resume empty: %#v %v", second, err)
	}
	rig.provider.awaitStart(t, 1)
	rig.provider.release(1)
	rig.awaitRunStatus(t, second.RunID, internal.RunCompleted)
}

// A new explicit user message resumes both old pending input and itself in a
// single FIFO turn. Detached reports cannot slip between resume and enqueue.
func TestSessionQueueExplicitMessageResumesStoppedInbox(t *testing.T) {
	rig := newSessionQueueRig(t, 2)
	first, err := rig.adapter.SubmitUser(rig.session, "start", "first", nil, api.RunOptions{Resume: true})
	if err != nil {
		t.Fatal(err)
	}
	rig.provider.awaitStart(t, 0)
	if err := rig.adapter.StopSession(rig.session, func() error { rig.adapter.Abort(string(first.RunID)); return nil }); err != nil {
		t.Fatal(err)
	}
	rig.awaitRunStatus(t, first.RunID, internal.RunAborted)
	if _, err := rig.queue.Enqueue(&internal.QueueItem{SessionID: rig.session, Source: internal.QueueItemSourceUser, Heading: "User message", Content: "saved evidence"}); err != nil {
		t.Fatal(err)
	}
	result, err := rig.adapter.SubmitUser(rig.session, "new direction", "next", nil, api.RunOptions{Resume: true})
	if err != nil || result.Status != "started" {
		t.Fatalf("send=%#v err=%v", result, err)
	}
	rig.provider.awaitStart(t, 1)
	messages := rig.provider.request(1).Messages
	content := messages[len(messages)-1].Content
	if !strings.Contains(content, "new direction") || !strings.Contains(content, "saved evidence") {
		t.Fatalf("lost batch input: %s", content)
	}
	rig.provider.release(1)
	rig.awaitRunStatus(t, result.RunID, internal.RunCompleted)
}

func TestSessionQueueSendNowInterruptsAndDeliversOnce(t *testing.T) {
	rig := newSessionQueueRig(t, 2)
	first, err := rig.adapter.SubmitUser(rig.session, "old direction", "old", nil, api.RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	rig.provider.awaitStart(t, 0)
	// The interrupt can end the old run before SubmitUser checks whether the
	// session is busy: then it starts the new run itself ("started"), otherwise
	// drainQueue starts it when the old run finishes ("queued"). Either way the
	// message is delivered once.
	sent, err := rig.adapter.SubmitUser(rig.session, "new direction", "new", nil, api.RunOptions{Resume: true, SteerNow: true})
	if err != nil || (sent.Status != "queued" && sent.Status != "started") {
		t.Fatalf("send now: %#v %v", sent, err)
	}
	rig.provider.awaitStart(t, 1)
	rig.awaitRunStatus(t, first.RunID, internal.RunInterrupted)
	duplicate, err := rig.adapter.SubmitUser(rig.session, "new direction", "new", nil, api.RunOptions{Resume: true, SteerNow: true})
	if err != nil || duplicate.RunID == "" {
		t.Fatalf("idempotent replay: %#v %v", duplicate, err)
	}
	if sent.Status == "started" && duplicate.RunID != sent.RunID {
		t.Fatalf("replay run=%s, want the started run %s", duplicate.RunID, sent.RunID)
	}
	if count, _ := rig.queue.PendingCount(rig.session); count != 0 {
		t.Fatalf("duplicate pending=%d", count)
	}
	if runs, _ := rig.runs.GetBySession(rig.session); len(runs) != 2 {
		t.Fatalf("runs=%d, want the interrupted run and one delivery", len(runs))
	}
	rig.provider.release(1)
	rig.awaitRunStatus(t, duplicate.RunID, internal.RunCompleted)
}

func TestSessionQueueStopSerializesWithNewSend(t *testing.T) {
	rig := newSessionQueueRig(t, 1)
	entered, release := make(chan struct{}), make(chan struct{})
	stopDone := make(chan error, 1)
	go func() {
		stopDone <- rig.adapter.StopSession(rig.session, func() error { close(entered); <-release; return nil })
	}()
	<-entered
	sent := make(chan api.QueueSubmitResult, 1)
	errs := make(chan error, 1)
	go func() {
		res, err := rig.adapter.SubmitUser(rig.session, "after stop", "unique", nil, api.RunOptions{Resume: true})
		sent <- res
		errs <- err
	}()
	select {
	case <-sent:
		t.Fatal("send passed an unfinished stop")
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	if err := <-stopDone; err != nil {
		t.Fatal(err)
	}
	res := <-sent
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
	rig.provider.awaitStart(t, 0)
	rig.provider.release(0)
	rig.awaitRunStatus(t, res.RunID, internal.RunCompleted)
	if paused, _ := rig.queue.IsPaused(rig.session); paused {
		t.Fatal("new send was stranded by older Stop")
	}
}

func TestUndeliverableQueuedMessagePausesWithReasonInsteadOfRetryingForever(t *testing.T) {
	rig := newSessionQueueRig(t, 1)
	rig.adapter.queueFailureGrace = time.Millisecond
	session, err := rig.adapter.sessionRepo.Get(rig.session)
	if err != nil {
		t.Fatal(err)
	}
	original := session.Provider
	session.Provider = "removed-provider"
	if err := rig.adapter.sessionRepo.Update(session); err != nil {
		t.Fatal(err)
	}
	submitted, err := rig.adapter.SubmitUser(rig.session, "hello", "m1", nil, api.RunOptions{})
	if err != nil || (submitted.Status != "queued" && submitted.Status != "paused") {
		t.Fatalf("submit=%+v err=%v", submitted, err)
	}
	failedRuns := func() int {
		runs, _ := rig.runs.GetBySession(rig.session)
		count := 0
		for _, run := range runs {
			if run.Status == internal.RunFailed {
				count++
			}
		}
		return count
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		paused, _ := rig.queue.IsPaused(rig.session)
		if paused {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("missing provider never paused the queue")
		}
		time.Sleep(20 * time.Millisecond)
	}
	reason, _ := rig.queue.FailureReason(rig.session)
	if !strings.Contains(reason, "provider not available: removed-provider") {
		t.Fatalf("failure reason=%q", reason)
	}
	attempts := failedRuns()
	time.Sleep(2500 * time.Millisecond)
	if got := failedRuns(); got != attempts {
		t.Fatalf("paused queue kept retrying: failed runs %d -> %d", attempts, got)
	}
	if pending, _ := rig.queue.PendingCount(rig.session); pending != 1 {
		t.Fatalf("undeliverable message left the queue: pending=%d", pending)
	}

	// Once fixed, Continue delivers the same message and clears the reason.
	session.Provider = original
	if err := rig.adapter.sessionRepo.Update(session); err != nil {
		t.Fatal(err)
	}
	continued, err := rig.adapter.Continue(rig.session)
	if err != nil || continued.Status != "started" {
		t.Fatalf("continue=%+v err=%v", continued, err)
	}
	if reason, _ := rig.queue.FailureReason(rig.session); reason != "" {
		t.Fatalf("resume kept failure reason %q", reason)
	}
	rig.provider.awaitStart(t, 0)
	rig.provider.release(0)
	rig.awaitRunStatus(t, continued.RunID, internal.RunCompleted)
}

func TestRejectedDispatchPausesImmediatelyAndReportsReason(t *testing.T) {
	rig := newSessionQueueRig(t, 1)
	if _, err := rig.queue.Enqueue(&internal.QueueItem{SessionID: rig.session, Source: internal.QueueItemSourceUser, Content: "switch to a small model"}); err != nil {
		t.Fatal(err)
	}
	rig.adapter.queueMu.Lock()
	paused := rig.adapter.handleDispatchFailureLocked(rig.session, rejectRun(fmt.Errorf("model switch blocked: conversation exceeds context window")))
	rig.adapter.queueMu.Unlock()
	reason, _ := rig.queue.FailureReason(rig.session)
	if !paused || !strings.Contains(reason, "model switch blocked") {
		t.Fatalf("paused=%v reason=%q", paused, reason)
	}
	// A transient error retries (deduplicated here so no timer outlives the
	// test) instead of pausing.
	rig.adapter.queueMu.Lock()
	rig.adapter.queueRetryPending = map[internal.SessionID]bool{rig.session: true}
	paused = rig.adapter.handleDispatchFailureLocked(rig.session, fmt.Errorf("database is locked"))
	attempts := rig.adapter.queueFailures[rig.session].attempts
	rig.adapter.queueMu.Unlock()
	if paused || attempts != 1 {
		t.Fatalf("transient failure paused=%v attempts=%d", paused, attempts)
	}
}
