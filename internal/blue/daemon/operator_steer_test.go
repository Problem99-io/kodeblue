package daemon

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
	"github.com/Problem99-io/kodeblue/internal/blue/runtime"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

type modeledSession struct {
	running    bool
	generation int
	changed    chan struct{}
}

// This model follows the actual queue semantics: idle steering starts a run,
// busy FollowUp waits for dispatch, Wait follows one run, WaitSession follows all.
type operatorSteerEngine struct {
	*fakeEngine
	mu                                            sync.Mutex
	sessions                                      map[string]*modeledSession
	started, followed, waiting, aborting, costing chan string
	follows, steers, idleSteers, queued, aborts   atomic.Int32
	beforeReturn                                  func(string)
	beforeTimeout                                 func(string)
	startGate                                     chan struct{}
	messages                                      []string
	steerErr                                      error
	costGate, abortGate, followGate               chan struct{}
}

func newOperatorEngine() *operatorSteerEngine {
	f := &operatorSteerEngine{fakeEngine: &fakeEngine{id: 1}, sessions: map[string]*modeledSession{}, started: make(chan string, 64), followed: make(chan string, 64), waiting: make(chan string, 64), aborting: make(chan string, 64), costing: make(chan string, 64)}
	f.alive.Store(true)
	return f
}
func (f *operatorSteerEngine) add(id string, running bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sessions[id] = &modeledSession{running: running, generation: 1, changed: make(chan struct{})}
}
func (f *operatorSteerEngine) change(s *modeledSession, running bool) {
	s.running = running
	close(s.changed)
	s.changed = make(chan struct{})
}
func (f *operatorSteerEngine) finish(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.change(f.sessions[id], false)
}
func (f *operatorSteerEngine) StartSession(ctx context.Context, a, p, m, body string) (*runtime.Session, error) {
	if f.startGate != nil {
		select {
		case <-f.startGate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	s, err := f.fakeEngine.StartSession(ctx, a, p, m, body)
	if err != nil {
		return nil, err
	}
	f.add(s.ID, true)
	f.started <- s.ID
	return s, nil
}
func (f *operatorSteerEngine) SessionBusy(ctx context.Context, id string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.sessions[id]
	return s != nil && s.running, nil
}
func (f *operatorSteerEngine) FollowUp(ctx context.Context, s *runtime.Session, body string) (*runtime.Session, error) {
	f.follows.Add(1)
	if f.followGate != nil {
		f.followed <- s.ID
		select {
		case <-f.followGate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	for {
		f.mu.Lock()
		state := f.sessions[s.ID]
		if state == nil {
			state = &modeledSession{changed: make(chan struct{})}
			f.sessions[s.ID] = state
		}
		if !state.running {
			state.generation++
			f.change(state, true)
			f.mu.Unlock()
			if f.followGate == nil {
				f.followed <- s.ID
			}
			return &runtime.Session{ID: s.ID, RunID: fmt.Sprint(state.generation)}, nil
		}
		changed := state.changed
		f.mu.Unlock()
		f.queued.Add(1)
		select {
		case <-changed:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}
func (f *operatorSteerEngine) Steer(ctx context.Context, s *runtime.Session, body string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	state := f.sessions[s.ID]
	if state == nil {
		return errors.New("unknown session")
	}
	f.steers.Add(1)
	f.messages = append(f.messages, body)
	if !state.running {
		f.idleSteers.Add(1)
	}
	state.generation++
	f.change(state, true)
	return f.steerErr
}
func (f *operatorSteerEngine) WaitSession(ctx context.Context, s *runtime.Session, timeout time.Duration) runtime.Outcome {
	f.waiting <- s.ID
	timer := time.NewTimer(max(timeout, 0))
	defer timer.Stop()
	for {
		f.mu.Lock()
		state := f.sessions[s.ID]
		if !state.running {
			hook := f.beforeReturn
			f.beforeReturn = nil
			f.mu.Unlock()
			if hook != nil {
				hook(s.ID)
			}
			return runtime.Outcome{Status: "completed", Text: "answer:" + s.ID}
		}
		changed := state.changed
		f.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return f.timeout(s.ID)
		case <-timer.C:
			return f.timeout(s.ID)
		}
	}
}
func (f *operatorSteerEngine) Wait(ctx context.Context, s *runtime.Session, timeout time.Duration) runtime.Outcome {
	f.mu.Lock()
	generation := f.sessions[s.ID].generation
	f.mu.Unlock()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		f.mu.Lock()
		state := f.sessions[s.ID]
		if !state.running || state.generation != generation {
			f.mu.Unlock()
			return runtime.Outcome{Status: "completed", Text: "decisions:" + s.ID}
		}
		changed := state.changed
		f.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return runtime.Outcome{Status: "timeout"}
		case <-timer.C:
			return runtime.Outcome{Status: "timeout"}
		}
	}
}
func (f *operatorSteerEngine) Abort(ctx context.Context, id string) error {
	f.aborts.Add(1)
	f.aborting <- id
	if f.abortGate != nil {
		select {
		case <-f.abortGate:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if state := f.sessions[id]; state != nil {
		f.change(state, false)
	}
	return nil
}
func (f *operatorSteerEngine) SessionCost(ctx context.Context, id string) (float64, int, int, int) {
	if f.costGate != nil {
		f.costing <- id
		select {
		case <-f.costGate:
		case <-ctx.Done():
			return 0, 0, 0, 0
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	n := f.sessions[id].generation
	return float64(n) * 0.01, n * 100, n * 10, 0
}
func receiveOperator(t *testing.T, ch <-chan string) string {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(2 * time.Second):
		t.Fatal("operator engine event timed out")
		return ""
	}
}
func operatorMessage(id int64, conv string) hubproto.OperatorMessage {
	return hubproto.OperatorMessage{ID: id, Author: "alice", Body: "input", ConversationID: conv}
}
func operatorIncident(t *testing.T, st *store.Store, kind, sid string) *store.Incident {
	t.Helper()
	in := &store.Incident{Title: kind, Kind: kind, Severity: "high"}
	if err := st.CreateIncident(in); err != nil {
		t.Fatal(err)
	}
	in.SessionID, in.Status = sid, "needs_human"
	if err := st.UpdateIncident(in); err != nil {
		t.Fatal(err)
	}
	return in
}

func TestOperatorInputSteersSameConversationAcrossIdleCompletion(t *testing.T) {
	d, st, _, _ := newTestDaemon(t)
	f := newOperatorEngine()
	d.setEngine(f)
	wait := d.BeginOperatorMessage(context.Background(), operatorMessage(1, "a"))
	sid := receiveOperator(t, f.started)
	receiveOperator(t, f.waiting)
	if reply := d.BeginOperatorMessage(context.Background(), operatorMessage(2, "a"))(); reply.Status != "done" || reply.SessionID != sid {
		t.Fatalf("running steer: %+v", reply)
	}
	f.mu.Lock()
	f.beforeReturn = func(string) {
		reply := d.BeginOperatorMessage(context.Background(), operatorMessage(3, "a"))()
		if reply.Status != "done" {
			t.Errorf("boundary steer: %+v", reply)
		}
	}
	f.mu.Unlock()
	f.finish(sid)
	receiveOperator(t, f.waiting)
	f.finish(sid)
	if reply := wait(); reply.Status != "done" || reply.SessionID != sid {
		t.Fatalf("reply: %+v", reply)
	}
	d.wg.Wait()
	if f.n.Load() != 1 || f.steers.Load() != 2 || f.idleSteers.Load() != 1 {
		t.Fatalf("continuations lost: starts=%d steers=%d idle=%d", f.n.Load(), f.steers.Load(), f.idleSteers.Load())
	}
	if st.Get("hub_conv_a") != sid || len(d.LiveSessions()) != 0 {
		t.Fatal("conversation tracking failed")
	}
}
func TestOperatorBookingQueuesSameAndOtherConversations(t *testing.T) {
	d, _, _, _ := newTestDaemon(t)
	f := newOperatorEngine()
	f.costGate = make(chan struct{})
	d.setEngine(f)
	first := d.BeginOperatorMessage(context.Background(), operatorMessage(1, "a"))
	sid := receiveOperator(t, f.started)
	receiveOperator(t, f.waiting)
	f.finish(sid)
	receiveOperator(t, f.costing)
	second := d.BeginOperatorMessage(context.Background(), operatorMessage(2, "a"))
	third := d.BeginOperatorMessage(context.Background(), operatorMessage(3, "b"))
	if f.n.Load() != 1 || f.follows.Load() != 0 {
		t.Fatal("work started before previous booking")
	}
	close(f.costGate)
	if reply := first(); reply.Status != "done" {
		t.Fatalf("first: %+v", reply)
	}
	if got := receiveOperator(t, f.followed); got != sid {
		t.Fatal("same conversation lost its session")
	}
	receiveOperator(t, f.waiting)
	f.finish(sid)
	if reply := second(); reply.Status != "done" {
		t.Fatalf("booking follow-up refused: %+v", reply)
	}
	other := receiveOperator(t, f.started)
	receiveOperator(t, f.waiting)
	f.finish(other)
	if reply := third(); reply.Status != "done" || reply.SessionID == sid {
		t.Fatalf("queued conversation: %+v", reply)
	}
	d.wg.Wait()
}
func TestOperatorCompletedAnswerSurvivesAdmissionLockPastDeadline(t *testing.T) {
	old := operatorWaitTimeout
	operatorWaitTimeout = 100 * time.Millisecond
	t.Cleanup(func() { operatorWaitTimeout = old })
	d, _, _, _ := newTestDaemon(t)
	f := newOperatorEngine()
	d.setEngine(f)
	wait := d.BeginOperatorMessage(context.Background(), operatorMessage(1, "a"))
	sid := receiveOperator(t, f.started)
	receiveOperator(t, f.waiting)
	observed := make(chan struct{})
	f.mu.Lock()
	f.beforeReturn = func(string) { close(observed) }
	f.mu.Unlock()
	d.operatorMu.Lock()
	f.finish(sid)
	<-observed
	time.Sleep(120 * time.Millisecond)
	d.operatorMu.Unlock()
	if reply := wait(); reply.Status != "done" || reply.Text != "answer:"+sid || f.aborts.Load() != 0 {
		t.Fatalf("completed answer timed out: %+v", reply)
	}
	d.wg.Wait()
}
func TestOperatorDeadlineAbortsBeforeReleasingOwnership(t *testing.T) {
	old := operatorWaitTimeout
	operatorWaitTimeout = 20 * time.Millisecond
	t.Cleanup(func() { operatorWaitTimeout = old })
	d, _, _, _ := newTestDaemon(t)
	f := newOperatorEngine()
	f.abortGate = make(chan struct{})
	d.setEngine(f)
	first := d.BeginOperatorMessage(context.Background(), operatorMessage(1, "a"))
	sid := receiveOperator(t, f.started)
	receiveOperator(t, f.aborting)
	if _, live := d.LiveSessions()[sid]; !live {
		t.Fatal("session untracked before Abort completed")
	}
	next := d.BeginOperatorMessage(context.Background(), operatorMessage(2, "b"))
	if f.n.Load() != 1 {
		t.Fatal("new turn started before Abort")
	}
	close(f.abortGate)
	if reply := first(); reply.Status != "failed" {
		t.Fatalf("deadline: %+v", reply)
	}
	other := receiveOperator(t, f.started)
	receiveOperator(t, f.waiting)
	f.finish(other)
	if reply := next(); reply.Status != "done" {
		t.Fatalf("next: %+v", reply)
	}
	d.wg.Wait()
}
func TestOperatorDoesNotResumeForeignWaiters(t *testing.T) {
	for _, kind := range []string{"incident", "learning", "review"} {
		t.Run(kind, func(t *testing.T) {
			d, st, _, _ := newTestDaemon(t)
			f := newOperatorEngine()
			f.add("foreign", false)
			d.setEngine(f)
			in := operatorIncident(t, st, kind, "foreign")
			done := d.track("foreign", in.ID)
			defer done()
			m := operatorMessage(1, "a")
			m.IncidentID = in.ID
			wait := d.BeginOperatorMessage(context.Background(), m)
			sid := receiveOperator(t, f.started)
			receiveOperator(t, f.waiting)
			f.finish(sid)
			reply := wait()
			d.wg.Wait()
			if reply.SessionID == "foreign" || f.follows.Load() != 0 || f.steers.Load() != 0 {
				t.Fatalf("foreign session taken over: %+v", reply)
			}
		})
	}
}
func TestOtherConversationCannotTakeIncidentSession(t *testing.T) {
	d, st, _, _ := newTestDaemon(t)
	f := newOperatorEngine()
	f.add("incident", false)
	d.setEngine(f)
	in := operatorIncident(t, st, "incident", "incident")
	a, b := operatorMessage(1, "a"), operatorMessage(2, "b")
	a.IncidentID, b.IncidentID = in.ID, in.ID
	first := d.BeginOperatorMessage(context.Background(), a)
	receiveOperator(t, f.followed)
	receiveOperator(t, f.waiting)
	second := d.BeginOperatorMessage(context.Background(), b)
	f.finish("incident")
	if reply := first(); reply.Status != "done" {
		t.Fatal(reply)
	}
	sid := receiveOperator(t, f.started)
	receiveOperator(t, f.waiting)
	f.finish(sid)
	reply := second()
	d.wg.Wait()
	if sid == "incident" || reply.SessionID != sid || st.Get("hub_conv_b") != sid || f.steers.Load() != 0 {
		t.Fatalf("cross-conversation routing: %+v", reply)
	}
}
func TestClaimedDecisionsStayForeignBeforeSemaphore(t *testing.T) {
	d, st, _, _ := newTestDaemon(t)
	f := newOperatorEngine()
	f.add("decisions", false)
	d.setEngine(f)
	in := operatorIncident(t, st, "incident", "decisions")
	if !d.claimFollowUp(in.ID) {
		t.Fatal("claim failed")
	}
	for i := 0; i < cap(d.incSem); i++ {
		d.incSem <- struct{}{}
	}
	d.wg.Add(1)
	go d.resumeAfterDecisions(context.Background(), in.ID, "decisions", "high", []string{"approved"})
	m := operatorMessage(1, "a")
	m.IncidentID = in.ID
	wait := d.BeginOperatorMessage(context.Background(), m)
	sid := receiveOperator(t, f.started)
	receiveOperator(t, f.waiting)
	if sid == "decisions" || f.follows.Load() != 0 {
		t.Fatal("claimed decision session taken over")
	}
	<-d.incSem
	receiveOperator(t, f.followed)
	f.finish(sid)
	f.finish("decisions")
	if reply := wait(); reply.SessionID != sid || reply.Text != "answer:"+sid {
		t.Fatalf("decisions answer leaked: %+v", reply)
	}
	d.wg.Wait()
}
func TestDecisionsRecheckLiveAfterSemaphore(t *testing.T) {
	d, st, _, _ := newTestDaemon(t)
	f := newOperatorEngine()
	f.add("incident", false)
	d.setEngine(f)
	in := operatorIncident(t, st, "incident", "incident")
	if !d.claimFollowUp(in.ID) {
		t.Fatal("claim failed")
	}
	for i := 0; i < cap(d.incSem); i++ {
		d.incSem <- struct{}{}
	}
	d.wg.Add(1)
	go d.resumeAfterDecisions(context.Background(), in.ID, "incident", "high", []string{"approved"})
	done := d.track("incident", in.ID)
	defer done()
	<-d.incSem
	d.wg.Wait()
	if f.follows.Load() != 0 {
		t.Fatal("live owner ignored after semaphore")
	}
	if _, ok := d.LiveSessions()["incident"]; !ok {
		t.Fatal("foreign waiter untracked")
	}
}
func TestOperatorBusySessionUsesSeparateConversation(t *testing.T) {
	d, st, _, _ := newTestDaemon(t)
	f := newOperatorEngine()
	f.add("busy", true)
	d.setEngine(f)
	in := operatorIncident(t, st, "incident", "busy")
	m := operatorMessage(1, "a")
	m.IncidentID = in.ID
	wait := d.BeginOperatorMessage(context.Background(), m)
	sid := receiveOperator(t, f.started)
	receiveOperator(t, f.waiting)
	f.finish(sid)
	reply := wait()
	d.wg.Wait()
	if reply.Status != "done" || f.queued.Load() != 0 || f.follows.Load() != 0 {
		t.Fatalf("busy follow-up queued untracked: %+v", reply)
	}
}
func TestOperatorSlowDispatchDoesNotBlockAdmissionOrStop(t *testing.T) {
	d, st, _, _ := newTestDaemon(t)
	f := newOperatorEngine()
	f.add("idle", false)
	f.followGate = make(chan struct{})
	d.setEngine(f)
	in := operatorIncident(t, st, "incident", "idle")
	m := operatorMessage(1, "a")
	m.IncidentID = in.ID
	first := d.BeginOperatorMessage(context.Background(), m)
	receiveOperator(t, f.followed)
	admitted := make(chan func() hubproto.MessageReply, 1)
	go func() { admitted <- d.BeginOperatorMessage(context.Background(), operatorMessage(2, "b")) }()
	var next func() hubproto.MessageReply
	select {
	case next = <-admitted:
	case <-time.After(time.Second):
		t.Fatal("dispatch held admission lock")
	}
	if reply := d.StopSession(context.Background(), hubproto.OperatorMessage{SessionID: "idle"}); reply.Status != "done" {
		t.Fatalf("stop: %+v", reply)
	}
	if reply := first(); reply.Status != "failed" {
		t.Fatalf("canceled dispatch: %+v", reply)
	}
	sid := receiveOperator(t, f.started)
	receiveOperator(t, f.waiting)
	f.finish(sid)
	if reply := next(); reply.Status != "done" {
		t.Fatalf("queued conversation: %+v", reply)
	}
	d.wg.Wait()
}
func TestOldUntrackCannotRemoveNewOwner(t *testing.T) {
	d, _, _, _ := newTestDaemon(t)
	first := d.track("same", 1)
	second := d.track("same", 2)
	first()
	if d.LiveSessions()["same"] != 2 {
		t.Fatal("old waiter removed new owner")
	}
	second()
}

func (f *operatorSteerEngine) timeout(id string) runtime.Outcome {
	f.mu.Lock()
	hook := f.beforeTimeout
	f.beforeTimeout = nil
	f.mu.Unlock()
	if hook != nil {
		hook(id)
	}
	return runtime.Outcome{Status: "timeout"}
}
func TestOperatorQueuedStartupInputsStayOrdered(t *testing.T) {
	d, _, _, _ := newTestDaemon(t)
	f := newOperatorEngine()
	f.startGate = make(chan struct{})
	d.setEngine(f)
	first := d.BeginOperatorMessage(context.Background(), operatorMessage(1, "a"))
	a, b := operatorMessage(2, "a"), operatorMessage(3, "a")
	a.Body, b.Body = "second constraint", "third constraint"
	second := d.BeginOperatorMessage(context.Background(), a)
	third := d.BeginOperatorMessage(context.Background(), b)
	close(f.startGate)
	sid := receiveOperator(t, f.started)
	receiveOperator(t, f.waiting)
	if second().Status != "done" || third().Status != "done" {
		t.Fatal("startup input rejected")
	}
	f.finish(sid)
	if first().Status != "done" {
		t.Fatal("first input failed")
	}
	d.wg.Wait()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.messages) != 2 || !strings.Contains(f.messages[0], "second constraint") || !strings.Contains(f.messages[1], "third constraint") {
		t.Fatalf("input order: %v", f.messages)
	}
}
func TestOperatorDeadlineAbortsLateIdleSteer(t *testing.T) {
	old := operatorWaitTimeout
	operatorWaitTimeout = 20 * time.Millisecond
	t.Cleanup(func() { operatorWaitTimeout = old })
	d, _, _, _ := newTestDaemon(t)
	f := newOperatorEngine()
	d.setEngine(f)
	f.beforeTimeout = func(sid string) {
		f.finish(sid)
		if reply := d.BeginOperatorMessage(context.Background(), operatorMessage(2, "a"))(); reply.Status != "done" {
			t.Errorf("late steer failed: %+v", reply)
		}
	}
	wait := d.BeginOperatorMessage(context.Background(), operatorMessage(1, "a"))
	receiveOperator(t, f.started)
	reply := wait()
	d.wg.Wait()
	if reply.Status != "failed" || f.idleSteers.Load() != 1 || f.aborts.Load() == 0 || len(d.LiveSessions()) != 0 {
		t.Fatalf("late continuation stranded: %+v", reply)
	}
}
func TestOperatorNewConversationsQueueAndBookOnce(t *testing.T) {
	d, _, _, _ := newTestDaemon(t)
	f := newOperatorEngine()
	d.setEngine(f)
	first := d.BeginOperatorMessage(context.Background(), operatorMessage(1, "a"))
	sid := receiveOperator(t, f.started)
	receiveOperator(t, f.waiting)
	next := d.BeginOperatorMessage(context.Background(), operatorMessage(2, "b"))
	if f.n.Load() != 1 {
		t.Fatal("operator sessions ran in parallel")
	}
	f.finish(sid)
	if first().Status != "done" {
		t.Fatal("first failed")
	}
	other := receiveOperator(t, f.started)
	receiveOperator(t, f.waiting)
	f.finish(other)
	if next().Status != "done" {
		t.Fatal("queued conversation refused")
	}
	d.wg.Wait()
	if got := d.spentToday(); math.Abs(got-0.02) > 0.00001 {
		t.Fatalf("usage booked incorrectly: %f", got)
	}
}

func TestOperatorUncertainSteerResponseStillTracksContinuation(t *testing.T) {
	d, _, _, _ := newTestDaemon(t)
	f := newOperatorEngine()
	f.steerErr = errors.New("response lost after accepting input")
	d.setEngine(f)
	wait := d.BeginOperatorMessage(context.Background(), operatorMessage(1, "a"))
	sid := receiveOperator(t, f.started)
	receiveOperator(t, f.waiting)
	f.mu.Lock()
	f.beforeReturn = func(string) {
		if reply := d.BeginOperatorMessage(context.Background(), operatorMessage(2, "a"))(); reply.Status != "failed" {
			t.Error("uncertain delivery was not reported")
		}
	}
	f.mu.Unlock()
	f.finish(sid)
	receiveOperator(t, f.waiting)
	if _, live := d.LiveSessions()[sid]; !live {
		t.Fatal("uncertain continuation untracked")
	}
	f.finish(sid)
	if wait().Status != "done" {
		t.Fatal("continuation not followed")
	}
	d.wg.Wait()
}
