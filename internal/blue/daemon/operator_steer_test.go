package daemon

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
	"github.com/Problem99-io/kodeblue/internal/blue/runtime"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

type operatorSteerEngine struct {
	*fakeEngine
	steered      []string
	follows      int
	aborts       atomic.Int32
	waits        atomic.Int32
	beforeReturn func()
}

func (f *operatorSteerEngine) Steer(_ context.Context, s *runtime.Session, text string) error {
	f.steered = append(f.steered, s.ID+":"+text)
	return nil
}
func (f *operatorSteerEngine) FollowUp(ctx context.Context, s *runtime.Session, text string) (*runtime.Session, error) {
	f.follows++
	return f.fakeEngine.FollowUp(ctx, s, text)
}
func (f *operatorSteerEngine) WaitSession(context.Context, *runtime.Session, time.Duration) runtime.Outcome {
	f.waits.Add(1)
	if f.beforeReturn != nil {
		cb := f.beforeReturn
		f.beforeReturn = nil
		cb()
	}
	return runtime.Outcome{Status: "completed", Text: "continued with operator input"}
}

func TestOperatorInputSteersSameSession(t *testing.T) {
	d, st, _, _ := newTestDaemon(t)
	f := &operatorSteerEngine{fakeEngine: &fakeEngine{id: 1}}
	f.alive.Store(true)
	d.setEngine(f)
	ctx := context.Background()
	wait := d.BeginOperatorMessage(ctx, hubproto.OperatorMessage{ID: 1, Author: "alice", Body: "investigate", ConversationID: "c_test"})
	sid := st.Get("hub_conv_c_test")
	if sid == "" {
		t.Fatal("session was not published before returning the wait")
	}
	for i, body := range []string{"focus on ssh", "preserve the log"} {
		reply := d.BeginOperatorMessage(ctx, hubproto.OperatorMessage{ID: int64(i + 2), Author: "alice", Body: body, ConversationID: "c_test"})()
		if reply.Status != "done" || reply.SessionID != sid {
			t.Fatalf("steer: %+v", reply)
		}
	}
	if len(f.steered) != 2 || !strings.Contains(f.steered[0], "focus on ssh") || !strings.Contains(f.steered[1], "preserve the log") || f.n.Load() != 1 || f.follows != 0 {
		t.Fatalf("started another chat: starts=%d follows=%d steers=%v", f.n.Load(), f.follows, f.steered)
	}
	// Input admitted just as WaitSession returns must not leave an untracked
	// continuation, book it twice, or resolve the conversation too early.
	f.beforeReturn = func() {
		r := d.BeginOperatorMessage(ctx, hubproto.OperatorMessage{ID: 4, Author: "alice", Body: "one more constraint", ConversationID: "c_test"})()
		if r.Status != "done" {
			t.Errorf("late input: %+v", r)
		}
	}
	if reply := wait(); reply.Status != "done" || reply.Text != "continued with operator input" || reply.SessionID != sid {
		t.Fatalf("final outcome: %+v", reply)
	}
	if f.waits.Load() != 2 {
		t.Fatalf("did not follow the late continuation: waits=%d", f.waits.Load())
	}
	if len(d.LiveSessions()) != 0 {
		t.Fatal("session still tracked after completing")
	}
	if incidents := st.Incidents(`WHERE kind='operator'`); len(incidents) != 1 || incidents[0].Status != "resolved" {
		t.Fatalf("duplicate/unresolved conversations: %+v", incidents)
	}
	// Once idle, the next message is an ordinary follow-up in the same session.
	r := d.HandleOperatorMessage(ctx, hubproto.OperatorMessage{ID: 5, Author: "alice", Body: "summarize", ConversationID: "c_test"})
	if r.Status != "done" || r.SessionID != sid || f.follows != 1 || f.n.Load() != 1 {
		t.Fatalf("idle follow-up: %+v follows=%d", r, f.follows)
	}
}

func TestOperatorInputDoesNotSteerForeignWaiter(t *testing.T) {
	d, st, _, _ := newTestDaemon(t)
	f := &operatorSteerEngine{fakeEngine: &fakeEngine{id: 1}}
	f.alive.Store(true)
	d.setEngine(f)
	in := &store.Incident{Title: "intrusion", Kind: "incident", Severity: "high", Status: "investigating", SessionID: "responder"}
	if err := st.CreateIncident(in); err != nil {
		t.Fatal(err)
	}
	// CreateIncident starts an incident in its default state.
	in.Status = "investigating"
	in.SessionID = "responder"
	_ = st.UpdateIncident(in)
	done := d.track("responder", in.ID)
	defer done()
	r := d.HandleOperatorMessage(context.Background(), hubproto.OperatorMessage{ID: 1, Author: "alice", Body: "keep the process alive", IncidentID: in.ID})
	if r.Status != "done" || r.SessionID == "responder" || len(f.steered) != 0 || f.n.Load() != 1 || f.follows != 0 || f.waits.Load() != 1 {
		t.Fatalf("did not steer responder: %+v engine=%+v", r, f)
	}
	if rows := st.Incidents(`WHERE kind='operator'`); len(rows) != 1 {
		t.Fatal("did not create a tracked operator session")
	}
}

func (f *operatorSteerEngine) Abort(context.Context, string) error { f.aborts.Add(1); return nil }

func TestOperatorDoesNotResumeLearningOrReview(t *testing.T) {
	for _, kind := range []string{"learning", "review"} {
		t.Run(kind, func(t *testing.T) {
			d, st, _, _ := newTestDaemon(t)
			f := &operatorSteerEngine{fakeEngine: &fakeEngine{id: 1}}
			f.alive.Store(true)
			d.setEngine(f)
			in := &store.Incident{Title: kind, Kind: kind, Severity: "info"}
			_ = st.CreateIncident(in)
			in.SessionID = "foreign"
			_ = st.UpdateIncident(in)
			done := d.track("foreign", in.ID)
			defer done()
			r := d.HandleOperatorMessage(context.Background(), hubproto.OperatorMessage{ID: 1, Body: "question", IncidentID: in.ID})
			if r.SessionID == "foreign" || f.follows != 0 || len(f.steered) != 0 {
				t.Fatalf("foreign waiter was steered: %+v", r)
			}
		})
	}
}

func TestOperatorCancellationAbortsLateContinuation(t *testing.T) {
	d, _, _, _ := newTestDaemon(t)
	f := &operatorSteerEngine{fakeEngine: &fakeEngine{id: 1}}
	f.alive.Store(true)
	d.setEngine(f)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wait := d.BeginOperatorMessage(ctx, hubproto.OperatorMessage{ID: 1, Body: "work", ConversationID: "cancel"})
	f.beforeReturn = func() {
		_ = d.BeginOperatorMessage(ctx, hubproto.OperatorMessage{ID: 2, Body: "late", ConversationID: "cancel"})()
		cancel()
	}
	_ = wait()
	if f.aborts.Load() == 0 || len(d.LiveSessions()) != 0 {
		t.Fatal("late continuation was not aborted and released")
	}
}

func TestNewOperatorConversationHasConcurrencyLimit(t *testing.T) {
	d, _, _, _ := newTestDaemon(t)
	f := &operatorSteerEngine{fakeEngine: &fakeEngine{id: 1}}
	f.alive.Store(true)
	d.setEngine(f)
	wait := d.BeginOperatorMessage(context.Background(), hubproto.OperatorMessage{ID: 1, Body: "work", ConversationID: "first"})
	r := d.BeginOperatorMessage(context.Background(), hubproto.OperatorMessage{ID: 2, Body: "work", ConversationID: "second"})()
	if r.Status != "refused" || f.n.Load() != 1 {
		t.Fatalf("unbounded operator sessions: %+v", r)
	}
	_ = wait()
}

func TestOperatorDeadlineAbortsChangedVersion(t *testing.T) {
	old := operatorWaitTimeout
	operatorWaitTimeout = time.Millisecond
	t.Cleanup(func() { operatorWaitTimeout = old })
	d, _, _, _ := newTestDaemon(t)
	f := &operatorSteerEngine{fakeEngine: &fakeEngine{id: 1}}
	f.alive.Store(true)
	d.setEngine(f)
	wait := d.BeginOperatorMessage(context.Background(), hubproto.OperatorMessage{ID: 1, Body: "work", ConversationID: "deadline"})
	f.beforeReturn = func() {
		_ = d.BeginOperatorMessage(context.Background(), hubproto.OperatorMessage{ID: 2, Body: "late", ConversationID: "deadline"})()
		time.Sleep(3 * time.Millisecond)
	}
	r := wait()
	if r.Status != "failed" || f.aborts.Load() == 0 || len(d.LiveSessions()) != 0 {
		t.Fatalf("deadline left continuation: %+v aborts=%d", r, f.aborts.Load())
	}
}
