package daemon

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
	"github.com/Problem99-io/kodeblue/internal/blue/runtime"
)

type investigatorEngine struct {
	fakeEngine
	d                 *Daemon
	agent, brief      string
	model             string
	entered           chan struct{}
	aborted           atomic.Bool
	liveAtAbort       atomic.Bool
	failAfterDispatch bool
}

func (f *investigatorEngine) StartSession(ctx context.Context, a, p, m, b string) (*runtime.Session, error) {
	f.agent, f.brief = a, b
	f.model = m
	sess, err := f.fakeEngine.StartSession(ctx, a, p, m, b)
	if f.failAfterDispatch {
		return sess, errors.New("synthetic dispatch response lost")
	}
	return sess, err
}
func (f *investigatorEngine) FollowUp(context.Context, *runtime.Session, string) (*runtime.Session, error) {
	panic("investigator must never take over a foreign session")
}
func (f *investigatorEngine) WaitSession(ctx context.Context, s *runtime.Session, timeout time.Duration) runtime.Outcome {
	if f.entered != nil {
		close(f.entered)
	}
	return f.fakeEngine.Wait(ctx, s, timeout)
}
func (f *investigatorEngine) Abort(_ context.Context, sid string) error {
	f.aborted.Store(true)
	_, live := f.d.LiveSessions()[sid]
	f.liveAtAbort.Store(live)
	return nil
}

func TestInvestigatorUsesNativeLifecycleAndBooksOnce(t *testing.T) {
	d, st, _, sent := newTestDaemon(t)
	d.cfg.Hub.URL = "https://hub.example"
	d.cfg.Hub.AcceptMessages = true
	f := &investigatorEngine{d: d}
	f.script = make(chan runtime.Outcome, 1)
	f.script <- runtime.Outcome{Status: "completed", Text: "INCONCLUSIVE: evidence website/7; operator verification missing."}
	d.setEngine(f)
	m := hubproto.OperatorMessage{ID: 77, Command: hubproto.CommandInvestigate, RequestID: "website", Body: "Compare source activity", CreatedAt: time.Now()}
	r := d.Investigate(context.Background(), m)
	if r.Status != "done" || r.CostUSD <= 0 || r.SessionID == "" || f.agent != "blue-investigator" || !strings.Contains(f.brief, "job_id=77") {
		t.Fatalf("reply=%+v agent=%s brief=%s", r, f.agent, f.brief)
	}
	cases := st.Incidents("WHERE kind='research'")
	if len(cases) != 1 || cases[0].Status != "resolved" || cases[0].Report != r.Text {
		t.Fatalf("cases %+v", cases)
	}
	if len(d.LiveSessions()) != 0 || len(sent.titles()) != 1 {
		t.Fatal("ownership leaked or notification missing")
	}
	before := d.spentToday()
	again := d.Investigate(context.Background(), m)
	if again.Status != "refused" || f.n.Load() != 1 || d.spentToday() != before || len(sent.titles()) != 1 {
		t.Fatalf("replay launched or charged twice: %+v", again)
	}
	chat := d.HandleOperatorMessage(context.Background(), hubproto.OperatorMessage{IncidentID: cases[0].ID, Body: "take over"})
	if chat.Status != "refused" {
		t.Fatal("operator took over investigator")
	}
}

func TestCouncilInterimTurnsKeepNativeAccountingWithoutNotificationNoise(t *testing.T) {
	for _, phase := range []string{"opening", "source", "conclusion"} {
		t.Run(phase, func(t *testing.T) {
			d, st, _, sent := newTestDaemon(t)
			d.cfg.Hub.URL = "https://hub.example"
			d.cfg.Hub.AcceptMessages = true
			engine := &investigatorEngine{d: d}
			engine.script = make(chan runtime.Outcome, 1)
			engine.script <- runtime.Outcome{Status: "completed", Text: `{"kind":"pass"}`}
			d.setEngine(engine)
			out := d.Investigate(context.Background(), hubproto.OperatorMessage{ID: 187, Command: hubproto.CommandInvestigate, RequestID: "website", Body: "Read-only council turn", CreatedAt: time.Now(), CouncilPhase: phase})
			if out.Status != "done" || out.CostUSD <= 0 || len(st.Incidents("WHERE kind='research'")) != 1 {
				t.Fatalf("native accounting lost: %+v", out)
			}
			expected := 0
			if phase == "conclusion" {
				expected = 1
			}
			if len(sent.titles()) != expected {
				t.Fatalf("%s notifications: %v", phase, sent.titles())
			}
		})
	}
}

func TestInvestigatorCancellationAbortsBeforeUntrack(t *testing.T) {
	d, _, _, _ := newTestDaemon(t)
	d.cfg.Hub.URL = "https://hub.example"
	d.cfg.Hub.AcceptMessages = true
	f := &investigatorEngine{d: d, entered: make(chan struct{})}
	d.setEngine(f)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan hubproto.MessageReply, 1)
	m := hubproto.OperatorMessage{ID: 78, Command: hubproto.CommandInvestigate, RequestID: "website", Body: "Inspect", CreatedAt: time.Now()}
	go func() { done <- d.Investigate(ctx, m) }()
	select {
	case <-f.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("did not start")
	}
	if r := d.Investigate(context.Background(), m); r.Status != "refused" {
		t.Fatal("parallel investigator accepted")
	}
	cancel()
	select {
	case r := <-done:
		if r.Status != "failed" {
			t.Fatal(r)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancellation did not finish")
	}
	if !f.aborted.Load() || !f.liveAtAbort.Load() || len(d.LiveSessions()) != 0 {
		t.Fatal("abort happened after ownership release")
	}
}

func TestInvestigatorBillsAndAbortsPartiallyStartedSession(t *testing.T) {
	d, st, _, _ := newTestDaemon(t)
	d.cfg.Hub.URL = "https://hub.example"
	d.cfg.Hub.AcceptMessages = true
	f := &investigatorEngine{d: d, failAfterDispatch: true}
	d.setEngine(f)
	r := d.Investigate(context.Background(), hubproto.OperatorMessage{ID: 88, Command: hubproto.CommandInvestigate, RequestID: "website", Body: "Inspect", CreatedAt: time.Now()})
	if r.Status != "failed" || r.SessionID == "" || r.CostUSD <= 0 || !f.aborted.Load() || !f.liveAtAbort.Load() || len(d.LiveSessions()) > 0 {
		t.Fatalf("partial dispatch leaked: %+v", r)
	}
	cases := st.Incidents("WHERE kind='research'")
	if len(cases) != 1 || cases[0].CostUSD != r.CostUSD || cases[0].SessionID != r.SessionID {
		t.Fatal("partial dispatch not accounted in case")
	}
}

func TestInvestigatorHonorsBudgetAndAdmissionDeadline(t *testing.T) {
	d, st, _, _ := newTestDaemon(t)
	d.cfg.Hub.URL = "https://hub.example"
	d.cfg.Hub.AcceptMessages = true
	d.cfg.Budget.DailyUSD = .001
	f := &investigatorEngine{d: d}
	d.setEngine(f)
	st.Spend("test", "test", 1, 1, 0, 1)
	m := hubproto.OperatorMessage{ID: 79, Command: hubproto.CommandInvestigate, RequestID: "website", Body: "Inspect", CreatedAt: time.Now()}
	if r := d.Investigate(context.Background(), m); r.Status != "refused" || f.n.Load() != 0 {
		t.Fatalf("budget bypass: %+v", r)
	}
	d.cfg.Budget.DailyUSD = 0
	d.incSem = make(chan struct{}, 1)
	d.incSem <- struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if r := d.Investigate(ctx, m); r.Status != "refused" || f.n.Load() != 0 {
		t.Fatalf("cancelled admission started: %+v", r)
	}
}

func TestWarRoomResponderUsesItsOwnModelInAFreshReadOnlyDelegate(t *testing.T) {
	d, st, _, _ := newTestDaemon(t)
	d.cfg.Hub.URL = "https://hub.example"
	d.cfg.Hub.AcceptMessages = true
	d.cfg.Inference.AgentModels = map[string]string{hubproto.RoleResponder: "responder-model", hubproto.RoleInvestigator: "investigator-model"}
	engine := &investigatorEngine{d: d}
	engine.script = make(chan runtime.Outcome, 1)
	engine.script <- runtime.Outcome{Status: "completed", Text: `{"kind":"pass"}`}
	d.setEngine(engine)
	reply := d.Investigate(context.Background(), hubproto.OperatorMessage{ID: 219, Command: hubproto.CommandInvestigate, RequestID: "wr_case", Body: "Read-only responder turn", CouncilPhase: "source", CouncilRole: "responder", CreatedAt: time.Now()})
	if reply.Status != "done" || engine.agent != "blue-warroom-responder" || engine.model != "responder-model" || len(st.Incidents("WHERE kind='research'")) != 1 {
		t.Fatalf("wrong role/session: %+v agent=%s model=%s", reply, engine.agent, engine.model)
	}
	bad := d.Investigate(context.Background(), hubproto.OperatorMessage{ID: 220, Command: hubproto.CommandInvestigate, RequestID: "wr_case", Body: "test", CouncilRole: "root-shell", CouncilPhase: "source", CreatedAt: time.Now()})
	if bad.Status != "refused" {
		t.Fatal("arbitrary agent dispatch allowed")
	}
}
