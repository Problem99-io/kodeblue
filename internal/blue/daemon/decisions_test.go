package daemon

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/mcpserver"
	"github.com/Problem99-io/kodeblue/internal/blue/respond"
	"github.com/Problem99-io/kodeblue/internal/blue/runtime"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

// followEngine records the follow-ups it is sent.
type followEngine struct {
	*fakeEngine
	mu   sync.Mutex
	msgs []string
}

func (f *followEngine) FollowUp(ctx context.Context, s *runtime.Session, msg string) (*runtime.Session, error) {
	f.mu.Lock()
	f.msgs = append(f.msgs, msg)
	f.mu.Unlock()
	return f.fakeEngine.FollowUp(ctx, s, msg)
}

func (f *followEngine) sent() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.msgs...)
}

func TestDecisionsResumeIncidentAgent(t *testing.T) {
	d, st, _, _ := newTestDaemon(t)
	d.cfg.Response.StateDir = filepath.Join(d.cfg.Server.StateDir, "response")
	if err := os.MkdirAll(d.cfg.Response.StateDir, 0o750); err != nil {
		t.Fatal(err)
	}
	eng := &followEngine{fakeEngine: &fakeEngine{id: 1, runFor: time.Millisecond}}
	eng.alive.Store(true)
	d.setEngine(eng)

	in := &store.Incident{Title: "ssh brute force", Severity: "high", Kind: "incident"}
	if err := st.CreateIncident(in); err != nil {
		t.Fatal(err)
	}
	in.Status, in.SessionID = "needs_human", "sess-1"
	_ = st.UpdateIncident(in)

	writeLines := func(path string, v ...any) {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		for _, x := range v {
			b, _ := json.Marshal(x)
			f.Write(append(b, '\n'))
		}
	}
	reqA := respond.Request{ID: "a1", IncidentID: in.ID, Action: "block_ip", Params: map[string]string{"ip": "203.0.113.7"}, RequestedBy: "agent"}
	reqB := respond.Request{ID: "b2", IncidentID: in.ID, Action: "block_ip", Params: map[string]string{"ip": "203.0.113.8"}, RequestedBy: "agent"}
	writeLines(filepath.Join(d.cfg.Server.StateDir, "response-requests.jsonl"), reqA, reqB)

	// One approved and carried out, one still waiting: nothing to hand back.
	ranA := respond.Record{Request: reqA, Status: "done", Result: "blocked 203.0.113.7"}
	ranA.RequestedBy = "agent+hub:admin+operator"
	writeLines(filepath.Join(d.cfg.Response.StateDir, "actions.jsonl"), ranA)
	d.followUpDecisions(context.Background())
	if got := eng.sent(); len(got) != 0 {
		t.Fatalf("follow-up sent while a request still waits: %q", got)
	}

	// The last one denied: the agent hears both decisions, once.
	if err := mcpserver.DenyRequest(d.cfg, "b2", "hub:admin"); err != nil {
		t.Fatal(err)
	}
	d.followUpDecisions(context.Background())
	d.wg.Wait()
	got := eng.sent()
	if len(got) != 1 {
		t.Fatalf("want one follow-up, got %d", len(got))
	}
	for _, want := range []string{"incident #", "block_ip ip=203.0.113.7: approved by admin (hub), done: blocked 203.0.113.7", "block_ip ip=203.0.113.8: denied by hub:admin", "incident_resolve"} {
		if !strings.Contains(got[0], want) {
			t.Errorf("follow-up lacks %q:\n%s", want, got[0])
		}
	}
	d.followUpDecisions(context.Background())
	d.wg.Wait()
	if n := len(eng.sent()); n != 1 {
		t.Fatalf("decisions handed back again: %d follow-ups", n)
	}
}
