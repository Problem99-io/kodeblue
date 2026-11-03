package hublink

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/config"
	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

type steeringChatAgent struct {
	Agent
	block     chan struct{}
	stopped   chan struct{}
	admitted  chan int64
	continued chan struct{}
}

func (a *steeringChatAgent) BeginOperatorMessage(ctx context.Context, m hubproto.OperatorMessage) func() hubproto.MessageReply {
	a.admitted <- m.ID
	if a.block != nil {
		select {
		case <-a.block:
		case <-ctx.Done():
		}
	}
	if m.ID == 2 {
		close(a.continued)
	}
	return func() hubproto.MessageReply {
		if m.ID == 1 {
			select {
			case <-a.continued:
			case <-ctx.Done():
			}
		}
		return hubproto.MessageReply{Status: "done", SessionID: "same-session"}
	}
}

func TestChatSteeringDoesNotWaitForThePreviousReply(t *testing.T) {
	replies := make(chan struct{}, 2)
	var polls atomic.Int32
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/reply") {
			replies <- struct{}{}
			_, _ = io.WriteString(w, "{}")
			return
		}
		if polls.Add(1) == 1 {
			_ = json.NewEncoder(w).Encode(hubproto.MessagesResponse{Messages: []hubproto.OperatorMessage{
				{ID: 1, Author: "alice", Body: "investigate", ConversationID: "c_test"},
				{ID: 2, Author: "alice", Body: "focus on ssh", ConversationID: "c_test"},
			}})
			return
		}
		<-r.Context().Done()
	}))
	defer hub.Close()
	cfg := config.Default()
	cfg.Server.StateDir = t.TempDir()
	st, err := store.Open(filepath.Join(cfg.Server.StateDir, "kb.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	a := &steeringChatAgent{admitted: make(chan int64, 2), continued: make(chan struct{})}
	l := &Link{cfg: cfg, st: st, log: slog.New(slog.NewTextHandler(io.Discard, nil)), agent: a, base: hub.URL, client: hub.Client(), poll: hub.Client(), nudge: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go l.messageLoop(ctx)
	for _, want := range []int64{1, 2} {
		select {
		case id := <-a.admitted:
			if id != want {
				t.Fatalf("admission out of order: got %d want %d", id, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("new input waited for the previous reply")
		}
	}
	for i := 0; i < 2; i++ {
		select {
		case <-replies:
		case <-time.After(5 * time.Second):
			t.Fatal("steered conversation did not finish")
		}
	}
}

func (a *steeringChatAgent) StopSession(context.Context, hubproto.OperatorMessage) hubproto.MessageReply {
	close(a.stopped)
	return hubproto.MessageReply{Status: "done"}
}
func TestStopDoesNotWaitForSlowChatAdmission(t *testing.T) {
	var polls atomic.Int32
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/reply") {
			io.WriteString(w, "{}")
			return
		}
		if polls.Add(1) == 1 {
			json.NewEncoder(w).Encode(hubproto.MessagesResponse{Messages: []hubproto.OperatorMessage{{ID: 1, Body: "work", ConversationID: "c"}, {ID: 2, Command: hubproto.CommandStop, SessionID: "running"}}})
			return
		}
		<-r.Context().Done()
	}))
	defer hub.Close()
	cfg := config.Default()
	cfg.Server.StateDir = t.TempDir()
	st, err := store.Open(filepath.Join(cfg.Server.StateDir, "kb.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	a := &steeringChatAgent{admitted: make(chan int64, 2), block: make(chan struct{}), stopped: make(chan struct{}), continued: make(chan struct{})}
	l := &Link{cfg: cfg, st: st, log: slog.New(slog.NewTextHandler(io.Discard, nil)), agent: a, base: hub.URL, client: hub.Client(), poll: hub.Client(), nudge: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer close(a.block)
	go l.messageLoop(ctx)
	select {
	case <-a.stopped:
	case <-time.After(time.Second):
		t.Fatal("stop waited behind slow admission")
	}
}
