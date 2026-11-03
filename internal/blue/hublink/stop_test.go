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
	"testing"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/config"
	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

// chatAgent answers a chat only once a stop has arrived, the way a running
// operator session ends when the operator stops it.
type chatAgent struct {
	Agent
	stopped chan struct{}
}

func (a *chatAgent) HandleOperatorMessage(ctx context.Context, _ hubproto.OperatorMessage) hubproto.MessageReply {
	select {
	case <-a.stopped:
		return hubproto.MessageReply{Status: "failed", Text: "aborted"}
	case <-ctx.Done():
		return hubproto.MessageReply{Status: "failed"}
	}
}

func (a *chatAgent) StopSession(_ context.Context, m hubproto.OperatorMessage) hubproto.MessageReply {
	close(a.stopped)
	return hubproto.MessageReply{Status: "done", SessionID: m.SessionID}
}

func (a *chatAgent) Investigate(ctx context.Context, m hubproto.OperatorMessage) hubproto.MessageReply {
	return a.HandleOperatorMessage(ctx, m)
}

// TestStopIsNotQueuedBehindAChat: a chat holds the message queue until its
// session ends, so a stop for that session must not wait behind it.
func TestStopIsNotQueuedBehindAChat(t *testing.T) {
	testStopNotQueued(t, "")
}

func TestStopIsNotQueuedBehindAnInvestigation(t *testing.T) {
	testStopNotQueued(t, hubproto.CommandInvestigate)
}

func testStopNotQueued(t *testing.T, command string) {
	replies := make(chan int64, 4)
	polls := 0
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/reply") {
			var id int64
			_, _ = io.WriteString(w, "{}")
			for _, p := range strings.Split(r.URL.Path, "/") {
				if n, err := json.Number(p).Int64(); err == nil {
					id = n
				}
			}
			replies <- id
			return
		}
		var out hubproto.MessagesResponse
		switch polls++; polls {
		case 1:
			out.Messages = []hubproto.OperatorMessage{{ID: 1, Author: "alice", Command: command, Body: "what changed?", ConversationID: "c1"}}
		case 2:
			out.Messages = []hubproto.OperatorMessage{{ID: 2, Author: "alice", Command: hubproto.CommandStop, SessionID: "s1"}}
		default:
			select {
			case <-r.Context().Done():
			case <-time.After(time.Second):
			}
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	defer hub.Close()

	dir := t.TempDir()
	cfg := config.Default()
	cfg.Server.StateDir = dir
	cfg.Hub.AcceptMessages = true
	st, err := store.Open(filepath.Join(dir, "kb.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	a := &chatAgent{stopped: make(chan struct{})}
	l := &Link{cfg: cfg, st: st, log: slog.New(slog.NewTextHandler(io.Discard, nil)), agent: a,
		base: hub.URL, client: hub.Client(), poll: hub.Client(), nudge: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go l.messageLoop(ctx)

	// The chat can only end once the stop has been handled, so both replies
	// arriving means the stop did not wait for it.
	var got []int64
	for len(got) < 2 {
		select {
		case id := <-replies:
			got = append(got, id)
		case <-time.After(10 * time.Second):
			t.Fatalf("replies so far %v: the stop was held behind the running chat", got)
		}
	}
}
