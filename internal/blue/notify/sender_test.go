package notify

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

type memQueue struct{ n []string }

func (q *memQueue) EnqueueNotification(kind, severity, title, body string, fields map[string]string, incidentID int64) error {
	q.n = append(q.n, title)
	return nil
}

func TestRouting(t *testing.T) {
	q := &memQueue{}
	if s := New(false, q, "", "", false); Enabled(s) {
		t.Fatal("no hub and no webhook must be disabled")
	}
	if s := New(false, q, "https://hooks.slack.com/services/x", "", false); !Enabled(s) || ViaHub(s) {
		t.Fatal("no hub: post directly")
	}
	s := New(true, q, "https://hooks.slack.com/services/x", "", false)
	if !ViaHub(s) {
		t.Fatal("with a hub, notifications go to the hub")
	}
	if _, isMulti := s.(multi); isMulti {
		t.Fatal("with a hub, the local webhook is ignored unless direct=true")
	}
	if err := s.Send(context.Background(), Message{Title: "x"}); err != nil || len(q.n) != 1 {
		t.Fatalf("outbox send: %v %v", err, q.n)
	}
	if _, isMulti := New(true, q, "https://hooks.slack.com/services/x", "", true).(multi); !isMulti {
		t.Fatal("direct=true keeps an independent copy")
	}
	var nilSender Sender = New(false, nil, "", "", false)
	nilSender.Async(Message{}, nil) // must not panic
}

type resultSender struct {
	stall bool
	fail  bool
	sent  atomic.Int32
}

func (s *resultSender) Send(ctx context.Context, _ Message) error {
	if s.stall {
		<-ctx.Done()
		return ctx.Err()
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	s.sent.Add(1)
	if s.fail {
		return errors.New("destination unavailable")
	}
	return nil
}
func (s *resultSender) Async(m Message, f func(error)) {
	if err := s.Send(context.Background(), m); err != nil && f != nil {
		f(err)
	}
}
func TestMultiPartialSuccessAndConcurrentDeadlines(t *testing.T) {
	for _, stall := range []bool{false, true} {
		t.Run(fmt.Sprint(stall), func(t *testing.T) {
			good, bad := &resultSender{}, &resultSender{stall: stall, fail: true}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			defer cancel()
			if err := (multi{bad, good}).Send(ctx, Message{}); err != nil || good.sent.Load() != 1 {
				t.Fatalf("backup failed: %v sends=%d", err, good.sent.Load())
			}
		})
	}
	a, b := &resultSender{fail: true}, &resultSender{fail: true}
	if err := (multi{a, b}).Send(context.Background(), Message{}); err == nil {
		t.Fatal("total failure hidden")
	}
}
