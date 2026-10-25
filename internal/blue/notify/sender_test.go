package notify

import (
	"context"
	"testing"
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
