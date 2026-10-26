package notify

import (
	"context"
	"errors"
)

// Sender delivers notifications. With a hub, kodeblue queues them for the hub
// (the control center owns delivery); without one it posts directly.
type Sender interface {
	Send(ctx context.Context, m Message) error
	Async(m Message, onErr func(error))
}

// Queue is the durable outbox the hub link drains (implemented by the store).
type Queue interface {
	EnqueueNotification(kind, severity, title, body string, fields map[string]string, incidentID int64) error
}

// Outbox queues notifications for the hub. Writes are local and durable: a
// notification raised while the hub is unreachable is delivered when it is
// back, and a short-lived process (the agents' tool server, the CLI) never
// loses one by exiting before a network call finishes.
type Outbox struct{ Q Queue }

func (o *Outbox) Send(_ context.Context, m Message) error {
	if o == nil || o.Q == nil {
		return errors.New("no outbox")
	}
	return o.Q.EnqueueNotification(m.Kind, m.Severity, m.Title, m.Body, m.Fields, m.IncidentID)
}

func (o *Outbox) Async(m Message, onErr func(error)) {
	if err := o.Send(context.Background(), m); err != nil && onErr != nil {
		onErr(err)
	}
}

type multi []Sender

func (ms multi) Send(ctx context.Context, m Message) error {
	var first error
	for _, s := range ms {
		if err := s.Send(ctx, m); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (ms multi) Async(m Message, onErr func(error)) {
	for _, s := range ms {
		s.Async(m, onErr)
	}
}

// New queues for the hub when enrolled. Without a hub, or with direct=true,
// it also delivers to local Slack and additional notification destinations.
func New(hub bool, q Queue, webhookURL, webhookFile string, direct bool, additional ...Sender) Sender {
	var senders multi
	if hub {
		senders = append(senders, &Outbox{Q: q})
	}
	if !hub || direct {
		if slack := FromConfig(webhookURL, webhookFile); slack != nil {
			senders = append(senders, slack)
		}
		for _, sender := range additional {
			// A missing Telegram configuration is a typed nil.
			if telegram, ok := sender.(*Telegram); ok && telegram == nil {
				continue
			}
			if sender != nil {
				senders = append(senders, sender)
			}
		}
	}
	switch len(senders) {
	case 0:
		return disabled{}
	case 1:
		return senders[0]
	default:
		return senders
	}
}

// ErrDisabled: no hub and no local notification destination configured.
var ErrDisabled = errors.New("notifications are not configured (no hub, no notification destination)")

type disabled struct{}

func (disabled) Send(context.Context, Message) error { return ErrDisabled }
func (disabled) Async(Message, func(error))          {}

// Enabled reports whether s delivers anywhere.
func Enabled(s Sender) bool {
	_, off := s.(disabled)
	return s != nil && !off
}

// ViaHub reports whether s queues for the hub.
func ViaHub(s Sender) bool {
	switch v := s.(type) {
	case *Outbox:
		return true
	case multi:
		for _, x := range v {
			if ViaHub(x) {
				return true
			}
		}
	}
	return false
}
