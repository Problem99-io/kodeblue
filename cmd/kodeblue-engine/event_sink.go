package main

import (
	"encoding/json"
	"os"
	"strings"
	"time"

	internal "github.com/Problem99-io/kodeblue/internal"
	"github.com/Problem99-io/kodeblue/internal/agent"
	"github.com/Problem99-io/kodeblue/internal/logging"
	"github.com/Problem99-io/kodeblue/internal/state"
)

const (
	// eventCoalesceWindow is the longest a streamed delta waits before it is
	// written. Pollers of the event history see tokens this much later, in
	// return for one row per window instead of one per token.
	eventCoalesceWindow = 250 * time.Millisecond
	// eventCoalesceMaxBytes flushes a merged delta early once it is this big.
	eventCoalesceMaxBytes = 16 << 10
)

// startEventSink persists events on a single background goroutine: the DB
// has one SQLite connection, so a synchronous sink would make every agent
// loop take turns on it for every token. The buffer is large; if it ever
// fills, the send blocks and applies backpressure rather than dropping events.
func startEventSink(logger *logging.Logger, eventRepo *state.EventRepo) agent.EventSink {
	eventQueue := make(chan internal.Event, 8192)
	go writeEvents(eventQueue, func(event *internal.Event) {
		if err := eventRepo.Append(event); err != nil {
			logger.Error("failed to persist runtime event", "session_id", string(event.SessionID), "run_id", string(event.RunID), "error", err)
		}
	}, eventCoalesceWindow)
	return func(event internal.Event) {
		eventQueue <- event
	}
}

// writeEvents writes queued events in order, merging each run of consecutive
// streaming deltas (model tokens of one channel, argument fragments of one
// tool call) into a single event whose text is their concatenation. Readers
// that concatenate deltas get the same text either way.
func writeEvents(queue <-chan internal.Event, write func(*internal.Event), window time.Duration) {
	var pending *coalescedDelta
	flush := func() {
		if pending != nil {
			event := pending.event()
			write(&event)
			pending = nil
		}
	}
	ticker := time.NewTicker(window)
	defer ticker.Stop()
	for {
		select {
		case event, ok := <-queue:
			if !ok {
				flush()
				return
			}
			delta, ok := newCoalescedDelta(event)
			if !ok {
				flush()
				write(&event)
				continue
			}
			if pending != nil && pending.key == delta.key && !delta.starts && pending.text.Len() < eventCoalesceMaxBytes {
				pending.text.WriteString(delta.text.String())
				continue
			}
			flush()
			pending = delta
		case <-ticker.C:
			if pending != nil && time.Since(pending.first.Timestamp) >= window {
				flush()
			}
		}
	}
}

// coalescedDelta is a run of streaming deltas merged into one event.
type coalescedDelta struct {
	key   string
	field string // payload field holding the delta text
	// starts marks a delta that opens a new tool call: the stream client
	// emits one with empty arguments when a call's name arrives. It never
	// merges into the delta before it, so two back-to-back calls stay
	// separate even when a gateway sends no call ids.
	starts  bool
	first   internal.Event
	payload map[string]any
	text    strings.Builder
}

func newCoalescedDelta(event internal.Event) (*coalescedDelta, bool) {
	var field, scope string
	var payload map[string]any
	switch event.Type {
	case internal.EventModelToken, internal.EventToolCallStreaming:
		if json.Unmarshal(event.Payload, &payload) != nil {
			return nil, false
		}
	default:
		return nil, false
	}
	if event.Type == internal.EventModelToken {
		field = "content"
		scope, _ = payload["channel"].(string)
	} else {
		field = "partial_arguments"
		id, _ := payload["id"].(string)
		name, _ := payload["name"].(string)
		scope = id + "\x00" + name
	}
	text, ok := payload[field].(string)
	if !ok {
		return nil, false
	}
	d := &coalescedDelta{
		key:     event.Type + "\x00" + string(event.SessionID) + "\x00" + string(event.RunID) + "\x00" + scope,
		field:   field,
		first:   event,
		payload: payload,
		starts:  event.Type == internal.EventToolCallStreaming && text == "",
	}
	d.text.WriteString(text)
	return d, true
}

func (d *coalescedDelta) event() internal.Event {
	event := d.first
	d.payload[d.field] = d.text.String()
	event.Payload, _ = json.Marshal(d.payload)
	return event
}

// pruneEventsPeriodically applies the event retention policy every interval,
// starting after delay, so the events table stays bounded on a long-lived
// engine. The first pass waits out startup: the supervisor registers its
// agents over the API right after the engine starts, and a backlog of old
// events should not compete with that for the database connection.
func pruneEventsPeriodically(logger *logging.Logger, eventRepo *state.EventRepo, policy state.EventRetention, delay, interval time.Duration) {
	time.Sleep(delay)
	for {
		started := time.Now()
		deleted, err := eventRepo.Prune(started, policy)
		if err != nil {
			logger.Warn("failed to prune events", "error", err, "deleted", deleted)
		} else if deleted > 0 {
			logger.Info("pruned events", "deleted", deleted, "took", time.Since(started).Round(time.Millisecond))
		}
		time.Sleep(interval)
	}
}

// eventPruneStartDelay is how long after startup the first prune runs.
// KODEBLUE_EVENT_PRUNE_DELAY (a Go duration) overrides it, for tests that
// need to observe a prune without waiting.
func eventPruneStartDelay() time.Duration {
	if raw := os.Getenv("KODEBLUE_EVENT_PRUNE_DELAY"); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil && d >= 0 {
			return d
		}
	}
	return 2 * time.Minute
}
