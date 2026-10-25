package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	internal "github.com/Problem99-io/kodeblue/internal"
)

func TestWriteEventsCoalescesStreamingDeltas(t *testing.T) {
	queue := make(chan internal.Event, 64)
	var written []internal.Event
	token := func(run, channel, text string) internal.Event {
		payload := map[string]any{"content": text}
		if channel != "" {
			payload["channel"] = channel
		}
		raw, _ := json.Marshal(payload)
		return internal.Event{Type: internal.EventModelToken, SessionID: "s", RunID: internal.RunID(run), Payload: raw, Timestamp: time.Now()}
	}
	args := func(id, text string) internal.Event {
		raw, _ := json.Marshal(map[string]any{"id": id, "name": "bash", "partial_arguments": text})
		return internal.Event{Type: internal.EventToolCallStreaming, SessionID: "s", RunID: "r", Payload: raw, Timestamp: time.Now()}
	}
	for _, e := range []internal.Event{
		token("r", "reasoning", "thin"), token("r", "reasoning", "king"),
		token("r", "", "Hel"), token("r", "", "lo"),
		args("c1", `{"comm`), args("c1", `and":"ls"}`), args("c2", `{}`),
		{Type: internal.EventToolRequested, SessionID: "s", RunID: "r", Payload: json.RawMessage(`{}`)},
		token("r", "", "!"),
	} {
		queue <- e
	}
	close(queue)
	writeEvents(queue, func(e *internal.Event) { written = append(written, *e) }, time.Hour)

	var got []string
	for _, e := range written {
		var p map[string]any
		_ = json.Unmarshal(e.Payload, &p)
		got = append(got, e.Type+":"+strings.TrimSpace(asString(p["content"])+asString(p["partial_arguments"])))
	}
	want := []string{
		"model.token:thinking", "model.token:Hello",
		`tool.streaming:{"command":"ls"}`, "tool.streaming:{}",
		"tool.requested:", "model.token:!",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("written:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	var p map[string]any
	_ = json.Unmarshal(written[0].Payload, &p)
	if p["channel"] != "reasoning" {
		t.Fatalf("channel lost: %s", written[0].Payload)
	}
}

func TestWriteEventsFlushesPendingDeltaAfterWindow(t *testing.T) {
	queue := make(chan internal.Event, 4)
	written := make(chan internal.Event, 4)
	go writeEvents(queue, func(e *internal.Event) { written <- *e }, 20*time.Millisecond)
	queue <- internal.Event{Type: internal.EventModelToken, SessionID: "s", RunID: "r", Payload: json.RawMessage(`{"content":"live"}`), Timestamp: time.Now()}
	select {
	case e := <-written:
		if !strings.Contains(string(e.Payload), "live") {
			t.Fatalf("payload %s", e.Payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a lone delta was never written")
	}
	close(queue)
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

func TestWriteEventsKeepsBackToBackToolCallsApartWithoutIDs(t *testing.T) {
	queue := make(chan internal.Event, 16)
	var written []internal.Event
	delta := func(id, name, text string) internal.Event {
		raw, _ := json.Marshal(map[string]any{"id": id, "name": name, "partial_arguments": text})
		return internal.Event{Type: internal.EventToolCallStreaming, SessionID: "s", RunID: "r", Payload: raw, Timestamp: time.Now()}
	}
	// A gateway that sends no call ids: two read_file calls in a row, then a
	// grep. Each call opens with an empty-argument delta when its name arrives.
	for _, e := range []internal.Event{
		delta("", "read_file", ""), delta("", "read_file", `{"path":`), delta("", "read_file", `"/a"}`),
		delta("", "read_file", ""), delta("", "read_file", `{"path":"/b"}`),
		delta("", "grep", ""), delta("", "grep", `{"pattern":"x"}`),
	} {
		queue <- e
	}
	close(queue)
	writeEvents(queue, func(e *internal.Event) { written = append(written, *e) }, time.Hour)
	var got []string
	for _, e := range written {
		var p map[string]any
		_ = json.Unmarshal(e.Payload, &p)
		got = append(got, asString(p["name"])+":"+asString(p["partial_arguments"]))
	}
	want := []string{`read_file:{"path":"/a"}`, `read_file:{"path":"/b"}`, `grep:{"pattern":"x"}`}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("written:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
