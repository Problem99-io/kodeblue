package openai

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Problem99-io/kodeblue/internal/provider"
)

// toolCallChunk is one SSE event carrying a tool-call delta.
func toolCallChunk(index int, id, name, args string) string {
	fn, _ := json.Marshal(map[string]string{"name": name, "arguments": args})
	tc := fmt.Sprintf(`{"index":%d,"function":%s`, index, fn)
	if id != "" {
		tc += fmt.Sprintf(`,"id":%q,"type":"function"`, id)
	}
	tc += "}"
	return fmt.Sprintf(`data: {"id":"gen-x","choices":[{"index":0,"delta":{"tool_calls":[%s]},"finish_reason":null}]}`+"\n\n", tc)
}

func finishChunk(reason string, usage bool) string {
	u := ""
	if usage {
		u = `,"usage":{"prompt_tokens":10,"completion_tokens":5}`
	}
	return fmt.Sprintf(`data: {"id":"gen-x","choices":[{"index":0,"delta":{},"finish_reason":%q}]%s}`+"\n\n", reason, u)
}

// streamEventsForTest runs parseSSE over body and returns every event.
func streamEventsForTest(t *testing.T, body string) []provider.StreamEvent {
	t.Helper()
	client := NewClient("test-key", "gpt-test")
	resp := &http.Response{Body: io.NopCloser(strings.NewReader(body))}
	ch := make(chan provider.StreamEvent, 64)
	go client.parseSSE(context.Background(), resp, ch)
	var events []provider.StreamEvent
	for ev := range ch {
		events = append(events, ev)
	}
	return events
}

// toolCallsAndDone returns the emitted tool calls and whether the stream ended
// with a Done event that came after every tool call.
func toolCallsAndDone(t *testing.T, events []provider.StreamEvent) ([]provider.ToolCallEvent, bool) {
	t.Helper()
	var calls []provider.ToolCallEvent
	done := false
	for _, ev := range events {
		switch ev.Type {
		case provider.EventError:
			t.Fatalf("unexpected stream error: %v", ev.Error)
		case provider.EventToolUse:
			if done {
				t.Fatalf("tool call %q emitted after Done", ev.ToolCall.Name)
			}
			calls = append(calls, *ev.ToolCall)
		case provider.EventDone:
			done = true
		}
	}
	return calls, done
}

// Tool calls are emitted in the order the model wrote them. They used to be
// emitted by ranging over a map, so monitor_create / monitor_test could run
// reversed: the engine runs MCP tools one after another.
func TestParseSSE_ToolCallsEmittedInIndexOrder(t *testing.T) {
	names := []string{"monitor_create", "monitor_test", "monitor_list", "read_file", "run_command"}
	var b strings.Builder
	// Each call starts with id and name, then its arguments arrive in two
	// fragments interleaved with the other calls' fragments.
	for i, name := range names {
		b.WriteString(toolCallChunk(i, fmt.Sprintf("call_%d", i), name, ""))
	}
	for i := range names {
		b.WriteString(toolCallChunk(i, "", "", `{"n":`))
	}
	for i := range names {
		b.WriteString(toolCallChunk(i, "", "", fmt.Sprintf("%d}", i)))
	}
	b.WriteString(finishChunk("tool_calls", true))
	b.WriteString("data: [DONE]\n\n")
	body := b.String()

	for iter := 0; iter < 200; iter++ {
		calls, done := toolCallsAndDone(t, streamEventsForTest(t, body))
		if !done {
			t.Fatal("stream did not finish with Done")
		}
		if len(calls) != len(names) {
			t.Fatalf("iteration %d: got %d tool calls, want %d", iter, len(calls), len(names))
		}
		for i, call := range calls {
			if call.Name != names[i] || call.ID != fmt.Sprintf("call_%d", i) || call.Arguments != fmt.Sprintf(`{"n":%d}`, i) {
				t.Fatalf("iteration %d: call %d = %+v, want %s/call_%d/{\"n\":%d}", iter, i, call, names[i], i, i)
			}
		}
	}
}

// Some relays end a tool-call turn with finish_reason "stop" (or with none at
// all before [DONE], or with a bare usage chunk). The streamed calls used to
// be dropped on every path but "tool_calls", ending the run with nothing done.
func TestParseSSE_ToolCallsSurviveAnyCompletion(t *testing.T) {
	calls := toolCallChunk(0, "call_a", "monitor_create", `{"name":"ssh"}`) +
		toolCallChunk(1, "call_b", "monitor_test", `{"name":"ssh"}`)
	for _, tc := range []struct{ name, tail string }{
		{"stop with usage", finishChunk("stop", true) + "data: [DONE]\n\n"},
		{"stop then usage chunk", finishChunk("stop", false) + `data: {"id":"gen-x","choices":[],"usage":{"prompt_tokens":1,"completion_tokens":1}}` + "\n\n"},
		{"stop then [DONE]", finishChunk("stop", false) + "data: [DONE]\n\n"},
		{"stop then EOF", finishChunk("stop", false)},
		{"no finish_reason, [DONE]", "data: [DONE]\n\n"},
		{"no finish_reason, usage chunk", `data: {"id":"gen-x","choices":[],"usage":{"prompt_tokens":1,"completion_tokens":1}}` + "\n\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, done := toolCallsAndDone(t, streamEventsForTest(t, calls+tc.tail))
			if !done {
				t.Fatal("stream did not finish with Done")
			}
			if len(got) != 2 || got[0].Name != "monitor_create" || got[1].Name != "monitor_test" {
				t.Fatalf("tool calls = %+v, want monitor_create then monitor_test", got)
			}
		})
	}
}

// summarizeStream counts what a stream produced.
func summarizeStream(t *testing.T, body string) (calls []provider.ToolCallEvent, dones int, errs []error) {
	t.Helper()
	for _, ev := range streamEventsForTest(t, body) {
		switch ev.Type {
		case provider.EventToolUse:
			calls = append(calls, *ev.ToolCall)
		case provider.EventDone:
			dones++
		case provider.EventError:
			errs = append(errs, ev.Error)
		}
	}
	return calls, dones, errs
}

// A call with incomplete arguments is never dispatched, and neither is the
// rest of its turn: the turn fails with an error the agent loop already
// handles (the run ends for a human to look at). Dispatching it used to hand
// the agent loop arguments it could not store, and on a restart the tools ran
// again.
func TestParseSSE_IncompleteToolCallArgsFailTheTurn(t *testing.T) {
	complete := toolCallChunk(0, "call_a", "monitor_create", `{"name":"ssh","command":"ss -tn"}`)
	for _, tc := range []struct{ name, body, want string }{
		{"length cuts the arguments",
			complete + toolCallChunk(1, "call_b", "write_file", `{"path":"/tmp/x","content":"line one`) + finishChunk("length", true) + "data: [DONE]\n\n",
			"stream truncated (finish_reason=length) inside tool call \"write_file\""},
		{"length right after the name",
			complete + toolCallChunk(1, "call_b", "incident_resolve", ``) + finishChunk("length", true),
			"stream truncated (finish_reason=length) inside tool call \"incident_resolve\""},
		{"[DONE] with no finish_reason after half the arguments",
			toolCallChunk(0, "call_a", "host_exec", `{"argv":["rm","-rf","/var/tmp/.x/kwo`) + "data: [DONE]\n\n",
			"stream truncated (finish_reason=none) inside tool call \"host_exec\""},
		{"usage chunk with no finish_reason after a name-only call",
			complete + toolCallChunk(1, "call_b", "respond", ``) + `data: {"id":"gen-x","choices":[],"usage":{"prompt_tokens":1,"completion_tokens":1}}` + "\n\n",
			"stream truncated (finish_reason=none) inside tool call \"respond\""},
		{"malformed JSON in a finished turn",
			complete + toolCallChunk(1, "call_b", "write_file", `{"path":"/tmp/x",}`) + finishChunk("tool_calls", true),
			"invalid JSON arguments for tool call \"write_file\""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls, dones, errs := summarizeStream(t, tc.body)
			if len(calls) != 0 || dones != 0 {
				t.Fatalf("calls=%+v dones=%d: an incomplete turn must not dispatch tools or complete", calls, dones)
			}
			if len(errs) != 1 || !strings.Contains(errs[0].Error(), tc.want) {
				t.Fatalf("errors = %v, want one containing %q", errs, tc.want)
			}
		})
	}
}

// In a turn that finished cleanly, a call with no arguments is a real
// no-argument call.
func TestParseSSE_NoArgumentCallInFinishedTurn(t *testing.T) {
	for _, reason := range []string{"tool_calls", "stop"} {
		calls, dones, errs := summarizeStream(t, toolCallChunk(0, "call_a", "monitor_list", ``)+finishChunk(reason, true))
		if len(errs) != 0 || dones != 1 || len(calls) != 1 || calls[0].Name != "monitor_list" || calls[0].Arguments != "" {
			t.Fatalf("%s: calls=%+v dones=%d errs=%v", reason, calls, dones, errs)
		}
	}
}

// Completion markers that overlap (usage after usage, [DONE] after usage)
// emit each call once and complete once.
func TestParseSSE_ToolCallsEmittedOnce(t *testing.T) {
	base := toolCallChunk(0, "a", "read_file", `{"path":"/x"}`) + toolCallChunk(1, "b", "list_dir", `{}`)
	usageOnly := `data: {"id":"gen-x","choices":[],"usage":{"prompt_tokens":1,"completion_tokens":1}}` + "\n\n"
	for name, body := range map[string]string{
		"tool_calls+usage, usage, [DONE]": base + finishChunk("tool_calls", true) + usageOnly + "data: [DONE]\n\n",
		"tool_calls, usage, [DONE]":       base + finishChunk("tool_calls", false) + usageOnly + "data: [DONE]\n\n",
		"stop, [DONE], usage":             base + finishChunk("stop", false) + "data: [DONE]\n\n" + usageOnly,
		"stop+usage twice":                base + finishChunk("stop", true) + finishChunk("stop", true) + "data: [DONE]\n\n",
		"no finish, usage, [DONE]":        base + usageOnly + "data: [DONE]\n\n",
	} {
		calls, dones, errs := summarizeStream(t, body)
		if len(calls) != 2 || dones != 1 || len(errs) != 0 {
			t.Errorf("%s: calls=%d dones=%d errs=%v, want 2/1/none", name, len(calls), dones, errs)
		}
	}
}

// Indexes need not start at 0 or be contiguous, and a call's id and name may
// arrive after its first argument fragment.
func TestParseSSE_IndexGapsAndLateIDAndName(t *testing.T) {
	body := toolCallChunk(7, "", "", `{"a":`) +
		toolCallChunk(3, "c3", "b_tool", `{}`) +
		toolCallChunk(7, "c7", "", `1}`) +
		toolCallChunk(7, "", "a_tool", ``) +
		finishChunk("stop", true)
	calls, _, errs := summarizeStream(t, body)
	if len(errs) != 0 || len(calls) != 2 || calls[0].ID != "c3" || calls[1].ID != "c7" || calls[1].Name != "a_tool" || calls[1].Arguments != `{"a":1}` {
		t.Fatalf("calls=%+v errs=%v", calls, errs)
	}
}

// Shapes this parser does not merge correctly (no index, a final chunk that
// restates the whole call, n>1 choices sharing index 0) accumulate invalid
// arguments. Whatever they do, no call with invalid JSON is ever dispatched.
func TestParseSSE_UnsupportedShapesNeverDispatchInvalidArgs(t *testing.T) {
	for name, body := range map[string]string{
		"no index": `data: {"choices":[{"index":0,"delta":{"tool_calls":[{"id":"g1","type":"function","function":{"name":"read_file","arguments":"{\"path\":\"/a\"}"}}]}}]}` + "\n\n" +
			`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"id":"g2","type":"function","function":{"name":"list_dir","arguments":"{\"path\":\"/b\"}"}}]}}]}` + "\n\n" +
			finishChunk("tool_calls", true),
		"full call restated in the final chunk": toolCallChunk(0, "a", "read_file", `{"path":`) + toolCallChunk(0, "", "", `"/x"}`) +
			`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"a","type":"function","function":{"name":"read_file","arguments":"{\"path\":\"/x\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}` + "\n\n",
		"two choices": `data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"x0","function":{"name":"read_file","arguments":"{\"path\":\"/a\"}"}}]}},{"index":1,"delta":{"tool_calls":[{"index":0,"id":"y0","function":{"name":"list_dir","arguments":"{\"path\":\"/b\"}"}}]}}]}` + "\n\n" +
			finishChunk("tool_calls", true),
	} {
		calls, _, _ := summarizeStream(t, body)
		for _, c := range calls {
			if !json.Valid([]byte(c.Arguments)) {
				t.Errorf("%s: dispatched %+v with invalid arguments", name, c)
			}
		}
	}
}

// A delta that never carried a function name cannot be dispatched.
func TestParseSSE_DropsNamelessToolCall(t *testing.T) {
	body := toolCallChunk(0, "call_a", "monitor_create", `{}`) +
		toolCallChunk(1, "call_b", "", `{"x":1}`) +
		finishChunk("tool_calls", true)
	got, _ := toolCallsAndDone(t, streamEventsForTest(t, body))
	if len(got) != 1 || got[0].Name != "monitor_create" {
		t.Fatalf("tool calls = %+v, want only monitor_create", got)
	}
}

// With no completion marker at all the stream is still a truncation: the
// calls are not emitted as if the turn had finished.
func TestParseSSE_ToolCallsWithoutCompletionMarkerAreTruncation(t *testing.T) {
	events := streamEventsForTest(t, toolCallChunk(0, "call_a", "monitor_create", `{}`))
	var sawErr bool
	for _, ev := range events {
		switch ev.Type {
		case provider.EventToolUse, provider.EventDone:
			t.Fatalf("unexpected %v event on a stream with no completion marker", ev.Type)
		case provider.EventError:
			sawErr = strings.Contains(ev.Error.Error(), "truncated")
		}
	}
	if !sawErr {
		t.Fatal("no truncation error")
	}
}

// [DONE] with no finish_reason ends a plain text turn normally too.
func TestParseSSE_DoneWithoutFinishReasonCompletesTextTurn(t *testing.T) {
	body := `data: {"id":"gen-x","choices":[{"index":0,"delta":{"content":"all clear"},"finish_reason":null}]}` + "\n\n" + "data: [DONE]\n\n"
	var text string
	var done bool
	for _, ev := range streamEventsForTest(t, body) {
		switch ev.Type {
		case provider.EventToken:
			text += ev.Content
		case provider.EventDone:
			done = true
		case provider.EventError:
			t.Fatalf("unexpected error: %v", ev.Error)
		}
	}
	if !done || text != "all clear" {
		t.Fatalf("done=%v text=%q, want done with %q", done, text, "all clear")
	}
}
