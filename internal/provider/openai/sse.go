package openai

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/Problem99-io/kodeblue/internal/provider"
	"github.com/Problem99-io/kodeblue/internal/provider/normalize"
)

// sseIdleTimeout ends a stream that has sent nothing for this long.
const sseIdleTimeout = 90 * time.Second

// sseStream turns a chat-completions SSE response into provider events.
type sseStream struct {
	ctx  context.Context
	resp *http.Response
	ch   chan<- provider.StreamEvent

	// activeTools accumulates streamed tool calls by their delta index. Calls
	// are emitted once, in ascending index order, when the turn completes.
	activeTools map[int]*toolAcc
	// finishReason is the terminal finish_reason, once one arrived.
	finishReason string
	// rdAcc accumulates raw reasoning_details deltas so the finished array can
	// ride on the Done event and be replayed verbatim next turn.
	rdAcc reasoningDetailsAcc
	// contentBytes counts reasoning and content bytes, for truncation
	// diagnostics.
	contentBytes int
	// pendingDone is set after a terminal finish_reason that carried no usage:
	// the turn is finished once a trailing usage chunk (or [DONE]) arrives.
	pendingDone bool
	// dataParts buffers the `data:` lines of the event being assembled. Per
	// the SSE spec one event may span several `data:` lines joined with "\n";
	// relays such as OpenRouter split large chunks (streamed tool-call
	// arguments) this way. Processing each line on its own would drop a
	// fragment or fail on half a JSON object, so the event is processed at the
	// blank-line boundary (or at end of stream).
	dataParts []string
}

func (s *sseStream) send(ev provider.StreamEvent) {
	if ev.Type == provider.EventError {
		ev.Error = provider.WrapResponseError(s.resp, ev.Error)
	}
	select {
	case s.ch <- ev:
	case <-s.ctx.Done():
	}
}

// sendDone completes the turn. Every path that finishes a turn goes through
// here, so accumulated tool calls are emitted first whatever the finish
// reason: relays differ on whether a tool-call turn ends with "tool_calls",
// "stop", or no finish_reason at all before [DONE].
func (s *sseStream) sendDone(usage *provider.Usage) {
	calls, err := s.toolCalls()
	if err != nil {
		s.send(normalize.ErrorEvent(err))
		return
	}
	for _, call := range calls {
		s.send(normalize.ToolUseEvent(call.ID, call.Name, call.Arguments))
	}
	ev := normalize.DoneEvent(usage)
	ev.ReasoningDetails = s.rdAcc.marshal()
	s.send(ev)
}

// toolCalls returns the accumulated tool calls in index order (the order the
// model wrote them), so dependent calls such as monitor_create then
// monitor_test run in sequence.
//
// A call whose arguments are not complete JSON is never dispatched, and
// neither is the rest of its turn: the turn fails with an error instead. That
// is a call cut off by the output token limit (finish_reason "length"), or by
// a stream that ended with [DONE] or usage but no finish_reason, or a model
// that wrote malformed JSON. Running the tool on half-written arguments, or
// handing the agent loop arguments it cannot store, is worse than ending the
// run for a human to look at. In a turn that did not finish cleanly a call
// with no arguments yet counts as cut off too, rather than running as {}.
func (s *sseStream) toolCalls() ([]provider.ToolCallEvent, error) {
	cutShort := s.finishReason == "length" || s.finishReason == ""
	var calls []provider.ToolCallEvent
	for _, index := range slices.Sorted(maps.Keys(s.activeTools)) {
		acc := s.activeTools[index]
		args := acc.args.String()
		if acc.name == "" {
			slog.Warn("openai stream: dropping tool call with no name", "index", index, "id", acc.id, "finish_reason", s.finishReason)
			continue
		}
		empty := strings.TrimSpace(args) == ""
		if (empty && cutShort) || (!empty && !json.Valid([]byte(args))) {
			reason := s.finishReason
			if reason == "" {
				reason = "none"
			}
			slog.Warn("openai stream: tool call arguments incomplete; not running this turn's tool calls",
				"tool", acc.name, "id", acc.id, "args_bytes", len(args), "finish_reason", reason, "tool_calls", len(s.activeTools))
			if cutShort {
				return nil, fmt.Errorf("openai: stream truncated (finish_reason=%s) inside tool call %q: its arguments are incomplete, so none of this turn's %d tool calls were run",
					reason, acc.name, len(s.activeTools))
			}
			return nil, fmt.Errorf("openai: model wrote invalid JSON arguments for tool call %q (finish_reason=%s), so none of this turn's %d tool calls were run",
				acc.name, reason, len(s.activeTools))
		}
		calls = append(calls, provider.ToolCallEvent{ID: acc.id, Name: acc.name, Arguments: args})
	}
	clear(s.activeTools)
	return calls, nil
}

// sendTruncated reports a stream that ended before the model finished: no
// [DONE] and no terminal finish_reason. That is what an intermediary killing
// the connection mid-response looks like. Reporting it as a normal completion
// would hand the agent loop a half-written message with no tool calls and
// zero usage, so it is an error.
func (s *sseStream) sendTruncated(cause string) {
	slog.Warn("openai stream truncated", "cause", cause, "content_bytes", s.contentBytes)
	s.send(normalize.ErrorEvent(fmt.Errorf(
		"openai: stream truncated by %s after %d bytes — no completion marker received",
		cause, s.contentBytes)))
}

// finishAtEnd handles the end of the response body: it processes any
// buffered event, completes a turn that was waiting for trailing usage, or
// reports the stream as truncated.
func (s *sseStream) finishAtEnd(cause string) {
	if s.flush() {
		return
	}
	if s.pendingDone {
		s.sendDone(nil)
		return
	}
	s.sendTruncated(cause)
}

// flush processes any buffered event. It returns true when the stream is done.
func (s *sseStream) flush() bool {
	if len(s.dataParts) == 0 {
		return false
	}
	data := strings.Join(s.dataParts, "\n")
	s.dataParts = s.dataParts[:0]
	return s.processEvent(data)
}

// processEvent handles one assembled SSE data payload. It returns true when
// the stream is finished.
func (s *sseStream) processEvent(data string) bool {
	if data == "[DONE]" {
		// [DONE] is an explicit end of response. A relay may send it with no
		// finish_reason before it; the turn is still complete, and any tool
		// calls it streamed must not be lost.
		if s.pendingDone || len(s.activeTools) > 0 || s.contentBytes > 0 {
			s.sendDone(nil)
		}
		return true
	}

	var chunk chatChunk
	if err := json.Unmarshal([]byte(data), &chunk); err != nil {
		s.send(normalize.ErrorEvent(fmt.Errorf("openai: parse chunk: %w", err)))
		return true
	}

	// Gateways can accept the HTTP request and report a provider error in an
	// SSE event instead. Preserve that cause before handling usage or
	// choices; otherwise it is discarded and misreported as EOF.
	if len(chunk.Error) > 0 && string(chunk.Error) != "null" {
		s.send(normalize.ErrorEvent(chunkError(chunk.Error)))
		return true
	}

	// Usage-only chunk (no choices).
	if chunk.Usage != nil && len(chunk.Choices) == 0 {
		s.sendDone(usageFromChunk(chunk.Usage))
		return true
	}

	// After a terminal finish_reason, any later chunk that carries usage
	// finalizes the turn even if it also has (empty) choices. Otherwise skip it.
	if s.pendingDone {
		if usage := usageFromChunk(chunk.Usage); usage != nil {
			s.sendDone(usage)
			return true
		}
		return false
	}

	for _, choice := range chunk.Choices {
		if s.processChoice(choice, chunk.Usage) {
			return true
		}
	}
	return false
}

// chunkError builds a stream error from an SSE error envelope. The envelope
// itself is not included: provider metadata may contain request bodies or
// other private diagnostics unrelated to the error.
func chunkError(raw json.RawMessage) error {
	var detail struct {
		Message string          `json:"message"`
		Code    json.RawMessage `json:"code"`
	}
	var message string
	if json.Unmarshal(raw, &detail) == nil {
		message = detail.Message
	} else {
		_ = json.Unmarshal(raw, &message)
	}
	if strings.TrimSpace(message) == "" {
		message = "provider returned an error event"
	}
	code := strings.TrimSpace(string(detail.Code))
	if strings.HasPrefix(code, "\"") {
		_ = json.Unmarshal(detail.Code, &code)
	}
	return &provider.StreamError{Provider: "openai", Code: code, Message: message}
}

// processChoice emits one choice's deltas and handles its finish_reason. It
// returns true when the stream is finished.
func (s *sseStream) processChoice(choice chunkChoice, chunkUsage *chunkUsage) bool {
	if len(choice.Delta.ReasoningDetails) > 0 {
		s.rdAcc.add(choice.Delta.ReasoningDetails)
	}
	if reasoning := extractReasoningText(choice.Delta); reasoning != "" {
		s.contentBytes += len(reasoning)
		s.send(normalize.ReasoningEvent(reasoning))
	}
	if choice.Delta.Content != "" {
		s.contentBytes += len(choice.Delta.Content)
		s.send(normalize.TokenEvent(choice.Delta.Content))
	}

	for _, tc := range choice.Delta.ToolCalls {
		acc, ok := s.activeTools[tc.Index]
		if !ok {
			acc = &toolAcc{}
			s.activeTools[tc.Index] = acc
		}
		if tc.ID != "" {
			acc.id = tc.ID
		}
		if tc.Function.Name != "" {
			acc.name = tc.Function.Name
			s.send(normalize.ToolUseDeltaEvent(acc.id, acc.name, ""))
		}
		if tc.Function.Arguments != "" {
			acc.args.WriteString(tc.Function.Arguments)
			s.send(normalize.ToolUseDeltaEvent(acc.id, acc.name, tc.Function.Arguments))
		}
	}

	if choice.FinishReason == nil {
		return false
	}
	switch reason := *choice.FinishReason; reason {
	case "error", "content_filter":
		s.send(normalize.ErrorEvent(fmt.Errorf("openai: upstream stream ended with finish_reason=%s", reason)))
		return true
	case "tool_calls", "stop", "length":
		s.finishReason = reason
		if usage := usageFromChunk(chunkUsage); usage != nil {
			s.sendDone(usage)
			return true
		}
		s.pendingDone = true
	}
	return false
}

type sseLine struct {
	line string
	err  error
	eof  bool
}

// readLines scans the body on its own goroutine so the caller can enforce an
// idle timeout. The channel closes when the reader stops.
func readLines(ctx context.Context, body interface{ Read([]byte) (int, error) }, stop <-chan struct{}) <-chan sseLine {
	lines := make(chan sseLine, 1)
	deliver := func(l sseLine) bool {
		select {
		case lines <- l:
			return true
		case <-stop:
			return false
		case <-ctx.Done():
			return false
		}
	}
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(body)
		scanner.Buffer(make([]byte, 64*1024), 512*1024)
		for scanner.Scan() {
			if !deliver(sseLine{line: scanner.Text()}) {
				return
			}
		}
		if err := scanner.Err(); err != nil {
			deliver(sseLine{err: err})
		} else {
			deliver(sseLine{eof: true})
		}
	}()
	return lines
}

func (c *Client) parseSSE(ctx context.Context, resp *http.Response, ch chan<- provider.StreamEvent) {
	defer close(ch)
	defer resp.Body.Close()

	s := &sseStream{ctx: ctx, resp: resp, ch: ch, activeTools: make(map[int]*toolAcc)}
	stop := make(chan struct{})
	defer close(stop)
	lines := readLines(ctx, resp.Body, stop)

	timer := time.NewTimer(sseIdleTimeout)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			if s.pendingDone {
				s.sendDone(nil)
			}
			return
		case <-timer.C:
			slog.Warn("openai stream idle timeout", "timeout", sseIdleTimeout)
			s.send(normalize.ErrorEvent(fmt.Errorf("openai: SSE stream idle timeout after %s", sseIdleTimeout)))
			return
		case sr, ok := <-lines:
			if !ok {
				s.finishAtEnd("scanner channel closed")
				return
			}
			if sr.eof {
				s.finishAtEnd("stream EOF")
				return
			}
			if sr.err != nil {
				if ctx.Err() == nil {
					s.send(normalize.ErrorEvent(fmt.Errorf("openai: stream read: %w", sr.err)))
				}
				return
			}

			// Reset the idle timer on every received line.
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(sseIdleTimeout)

			// bufio.Scanner strips the newline; drop a stray CR so CRLF-framed
			// streams still show the blank event boundary.
			line := strings.TrimSuffix(sr.line, "\r")
			if line == "" {
				if s.flush() {
					return
				}
				continue
			}
			if strings.HasPrefix(line, "data:") {
				// Strip the field name and one optional leading space, per the
				// SSE spec; providers differ on whether the space is sent.
				s.dataParts = append(s.dataParts, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
			}
			// Other lines (": " comments such as OpenRouter keep-alives, and
			// "event:"/"id:" fields) carry nothing we need.
		}
	}
}
