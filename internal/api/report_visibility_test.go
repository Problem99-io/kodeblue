package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	internal "github.com/Problem99-io/kodeblue/internal"
)

func reportFixtureEvents(sessionID internal.SessionID) []internal.Event {
	specs := []struct{ kind, payload string }{
		{internal.EventToolCallStreaming, `{"id":"private","partial_arguments":"PRIVATE_PAYLOAD"}`},
		{internal.EventToolCallStreaming, `{"id":"private","name":"report_sus","partial_arguments":"PRIVATE_PAYLOAD"}`},
		{internal.EventToolRequested, `{"tool_call_id":"private","tool_name":"report_suspicious_input","arguments":"PRIVATE_PAYLOAD","internal":true}`},
		{internal.EventToolOutput, `{"tool_call_id":"private","content":"PRIVATE_PAYLOAD","is_error":true,"internal":true}`},
		{internal.EventModelCompleted, `{"content":"PRIVATE_PAYLOAD","internal":true,"input_tokens":10,"output_tokens":2,"cost":{"billed_total_usd":0.1}}`},
		{internal.EventToolRequested, `{"tool_call_id":"public","tool_name":"read_file","arguments":"visible arguments"}`},
		{internal.EventToolOutput, `{"tool_call_id":"public","content":"visible file"}`},
		{internal.EventModelToken, `{"content":"Visible answer"}`},
		{internal.EventModelCompleted, `{"content":"Visible answer","input_tokens":12,"output_tokens":3,"cost":{"billed_total_usd":0.2}}`},
		{internal.EventCompactionPerformed, `{"summary_content":"PRIVATE_PAYLOAD","internal_summary":true,"compacted_messages":8}`},
		{internal.EventRunCompleted, `{"final_content":"Visible answer"}`},
	}
	events := make([]internal.Event, 0, len(specs))
	for _, spec := range specs {
		events = append(events, internal.Event{SessionID: sessionID, RunID: "run", Type: spec.kind, Timestamp: time.Now(), Payload: json.RawMessage(spec.payload)})
	}
	return events
}
func assertPublicReportEvents(t *testing.T, events []internal.Event) {
	t.Helper()
	encoded, _ := json.Marshal(events)
	for _, private := range []string{"PRIVATE_PAYLOAD", "report_sus", `"internal"`, `"internal_summary"`} {
		if strings.Contains(string(encoded), private) {
			t.Fatalf("private event reached browser: %s", encoded)
		}
	}
	if len(events) != 6 {
		t.Fatalf("lost public events: %s", encoded)
	}
	var completed map[string]any
	for _, event := range events {
		if event.Type == internal.EventModelCompleted {
			_ = json.Unmarshal(event.Payload, &completed)
		}
	}
	if completed["input_tokens"] != float64(22) || completed["output_tokens"] != float64(5) {
		t.Fatalf("lost usage: %#v", completed)
	}
	cost := completed["cost"].(map[string]any)["billed_total_usd"].(float64)
	if cost < 0.29999 || cost > 0.30001 {
		t.Fatalf("cost=%v", cost)
	}
}
func TestReportEventHistoryFiltersOnlyPublicProjection(t *testing.T) {
	deps, _ := setupTestDeps(t)
	now := time.Now()
	session := &internal.Session{ID: internal.NewSessionID(), Status: internal.SessionActive, CreatedAt: now, UpdatedAt: now}
	if err := deps.Sessions.Create(session); err != nil {
		t.Fatal(err)
	}
	fixtures := reportFixtureEvents(session.ID)
	for _, event := range fixtures {
		if err := deps.Events.Append(&event); err != nil {
			t.Fatal(err)
		}
	}
	router := NewRouter(deps)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/sessions/"+string(session.ID)+"/events/history?include_tokens=true", nil))
	if response.Code != 200 {
		t.Fatal(response.Body.String())
	}
	var public []internal.Event
	if err := json.Unmarshal(response.Body.Bytes(), &public); err != nil {
		t.Fatal(err)
	}
	assertPublicReportEvents(t, public)
	raw, err := deps.Events.GetBySession(session.ID, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(raw)
	if len(raw) != len(fixtures) || !strings.Contains(string(encoded), "PRIVATE_PAYLOAD") {
		t.Fatal("public projection deleted backend evidence")
	}
}

func TestPersistedReportMessagesRemainPrivateAfterReload(t *testing.T) {
	deps, _ := setupTestDeps(t)
	now := time.Now()
	session := &internal.Session{ID: internal.NewSessionID(), Status: internal.SessionActive, CreatedAt: now, UpdatedAt: now}
	if err := deps.Sessions.Create(session); err != nil {
		t.Fatal(err)
	}
	messages := []internal.Message{
		{ID: "input", Role: "user", Content: "Original task", CreatedAt: now},
		{ID: "report", Role: "assistant", Internal: true, Content: "PRIVATE_PAYLOAD", ToolCalls: []internal.ToolCall{{ID: "private", Name: "report_suspicious_input", Arguments: json.RawMessage(`{"summary":"PRIVATE_PAYLOAD"}`), Internal: true}}, Usage: &internal.MessageUsage{InputTokens: 10, OutputTokens: 2}, CreatedAt: now},
		{ID: "result", Role: "user", ToolResults: []internal.ToolResult{{ToolCallID: "private", Content: "PRIVATE_PAYLOAD", IsError: true, Internal: true}}, CreatedAt: now},
		{ID: "summary", Role: "user", Internal: true, Content: "PRIVATE_PAYLOAD in compacted context", CreatedAt: now},
		{ID: "answer", Role: "assistant", Content: "Visible answer", Usage: &internal.MessageUsage{InputTokens: 12, OutputTokens: 3}, CreatedAt: now},
	}
	if err := deps.Messages.CompactMessages(session.ID, "run", messages); err != nil {
		t.Fatal(err)
	}
	raw, err := deps.Messages.GetBySession(session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 5 || !raw[1].Internal || !raw[3].Internal || !raw[2].ToolResults[0].IsError {
		t.Fatalf("lost private context: %#v", raw)
	}
	w := httptest.NewRecorder()
	NewRouter(deps).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/v1/sessions/"+string(session.ID)+"/messages", nil))
	if w.Code != 200 || strings.Contains(w.Body.String(), "PRIVATE_PAYLOAD") || strings.Contains(w.Body.String(), "report_suspicious_input") {
		t.Fatalf("leaked transcript: %s", w.Body.String())
	}
	var public []messageResponse
	if err := json.Unmarshal(w.Body.Bytes(), &public); err != nil {
		t.Fatal(err)
	}
	if len(public) != 2 || public[1].Usage.InputTokens != 22 || public[1].Usage.OutputTokens != 5 {
		t.Fatalf("lost visible conversation or usage: %#v", public)
	}
	// Output folding must not mutate usage in the raw operational transcript.
	if raw[4].Usage.InputTokens != 12 {
		t.Fatal("public projection changed raw accounting")
	}
}
func TestPrivateUsageDoesNotCrossRunsOrLeakOnFailure(t *testing.T) {
	stream := &publicEventStream{}
	_, show := stream.visible(internal.Event{RunID: "private", Type: internal.EventModelCompleted, Payload: json.RawMessage(`{"internal":true,"input_tokens":10,"content":"PRIVATE_PAYLOAD"}`)})
	if show {
		t.Fatal("private completion shown")
	}
	visible, _ := stream.visible(internal.Event{RunID: "other", Type: internal.EventModelCompleted, Payload: json.RawMessage(`{"input_tokens":3}`)})
	if strings.Contains(string(visible.Payload), "13") {
		t.Fatal("usage crossed runs")
	}
	visible, show = stream.visible(internal.Event{RunID: "private", Type: internal.EventRunFailed, Payload: json.RawMessage(`{"reason":"provider failed"}`)})
	if !show || !strings.Contains(string(visible.Payload), `"input_tokens":10`) || strings.Contains(string(visible.Payload), "PRIVATE_PAYLOAD") {
		t.Fatalf("bad terminal usage: %s", visible.Payload)
	}
}
