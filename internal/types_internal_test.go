package internal

import (
	"encoding/json"
	"testing"
)

func TestVisibleMessagesRemovesInternalToolExchange(t *testing.T) {
	messages := []Message{
		{ID: "assistant-hidden", Role: "assistant", Content: "incidental hidden-turn text", Internal: true, ToolCalls: []ToolCall{{ID: "hidden", Name: "report_suspicious_input", Arguments: json.RawMessage(`{"summary":"safe"}`), Internal: true}}},
		{ID: "tool-hidden", Role: "user", ToolResults: []ToolResult{{ToolCallID: "hidden", Content: "Continue.", Internal: true}}},
		{ID: "assistant-visible", Role: "assistant", Content: "Visible answer"},
	}

	visible := VisibleMessages(messages)
	if len(visible) != 1 || visible[0].ID != "assistant-visible" {
		t.Fatalf("visible messages = %#v, want only final assistant message", visible)
	}
}

func TestVisibleMessagesPreservesVisibleCallsFromMixedTurn(t *testing.T) {
	messages := []Message{{
		ID: "mixed", Role: "assistant", ToolCalls: []ToolCall{
			{ID: "hidden", Name: "report_suspicious_input", Internal: true},
			{ID: "visible", Name: "read_file"},
		},
	}}
	visible := VisibleMessages(messages)
	if len(visible) != 1 || len(visible[0].ToolCalls) != 1 || visible[0].ToolCalls[0].ID != "visible" {
		t.Fatalf("mixed turn was not filtered correctly: %#v", visible)
	}
}

func TestVisibleMessagesHandlesLegacyReportFlagsAndMixedResults(t *testing.T) {
	messages := []Message{
		{ID: "calls", Role: "assistant", ToolCalls: []ToolCall{{ID: "private", Name: "report_suspicious_input"}, {ID: "public", Name: "read_file"}}},
		{ID: "results", Role: "user", ToolResults: []ToolResult{{ToolCallID: "private", Content: "PRIVATE"}, {ToolCallID: "public", Content: "public file"}}},
	}
	visible := VisibleMessages(messages)
	if len(visible) != 2 || len(visible[0].ToolCalls) != 1 || visible[0].ToolCalls[0].ID != "public" || len(visible[1].ToolResults) != 1 || visible[1].ToolResults[0].Content != "public file" {
		t.Fatalf("incorrect legacy projection: %#v", visible)
	}
	if len(messages[0].ToolCalls) != 2 || len(messages[1].ToolResults) != 2 {
		t.Fatal("public projection changed raw history")
	}
}
