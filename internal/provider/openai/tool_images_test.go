package openai

import (
	"testing"

	internal "github.com/Problem99-io/kodeblue/internal"
)

func TestToolResultImagesFollowAllToolResponses(t *testing.T) {
	msgs := convertMessage(internal.Message{Role: "user", ToolResults: []internal.ToolResult{{ToolCallID: "first", Content: "one"}, {ToolCallID: "second", Content: "two"}}, Attachments: []internal.Attachment{{MediaType: "image/png", FileName: "browser.png", Data: "aW1n"}}})
	if len(msgs) != 3 || msgs[0].Role != "tool" || msgs[0].ToolCallID != "first" || msgs[1].ToolCallID != "second" || msgs[2].Role != "user" {
		t.Fatalf("tool/image order: %+v", msgs)
	}
	parts, ok := msgs[2].Content.([]contentPart)
	if !ok || len(parts) != 2 || parts[1].ImageURL == nil || parts[1].ImageURL.URL != "data:image/png;base64,aW1n" {
		t.Fatalf("image content: %+v", msgs[2])
	}
}
