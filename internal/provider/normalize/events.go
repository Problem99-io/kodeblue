package normalize

import (
	"github.com/Problem99-io/kodeblue/internal/provider"
)

// TokenEvent creates a StreamEvent carrying a text token.
func TokenEvent(content string) provider.StreamEvent {
	return provider.StreamEvent{
		Type:    provider.EventToken,
		Content: content,
		Channel: provider.ChannelText,
	}
}

// ReasoningEvent creates a StreamEvent carrying a reasoning/thinking token.
func ReasoningEvent(content string) provider.StreamEvent {
	return provider.StreamEvent{
		Type:    provider.EventToken,
		Content: content,
		Channel: provider.ChannelReasoning,
	}
}

// ToolUseEvent creates a StreamEvent for a tool invocation.
func ToolUseEvent(id, name, args string) provider.StreamEvent {
	return provider.StreamEvent{
		Type: provider.EventToolUse,
		ToolCall: &provider.ToolCallEvent{
			ID:        id,
			Name:      name,
			Arguments: args,
		},
	}
}

// ToolUseDeltaEvent creates a StreamEvent carrying a partial fragment of a tool
// invocation's arguments while the model is still streaming it. A fragment of ""
// signals that a tool call has started (id and name known, arguments pending).
func ToolUseDeltaEvent(id, name, fragment string) provider.StreamEvent {
	return provider.StreamEvent{
		Type: provider.EventToolUseDelta,
		ToolCall: &provider.ToolCallEvent{
			ID:        id,
			Name:      name,
			Arguments: fragment,
		},
	}
}

// DoneEvent creates a StreamEvent indicating the stream is finished.
func DoneEvent(usage *provider.Usage) provider.StreamEvent {
	return provider.StreamEvent{
		Type:  provider.EventDone,
		Usage: usage,
		Done:  true,
	}
}

// ErrorEvent creates a StreamEvent carrying an error.
func ErrorEvent(err error) provider.StreamEvent {
	return provider.StreamEvent{
		Type:  provider.EventError,
		Error: err,
		Done:  true,
	}
}
