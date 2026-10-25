package api

import (
	"encoding/json"
	"strings"

	internal "github.com/Problem99-io/kodeblue/internal"
)

// publicEventStream projects durable runtime events onto the browser-facing
// stream. It never changes execution, stored events, or provider history.
type publicEventStream struct {
	pendingUsage map[internal.RunID]map[string]any
}

func (s *publicEventStream) visible(event internal.Event) (internal.Event, bool) {
	var payload map[string]any
	if json.Unmarshal(event.Payload, &payload) != nil || payload == nil {
		return event, true
	}
	private := payload["internal"] == true || payload["internal_tool_turn"] == true || payload["visibility"] == "internal"
	if strings.HasPrefix(event.Type, "tool.") {
		name, _ := payload["tool_name"].(string)
		if name == "" {
			name, _ = payload["name"].(string)
		}
		name = internal.CanonicalToolNameString(name)
		private = private || name == "report_suspicious_input"
		// Argument deltas are not safe for display until the full tool name is
		// known. Complete public tool.requested events retain all arguments.
		if event.Type == internal.EventToolCallStreaming && (name == "" || strings.HasPrefix("report_suspicious_input", name)) {
			return event, false
		}
	}
	if event.Type == internal.EventModelCompleted {
		if private {
			if s.pendingUsage == nil {
				s.pendingUsage = make(map[internal.RunID]map[string]any)
			}
			usage := map[string]any{}
			mergePublicUsage(usage, payload)
			mergePublicUsage(usage, s.pendingUsage[event.RunID])
			s.pendingUsage[event.RunID] = usage
			return event, false
		}
		mergePublicUsage(payload, s.pendingUsage[event.RunID])
		delete(s.pendingUsage, event.RunID)
	}
	if private {
		return event, false
	}
	if event.Type == internal.EventCompactionPerformed && payload["internal_summary"] == true {
		delete(payload, "summary_content")
	}
	if event.Type == internal.EventRunCompleted || event.Type == internal.EventRunFailed || event.Type == internal.EventRunAborted {
		mergePublicUsage(payload, s.pendingUsage[event.RunID])
		delete(s.pendingUsage, event.RunID)
	}
	delete(payload, "internal")
	delete(payload, "internal_tool_turn")
	delete(payload, "visibility")
	delete(payload, "internal_summary")
	event.Payload, _ = json.Marshal(payload)
	return event, true
}

// Merge numeric accounting only. Private content, arguments and diagnostics
// must not be carried into the next visible completion along with its usage.
func mergePublicUsage(target, extra map[string]any) {
	for _, field := range []string{"input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens"} {
		if value, ok := extra[field].(float64); ok {
			prior, _ := target[field].(float64)
			target[field] = prior + value
		}
	}
	if cost, ok := extra["cost"].(map[string]any); ok {
		merged, _ := target["cost"].(map[string]any)
		if merged == nil {
			merged = map[string]any{}
		}
		for _, field := range []string{"input_cost_usd", "output_cost_usd", "cache_creation_cost_usd", "cache_read_cost_usd", "raw_total_usd", "billed_total_usd"} {
			if value, ok := cost[field].(float64); ok {
				prior, _ := merged[field].(float64)
				merged[field] = prior + value
			}
		}
		target["cost"] = merged
	}
}

func messagesForPublicResponse(messages []internal.Message) []internal.Message {
	visible := internal.VisibleMessages(messages)
	byID := make(map[string]int, len(visible))
	for i, message := range visible {
		byID[message.ID] = i
	}
	pendingUsage := map[string]any{}
	for _, message := range messages {
		i, public := byID[message.ID]
		if !public {
			if message.Usage != nil {
				encoded, _ := json.Marshal(message.Usage)
				var usage map[string]any
				_ = json.Unmarshal(encoded, &usage)
				mergePublicUsage(pendingUsage, usage)
			}
			continue
		}
		if message.Role == "assistant" && len(pendingUsage) > 0 {
			usage := map[string]any{}
			if message.Usage != nil {
				encoded, _ := json.Marshal(message.Usage)
				_ = json.Unmarshal(encoded, &usage)
			}
			mergePublicUsage(usage, pendingUsage)
			encoded, _ := json.Marshal(usage)
			visible[i].Usage = &internal.MessageUsage{}
			_ = json.Unmarshal(encoded, visible[i].Usage)
			pendingUsage = map[string]any{}
		}
	}
	return visible
}
