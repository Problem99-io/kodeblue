package agent

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"

	internal "github.com/Problem99-io/kodeblue/internal"
)

// normalizeTextualAskUserCall is a narrowly-scoped compatibility path for
// local OpenAI-compatible models that sometimes serialize the harmless
// ask_user UI request as an exact JSON envelope instead of tool_calls. It must
// not grow into a general assistant-text-to-tool execution mechanism.
func normalizeTextualAskUserCall(content string, calls []internal.ToolCall, definitions []internal.ToolDefinition) (string, []internal.ToolCall, bool) {
	if len(calls) != 0 || !toolDefinitionEnabled(definitions, "ask_user") {
		return content, calls, false
	}
	arguments, ok := parseTextualAskUserEnvelope(content)
	if !ok {
		return content, calls, false
	}
	return "", append(calls, internal.ToolCall{
		ID:        internal.NewID("call"),
		Name:      "ask_user",
		Arguments: arguments,
	}), true
}

func toolDefinitionEnabled(definitions []internal.ToolDefinition, name internal.ToolName) bool {
	for _, definition := range definitions {
		if internal.CanonicalToolName(definition.Name) == name {
			return true
		}
	}
	return false
}

func parseTextualAskUserEnvelope(content string) (json.RawMessage, bool) {
	raw := []byte(strings.TrimSpace(content))
	if len(raw) == 0 {
		return nil, false
	}
	if validTextualAskUserArguments(raw, true) {
		return append(json.RawMessage(nil), raw...), true
	}
	if !hasUniqueTopLevelFields(raw, "name", "arguments") {
		return nil, false
	}
	var envelope struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, false
	}
	if envelope.Name != "ask_user" || len(envelope.Arguments) == 0 {
		return nil, false
	}
	if !validTextualAskUserArguments(envelope.Arguments, true) {
		return nil, false
	}
	return append(json.RawMessage(nil), envelope.Arguments...), true
}

func validTextualAskUserArguments(raw []byte, allowBatch bool) bool {
	allowed := []string{"title", "question", "mode", "options", "recommended", "recommended_choices"}
	if allowBatch {
		allowed = append(allowed, "questions")
	}
	fields, ok := uniqueAllowedTopLevelFields(raw, allowed...)
	if !ok {
		return false
	}
	if _, batch := fields["questions"]; batch {
		if !allowBatch || len(fields) != 1 {
			return false
		}
		var value struct {
			Questions []json.RawMessage `json:"questions"`
		}
		if err := json.Unmarshal(raw, &value); err != nil || len(value.Questions) == 0 {
			return false
		}
		for _, question := range value.Questions {
			if !validTextualAskUserArguments(question, false) {
				return false
			}
		}
		return true
	}
	if _, hasQuestion := fields["question"]; !hasQuestion {
		return false
	}
	if _, hasMode := fields["mode"]; !hasMode {
		return false
	}
	var value struct {
		Question string   `json:"question"`
		Mode     string   `json:"mode"`
		Options  []string `json:"options"`
	}
	if err := json.Unmarshal(raw, &value); err != nil || strings.TrimSpace(value.Question) == "" {
		return false
	}
	if value.Mode != "single_select" && value.Mode != "multi_select" {
		return false
	}
	if len(value.Options) < 2 {
		return false
	}
	for _, option := range value.Options {
		if strings.TrimSpace(option) == "" {
			return false
		}
	}
	return true
}

func hasUniqueTopLevelFields(raw []byte, required ...string) bool {
	seen, ok := uniqueAllowedTopLevelFields(raw, required...)
	return ok && len(seen) == len(required)
}

func uniqueAllowedTopLevelFields(raw []byte, allowed ...string) (map[string]struct{}, bool) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return nil, false
	}
	want := make(map[string]struct{}, len(allowed))
	for _, field := range allowed {
		want[field] = struct{}{}
	}
	seen := make(map[string]struct{}, len(allowed))
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return nil, false
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, false
		}
		if _, allowed := want[key]; !allowed {
			return nil, false
		}
		if _, duplicate := seen[key]; duplicate {
			return nil, false
		}
		seen[key] = struct{}{}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, false
		}
	}
	last, err := decoder.Token()
	if err != nil || last != json.Delim('}') || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, false
	}
	return seen, true
}
