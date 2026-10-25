package openai

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestReasoningDeltaPreservesWhitespace(t *testing.T) {
	for _, fallback := range []bool{false, true} {
		var joined strings.Builder
		for _, part := range []string{"The", " user", " ", "wants", "\n", "tool calls. "} {
			raw, _ := json.Marshal(part)
			delta := chunkDelta{ReasoningContent: raw}
			if fallback {
				delta = chunkDelta{Reasoning: raw}
			}
			joined.WriteString(extractReasoningText(delta))
		}
		if got := joined.String(); got != "The user wants\ntool calls. " {
			t.Fatalf("lost token spacing: %q", got)
		}
	}
}
