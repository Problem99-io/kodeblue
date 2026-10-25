package agent

import (
	"encoding/json"
	"testing"

	internal "github.com/Problem99-io/kodeblue/internal"
)

func TestNormalizeToolArgumentsEmptyIsMarshalable(t *testing.T) {
	for _, in := range []string{"", "  ", "\n"} {
		tc := internal.ToolCall{ID: "c1", Name: "stats", Arguments: normalizeToolArguments(in)}
		if _, err := json.Marshal(tc); err != nil {
			t.Fatalf("arguments %q: %v", in, err)
		}
	}
	if got := string(normalizeToolArguments(`{"a":1}`)); got != `{"a":1}` {
		t.Fatalf("non-empty arguments changed: %s", got)
	}
}
