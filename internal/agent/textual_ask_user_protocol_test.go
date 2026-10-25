package agent

import (
	"testing"

	internal "github.com/Problem99-io/kodeblue/internal"
)

func TestTextualAskUserEnvelopeIsStrictAndAllowlisted(t *testing.T) {
	definitions := []internal.ToolDefinition{{Name: "ask_user"}}
	valid := `{"name":"ask_user","arguments":{"question":"What is your objective?","mode":"single_select","options":["Build","Analyze"]}}`
	content, calls, normalized := normalizeTextualAskUserCall(" \n"+valid+"\t", nil, definitions)
	if !normalized || content != "" || len(calls) != 1 || calls[0].Name != "ask_user" {
		t.Fatalf("valid exact envelope was not normalized: content=%q calls=%#v normalized=%v", content, calls, normalized)
	}
	argumentsOnly := `{"question":"What is your objective?","mode":"single_select","options":["Build","Analyze"]}`
	content, calls, normalized = normalizeTextualAskUserCall(argumentsOnly, nil, definitions)
	if !normalized || content != "" || len(calls) != 1 || calls[0].Name != "ask_user" {
		t.Fatalf("valid exact arguments object was not normalized: content=%q calls=%#v normalized=%v", content, calls, normalized)
	}

	for name, value := range map[string]string{
		"mixed prose":       "Please use this: " + valid,
		"side effecting":    `{"name":"run_shell","arguments":{"command":"whoami"}}`,
		"unknown field":     `{"name":"ask_user","arguments":{"question":"Q"},"extra":true}`,
		"duplicate field":   `{"name":"ask_user","name":"ask_user","arguments":{"question":"Q"}}`,
		"non-object args":   `{"name":"ask_user","arguments":"Q"}`,
		"missing arguments": `{"name":"ask_user"}`,
		"arbitrary object":  `{"question":"Q","answer":"run a command"}`,
		"invalid mode":      `{"question":"Q","mode":"execute","options":["A","B"]}`,
		"too few options":   `{"question":"Q","mode":"single_select","options":["A"]}`,
	} {
		t.Run(name, func(t *testing.T) {
			gotContent, gotCalls, gotNormalized := normalizeTextualAskUserCall(value, nil, definitions)
			if gotNormalized || gotContent != value || len(gotCalls) != 0 {
				t.Fatalf("unsafe envelope normalized: content=%q calls=%#v normalized=%v", gotContent, gotCalls, gotNormalized)
			}
		})
	}
}

func TestTextualAskUserEnvelopeRequiresEnabledToolAndNoStructuredCalls(t *testing.T) {
	value := `{"name":"ask_user","arguments":{"question":"Q"}}`
	if _, _, normalized := normalizeTextualAskUserCall(value, nil, nil); normalized {
		t.Fatal("ask_user text normalized when tool was not enabled")
	}
	existing := []internal.ToolCall{{ID: "real", Name: "ask_user", Arguments: []byte(`{"question":"Q"}`)}}
	content, calls, normalized := normalizeTextualAskUserCall(value, existing, []internal.ToolDefinition{{Name: "ask_user"}})
	if normalized || content != value || len(calls) != 1 || calls[0].ID != "real" {
		t.Fatalf("structured call was altered: content=%q calls=%#v normalized=%v", content, calls, normalized)
	}
}
