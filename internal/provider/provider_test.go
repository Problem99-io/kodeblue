package provider

import (
	"encoding/json"
	"testing"
)

func TestSanitizeToolArguments(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"valid object", `{"path":"README.md"}`, `{"path":"README.md"}`},
		{"valid empty object", `{}`, `{}`},
		{"valid nested", `{"a":{"b":[1,2,3]},"c":"x"}`, `{"a":{"b":[1,2,3]},"c":"x"}`},
		{"valid non-object json is left alone", `"just a string"`, `"just a string"`},
		{"empty blob preserved", ``, ``},
		{"whitespace-only preserved", "  \n\t ", "  \n\t "},
		// The reported failure: a shell command truncated mid-string when the
		// generation was cut off. Unparseable, so it must be repaired.
		{"truncated string value", `{"command":"find backend && go build ./... 2>`, `{}`},
		{"truncated missing closing brace", `{"path":"README.md"`, `{}`},
		{"truncated key", `{"comm`, `{}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := string(SanitizeToolArguments(json.RawMessage(tc.in)))
			if got != tc.want {
				t.Fatalf("SanitizeToolArguments(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestSanitizeToolArguments_OutputAlwaysReplayable proves the core invariant:
// after sanitizing, a non-empty result is always valid JSON, so it can never
// trigger the provider-side "EOF while parsing a string" 400 on replay.
func TestSanitizeToolArguments_OutputAlwaysReplayable(t *testing.T) {
	inputs := []string{
		`{"command":"go build ./... 2>`, // the export's truncated run_shell
		`{"x":`,
		`[1,2,`,
		`{"nested":{"deep":`,
		`not json at all`,
	}
	for _, in := range inputs {
		out := SanitizeToolArguments(json.RawMessage(in))
		if len(out) == 0 {
			t.Fatalf("input %q produced empty output", in)
		}
		if !json.Valid(out) {
			t.Fatalf("input %q produced non-replayable output %q", in, string(out))
		}
	}
}
