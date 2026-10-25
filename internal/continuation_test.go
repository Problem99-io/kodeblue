package internal

import "testing"

func TestInterpretContinuationAnswer(t *testing.T) {
	cases := []struct {
		name     string
		answer   QuestionAnswer
		proceed  bool
		guidance string
	}{
		{
			name:    "yes option continues",
			answer:  QuestionAnswer{Choices: []string{ContinueYesOption}},
			proceed: true,
		},
		{
			name:    "no option stops",
			answer:  QuestionAnswer{Choices: []string{ContinueNoOption}},
			proceed: false,
		},
		{
			name:    "no option wins over echoed text",
			answer:  QuestionAnswer{Choices: []string{ContinueNoOption}, Text: ContinueNoOption},
			proceed: false,
		},
		{
			// The tool layer copies a single choice into Text; that is not guidance.
			name:    "yes option with echoed text carries no guidance",
			answer:  QuestionAnswer{Choices: []string{ContinueYesOption}, Text: ContinueYesOption},
			proceed: true,
		},
		{
			name:     "yes option plus a typed correction",
			answer:   QuestionAnswer{Choices: []string{ContinueYesOption}, Text: "skip the tests"},
			proceed:  true,
			guidance: "skip the tests",
		},
		{
			name:     "free text alone is guidance and continues",
			answer:   QuestionAnswer{Text: "  focus on the parser  "},
			proceed:  true,
			guidance: "focus on the parser",
		},
		{
			name:    "bare negative free text stops",
			answer:  QuestionAnswer{Text: "No."},
			proceed: false,
		},
		{
			name:    "empty answer follows the recommendation",
			answer:  QuestionAnswer{},
			proceed: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proceed, guidance := InterpretContinuationAnswer(tc.answer)
			if proceed != tc.proceed {
				t.Fatalf("proceed = %v, want %v", proceed, tc.proceed)
			}
			if guidance != tc.guidance {
				t.Fatalf("guidance = %q, want %q", guidance, tc.guidance)
			}
		})
	}
}
