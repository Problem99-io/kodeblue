package internal

import "strings"

// Question kinds distinguish a question the model chose to ask (ask_user) from
// one the system asked on its own. The kind is persisted so a question can
// still be interpreted correctly after the run that asked it is gone.
const (
	QuestionKindAskUser      = "ask_user"
	QuestionKindContinuation = "continuation"
)

// Continuation checkpoint choices. These are the labels the user clicks, so
// they are also what comes back in the answer and are matched exactly.
const (
	ContinueYesOption = "Yes, keep going"
	ContinueNoOption  = "No, stop here"
)

// continuationStopWords are free-text answers meant as "stop" rather than as
// steering. Anything else typed in the free-text box is guidance, and guidance
// implies the run should carry on with a correction.
var continuationStopWords = map[string]bool{
	"no": true, "n": true, "nope": true, "stop": true, "halt": true,
	"cancel": true, "abort": true, "quit": true, "no thanks": true,
}

// InterpretContinuationAnswer maps a user's answer to a continuation checkpoint
// into whether the run proceeds and, if so, any free-text steering to hand the
// model along with the tool results the checkpoint is holding.
//
// A clicked option decides on its own. Free text stops the run only when it is
// a bare negative ("no", "stop"); otherwise it is guidance, which continues.
// An empty answer follows the recommended option and continues.
func InterpretContinuationAnswer(answer QuestionAnswer) (proceed bool, guidance string) {
	choice := ""
	if len(answer.Choices) > 0 {
		choice = strings.TrimSpace(answer.Choices[0])
	}
	text := strings.TrimSpace(answer.Text)

	switch choice {
	case ContinueYesOption:
		// The user can pick "yes" and still type a correction alongside it.
		if text == ContinueYesOption {
			text = ""
		}
		return true, text
	case ContinueNoOption:
		return false, ""
	}

	if text == "" {
		return true, ""
	}
	if continuationStopWords[strings.ToLower(strings.Trim(text, ".!"))] {
		return false, ""
	}
	return true, text
}
