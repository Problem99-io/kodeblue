package agent

import (
	_ "embed"
	"strings"
)

// baseInstructionsMarkdown is the prompt every session starts from: who the
// agent is, how kodeblue works and the rules it must follow. Each agent's role
// instructions are appended after it.
//
//go:embed sysprompt/base.md
var baseInstructionsMarkdown string

// BaseInstructions returns the shared base prompt.
func BaseInstructions() string {
	return strings.TrimSpace(baseInstructionsMarkdown)
}
