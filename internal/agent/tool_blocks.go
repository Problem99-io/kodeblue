package agent

import (
	"strings"

	internal "github.com/Problem99-io/kodeblue/internal"
)

// Prompt text may name tools the agent holding it does not actually have. That
// is not cosmetic: an agent told to `ask_user` when it has no such tool either
// ignores the instruction or wastes a turn, and an agent told to use
// `explore_project` (defined but never registered) is being pointed at nothing.
//
// A prompt can therefore fence any block that only makes sense with a given
// tool:
//
//	<!--if:edit_file,write_file-->
//	...guidance that only applies when you can edit files...
//	<!--endif-->
//
// The block is kept when the agent holds AT LEAST ONE of the listed tools, and
// dropped otherwise. Blocks nest, so a broad section can carry narrower
// paragraphs inside it. Prompts with no directives pass through byte-identical,
// which keeps this safe to run over every prompt including the compaction
// parity path.
const (
	toolBlockOpenPrefix = "<!--if:"
	toolBlockOpenSuffix = "-->"
	toolBlockClose      = "<!--endif-->"
)

// ResolveToolBlocks removes the tool-conditioned blocks in text whose tools are
// absent from available, and strips the directive markers from the ones it
// keeps. An unterminated block is dropped along with the rest of the text after
// it, which fails closed: a malformed prompt loses guidance rather than
// advertising tools that may not exist.
func ResolveToolBlocks(text string, available map[string]bool) string {
	if !strings.Contains(text, toolBlockOpenPrefix) {
		return text
	}

	// keep[i] reports whether the block at depth i+1 is being emitted. A nested
	// block is only emitted when every block enclosing it is too.
	var keep []bool
	emitting := func() bool {
		for _, k := range keep {
			if !k {
				return false
			}
		}
		return true
	}

	lines := strings.Split(text, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		switch {
		case strings.HasPrefix(trimmed, toolBlockOpenPrefix) && strings.HasSuffix(trimmed, toolBlockOpenSuffix):
			names := strings.TrimSuffix(strings.TrimPrefix(trimmed, toolBlockOpenPrefix), toolBlockOpenSuffix)
			keep = append(keep, anyToolAvailable(names, available))
		case trimmed == toolBlockClose:
			if len(keep) > 0 {
				keep = keep[:len(keep)-1]
			}
		default:
			if emitting() {
				out = append(out, line)
			}
		}
	}

	return collapseBlankRuns(strings.Join(out, "\n"))
}

// anyToolAvailable reports whether any of the comma-separated tool names is
// available. An empty list keeps the block: a directive with no tools names no
// requirement.
func anyToolAvailable(names string, available map[string]bool) bool {
	listed := false
	for _, name := range strings.Split(names, ",") {
		name = internal.CanonicalToolNameString(strings.TrimSpace(name))
		if name == "" {
			continue
		}
		listed = true
		if available[name] {
			return true
		}
	}
	return !listed
}

// AvailableToolSet indexes tool definitions by canonical name for
// ResolveToolBlocks.
func AvailableToolSet(defs []internal.ToolDefinition) map[string]bool {
	set := make(map[string]bool, len(defs))
	for i := range defs {
		set[internal.CanonicalToolNameString(string(defs[i].Name))] = true
	}
	return set
}

// collapseBlankRuns squeezes the blank-line runs that dropping a block leaves
// behind, so a filtered prompt reads like one that was written that way.
func collapseBlankRuns(text string) string {
	lines := strings.Split(text, "\n")
	out := make([]string, 0, len(lines))
	blanks := 0
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			blanks++
			if blanks > 1 {
				continue
			}
		} else {
			blanks = 0
		}
		out = append(out, line)
	}
	return strings.TrimSpace(strings.Join(out, "\n"))
}
