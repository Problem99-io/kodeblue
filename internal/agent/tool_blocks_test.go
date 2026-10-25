package agent

import (
	"strings"
	"testing"
)

func toolSet(names ...string) map[string]bool {
	set := map[string]bool{}
	for _, n := range names {
		set[n] = true
	}
	return set
}

// A prompt with no directives must come back byte-identical. The compaction
// path rebuilds the system prompt and relies on it matching the run prompt
// exactly, so any rewriting here would silently break prompt caching.
func TestResolveToolBlocksLeavesUndirectedTextIdentical(t *testing.T) {
	text := "Plain instructions.\n\nKeep this prompt byte-identical.\n"
	if got := ResolveToolBlocks(text, toolSet()); got != text {
		t.Error("undirected text was modified")
	}
}

func TestResolveToolBlocksKeepsAndDrops(t *testing.T) {
	text := strings.Join([]string{
		"head",
		"<!--if:run_shell-->",
		"shell guidance",
		"<!--endif-->",
		"<!--if:write_file,edit_file-->",
		"editing guidance",
		"<!--endif-->",
		"tail",
	}, "\n")

	got := ResolveToolBlocks(text, toolSet("edit_file"))
	if strings.Contains(got, "shell guidance") {
		t.Error("kept a block whose tool is absent")
	}
	if !strings.Contains(got, "editing guidance") {
		t.Error("dropped a block where one of the listed tools is present")
	}
	if !strings.Contains(got, "head") || !strings.Contains(got, "tail") {
		t.Error("dropped text outside the directives")
	}
	if strings.Contains(got, "<!--if:") || strings.Contains(got, "<!--endif-->") {
		t.Errorf("directive markers survived: %q", got)
	}
}

// A narrow block inside a broad one must not be emitted just because the outer
// one was kept — this is the bug the bundled-agent test caught, where a
// read-only agent was shown write-tool guidance nested under a read block.
func TestResolveToolBlocksNesting(t *testing.T) {
	text := strings.Join([]string{
		"<!--if:read_file-->",
		"outer",
		"<!--if:write_file-->",
		"inner",
		"<!--endif-->",
		"outer tail",
		"<!--endif-->",
	}, "\n")

	got := ResolveToolBlocks(text, toolSet("read_file"))
	if !strings.Contains(got, "outer") || !strings.Contains(got, "outer tail") {
		t.Errorf("outer block was dropped: %q", got)
	}
	if strings.Contains(got, "inner") {
		t.Errorf("nested block emitted without its tool: %q", got)
	}

	if got := ResolveToolBlocks(text, toolSet("write_file")); strings.Contains(got, "inner") {
		t.Errorf("nested block emitted while its parent was dropped: %q", got)
	}
}

func TestResolveToolBlocksCanonicalizesNames(t *testing.T) {
	text := "<!--if:grep_search-->\nsearch guidance\n<!--endif-->"
	if got := ResolveToolBlocks(text, toolSet("grep")); !strings.Contains(got, "search guidance") {
		t.Errorf("alias %q was not canonicalized to %q", "grep_search", "grep")
	}
}
