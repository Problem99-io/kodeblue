package agent

import (
	"strings"

	internal "github.com/Problem99-io/kodeblue/internal"
)

// qualifyBareToolNames fixes the two ways models misname tools. A call to an
// MCP tool by its bare name ("host_exec") becomes the registered name
// ("mcp__kodeblue__host_exec"), and a built-in tool called with an MCP prefix
// ("mcp__kodeblue__patch_definition") loses it. Prompts name tools the short
// way and models carry a prefix over from neighbouring tools; without this
// the allowlist refuses the call and the model concludes the tool does not
// exist. A name is only rewritten when it is not itself a tool and the
// rewrite names exactly one tool.
func qualifyBareToolNames(calls []internal.ToolCall, defs []internal.ToolDefinition) []internal.ToolCall {
	if len(calls) == 0 || len(defs) == 0 {
		return calls
	}
	known := make(map[string]bool, len(defs))
	bare := make(map[string]string)
	for _, def := range defs {
		name := string(internal.CanonicalToolName(def.Name))
		known[name] = true
		if !strings.HasPrefix(name, "mcp__") {
			continue
		}
		i := strings.LastIndex(name, "__")
		if i <= len("mcp_") {
			continue
		}
		short := name[i+2:]
		if _, dup := bare[short]; dup {
			bare[short] = "" // ambiguous between servers: leave it alone
			continue
		}
		bare[short] = name
	}
	for i, call := range calls {
		name := string(internal.CanonicalToolName(call.Name))
		if known[name] {
			continue
		}
		if full := bare[name]; full != "" {
			calls[i].Name = internal.ToolName(full)
			continue
		}
		if strings.HasPrefix(name, "mcp__") {
			if j := strings.LastIndex(name, "__"); j > len("mcp_") && known[name[j+2:]] && !strings.HasPrefix(name[j+2:], "mcp__") {
				calls[i].Name = internal.ToolName(name[j+2:])
			}
		}
	}
	return calls
}
