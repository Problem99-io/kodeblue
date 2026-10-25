package internal

// CanonicalToolName normalizes legacy aliases to the model-facing tool name.
func CanonicalToolName(name ToolName) ToolName {
	if name == "grep_search" {
		return "grep"
	}
	if name == "memory_notes" {
		return "create_definition"
	}
	return name
}

// CanonicalToolNameString normalizes a string tool name.
func CanonicalToolNameString(name string) string {
	return string(CanonicalToolName(ToolName(name)))
}
