package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

// ToolConfig holds shared configuration for all tools.
type ToolConfig struct {
	ProjectRoot     string
	DefinitionsRoot string
	MaxOutputBytes  int64
}

// effectiveRoot returns the per-session CWD if set in the context,
// otherwise falls back to the tool's configured ProjectRoot.
func effectiveRoot(ctx context.Context, cfg ToolConfig) string {
	if cwd := SessionCWDFromContext(ctx); cwd != "" {
		return cwd
	}
	return cfg.ProjectRoot
}

// validatePath resolves requestedPath relative to projectRoot and ensures it
// does not escape the project root via traversal. Returns the cleaned absolute path.
func validatePath(projectRoot, requestedPath string) (string, error) {
	if requestedPath == "" {
		return "", fmt.Errorf("path must not be empty")
	}

	var abs string
	if filepath.IsAbs(requestedPath) {
		abs = filepath.Clean(requestedPath)
	} else {
		abs = filepath.Clean(filepath.Join(projectRoot, requestedPath))
	}

	rel, err := filepath.Rel(projectRoot, abs)
	if err != nil {
		return "", fmt.Errorf("invalid path: %w", err)
	}
	if strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("path %q escapes project root", requestedPath)
	}
	return abs, nil
}

// makeSchema builds a JSON Schema object from a properties map and required field list.
func makeSchema(properties map[string]any, required []string) json.RawMessage {
	schema := map[string]any{
		"type":       "object",
		"properties": properties,
	}
	if len(required) > 0 {
		schema["required"] = required
	}
	b, err := json.Marshal(schema)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return json.RawMessage(b)
}
