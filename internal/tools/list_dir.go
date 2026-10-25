package tools

import (
	"context"
	"encoding/json"
	"os"
	"strings"

	internal "github.com/Problem99-io/kodeblue/internal"
	"github.com/Problem99-io/kodeblue/internal/definitions"
)

type listDirTool struct {
	cfg ToolConfig
}

// NewListDir creates a list_dir tool.
func NewListDir(cfg ToolConfig) Tool {
	return &listDirTool{cfg: cfg}
}

func (t *listDirTool) Name() internal.ToolName { return "list_dir" }

func (t *listDirTool) Description() string {
	return "List directory contents. Directories end with '/'. When you need to inspect several directories, issue the calls in parallel in a single step (or from programmatic_tool_caller) instead of one at a time."
}

func (t *listDirTool) Parameters() json.RawMessage {
	return makeSchema(map[string]any{
		"path": map[string]any{"type": "string", "description": "Directory path relative to project root or absolute"},
	}, []string{"path"})
}

func (t *listDirTool) Execute(ctx context.Context, args json.RawMessage) (*Result, error) {
	var params struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return &Result{Content: "invalid arguments: " + err.Error(), IsError: true}, nil
	}

	absPath, err := validatePath(effectiveRoot(ctx, t.cfg), params.Path)
	if err != nil {
		return &Result{Content: err.Error(), IsError: true}, nil
	}

	entries, err := os.ReadDir(absPath)
	if err != nil {
		return &Result{Content: "failed to read directory: " + err.Error(), IsError: true}, nil
	}

	var lines []string
	for _, e := range entries {
		name := e.Name()
		if IsTempFile(name) || definitions.IsTempFile(name) {
			// A write in flight, or one a crash interrupted: not a file.
			continue
		}
		if e.IsDir() {
			name += "/"
		}
		lines = append(lines, name)
	}

	return &Result{
		Content: strings.Join(lines, "\n"),
		Metadata: map[string]any{
			"tool":    "list_dir",
			"path":    absPath,
			"entries": len(lines),
		},
	}, nil
}
