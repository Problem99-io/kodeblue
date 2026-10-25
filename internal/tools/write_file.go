package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	internal "github.com/Problem99-io/kodeblue/internal"
)

type writeFileTool struct {
	cfg ToolConfig
}

// NewWriteFile creates a write_file tool.
func NewWriteFile(cfg ToolConfig) Tool {
	return &writeFileTool{cfg: cfg}
}

func (t *writeFileTool) Name() internal.ToolName { return "write_file" }

func (t *writeFileTool) Description() string {
	return "Create a new file when a new file needs to be added, or intentionally replace an entire existing file only when overwrite=true. Creates parent directories if needed. If the target file already exists, you must set overwrite=true to replace it. To change an existing file, read it first and write back its complete new contents with overwrite=true. If overwrite=true, the provided content becomes the complete final file contents from top to bottom; anything not included is removed, so partial snippets can truncate the file. The file is replaced atomically: a reader or a crash sees either the old contents or the new, never a partial file. To create several files in one call, pass a writes array; each file is written independently and the result reports exactly which files were written and which failed, so a failure on one file does not roll back the others."
}

// writeRequest is a single write operation, usable on its own (path/content/overwrite
// at the top level) or as one element of the batch writes array.
type writeRequest struct {
	Path      string `json:"path"`
	Content   string `json:"content"`
	Overwrite bool   `json:"overwrite"`
}

func (t *writeFileTool) Parameters() json.RawMessage {
	return makeSchema(map[string]any{
		"path":      map[string]any{"type": "string", "description": "File path relative to the active workspace/session root or an allowed absolute path. Omit when using writes."},
		"content":   map[string]any{"type": "string", "description": "Full file content to write. When overwrite=true, this must be the entire final contents of the file, not just the section you want to change."},
		"overwrite": map[string]any{"type": "boolean", "description": "Allow replacing an existing file with the provided content. Default false. Set it to true only to replace an existing file on purpose, with its complete new contents."},
		"writes": map[string]any{
			"type":        "array",
			"description": "Optional batch mode: a list of independent write operations executed in one call. When provided, the top-level path/content/overwrite are ignored. Each write succeeds or fails on its own; the result lists which files were written and which failed without rolling the others back.",
			"items": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path":      map[string]any{"type": "string", "description": "File path relative to the active workspace/session root or an allowed absolute path"},
					"content":   map[string]any{"type": "string", "description": "Full file content to write."},
					"overwrite": map[string]any{"type": "boolean", "description": "Allow replacing an existing file. Default false."},
				},
				"required": []string{"path", "content"},
			},
		},
	}, nil)
}

func (t *writeFileTool) Execute(ctx context.Context, args json.RawMessage) (*Result, error) {
	var params struct {
		writeRequest
		Writes []writeRequest `json:"writes"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return &Result{Content: "invalid arguments: " + err.Error(), IsError: true}, nil
	}

	if len(params.Writes) > 0 {
		return t.executeBatch(ctx, params.Writes), nil
	}
	if params.Path == "" {
		return &Result{Content: "path is required (or provide a non-empty writes array)", IsError: true}, nil
	}
	return t.writeOne(ctx, params.writeRequest), nil
}

// executeBatch writes each file independently. The result reports per-file
// success/failure so a failure on one file does not discard the successful writes.
func (t *writeFileTool) executeBatch(ctx context.Context, writes []writeRequest) *Result {
	files := make([]map[string]any, 0, len(writes))
	lines := make([]string, 0, len(writes)+1)
	succeeded := 0
	failed := 0
	for _, w := range writes {
		res := t.writeOne(ctx, w)
		ok := !res.IsError
		status := "OK"
		if ok {
			succeeded++
		} else {
			failed++
			status = "FAILED"
		}
		lines = append(lines, fmt.Sprintf("[%s] %s: %s", status, w.Path, res.Content))
		files = append(files, map[string]any{"path": w.Path, "ok": ok, "message": res.Content})
	}
	summary := fmt.Sprintf("write_file batch: %d of %d succeeded, %d failed", succeeded, len(writes), failed)
	return &Result{
		Content: summary + "\n" + strings.Join(lines, "\n"),
		IsError: failed > 0,
		Metadata: map[string]any{
			"tool":      "write_file",
			"batch":     true,
			"succeeded": succeeded,
			"failed":    failed,
			"files":     files,
		},
	}
}

// writeOne writes a single file and returns its result.
func (t *writeFileTool) writeOne(ctx context.Context, w writeRequest) *Result {
	absPath, err := validatePath(effectiveRoot(ctx, t.cfg), w.Path)
	if err != nil {
		return &Result{Content: err.Error(), IsError: true}
	}

	if info, err := os.Stat(absPath); err == nil {
		if info.IsDir() {
			return &Result{Content: "failed to write file: target path is a directory", IsError: true}
		}
		if !w.Overwrite {
			return &Result{Content: fmt.Sprintf("refusing to overwrite existing file %s; set overwrite=true for an intentional full replacement", absPath), IsError: true}
		}
	} else if !os.IsNotExist(err) {
		return &Result{Content: "failed to inspect target file: " + err.Error(), IsError: true}
	}

	if err := secureWrite(ctx, effectiveRoot(ctx, t.cfg), absPath, []byte(w.Content), w.Overwrite); err != nil {
		return &Result{Content: "failed to write file: " + err.Error(), IsError: true}
	}

	return &Result{
		Content: fmt.Sprintf("wrote %d bytes to %s", len(w.Content), absPath),
		Metadata: map[string]any{
			"tool":        "write_file",
			"file":        absPath,
			"bytes":       len(w.Content),
			"lines":       strings.Count(w.Content, "\n") + 1,
			"overwritten": w.Overwrite,
		},
	}
}
