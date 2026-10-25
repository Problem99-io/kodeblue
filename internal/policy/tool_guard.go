package policy

import (
	"encoding/json"
	"fmt"
	"strings"

	internal "github.com/Problem99-io/kodeblue/internal"
)

// ToolCheck holds the result of a tool-execution policy evaluation.
type ToolCheck struct {
	Allowed    bool   `json:"allowed"`
	DenyReason string `json:"deny_reason,omitempty"`
}

// ToolGuard applies the path policy to file tool calls. It decodes each call's
// arguments the same way the tool does (encoding/json into the same field
// names), so the paths it checks are the paths the tool touches. Any tool that
// writes files must be listed in CheckToolExecutionAtRoot; unlisted tools are
// allowed through untouched.
type ToolGuard struct {
	pathPolicy *PathPolicy
}

// NewToolGuard constructs a ToolGuard from a Config.
func NewToolGuard(cfg *Config) (*ToolGuard, error) {
	pp, err := NewPathPolicy(cfg)
	if err != nil {
		return nil, fmt.Errorf("path policy: %w", err)
	}
	return &ToolGuard{pathPolicy: pp}, nil
}

// CheckToolExecution evaluates whether a tool call is allowed.
func (g *ToolGuard) CheckToolExecution(toolName internal.ToolName, args json.RawMessage) (*ToolCheck, error) {
	return g.CheckToolExecutionAtRoot(toolName, args, "")
}

// CheckToolExecutionAtRoot evaluates a call using the run's effective
// filesystem root. This keeps policy resolution aligned with the tool context
// instead of resolving relative paths from the daemon process CWD.
func (g *ToolGuard) CheckToolExecutionAtRoot(toolName internal.ToolName, args json.RawMessage, root string) (*ToolCheck, error) {
	toolName = internal.CanonicalToolName(toolName)

	switch toolName {
	case "write_file":
		return g.checkWritePaths(args, root)
	case "read_file", "list_dir":
		return g.checkReadPaths(toolName, args, root)
	default:
		return &ToolCheck{Allowed: true}, nil
	}
}

func (g *ToolGuard) checkWritePaths(args json.RawMessage, root string) (*ToolCheck, error) {
	paths, err := writePaths(args)
	if err != nil {
		return nil, fmt.Errorf("parse write args: %w", err)
	}
	for _, path := range paths {
		if err := g.pathPolicy.CheckWriteAtRoot(root, path); err != nil {
			return &ToolCheck{Allowed: false, DenyReason: err.Error()}, nil
		}
	}
	return &ToolCheck{Allowed: true}, nil
}

func (g *ToolGuard) checkReadPaths(toolName internal.ToolName, args json.RawMessage, root string) (*ToolCheck, error) {
	paths, err := readPaths(toolName, args)
	if err != nil {
		return nil, fmt.Errorf("parse read args: %w", err)
	}
	for _, path := range paths {
		if err := g.pathPolicy.CheckReadAtRoot(root, path); err != nil {
			return &ToolCheck{Allowed: false, DenyReason: err.Error()}, nil
		}
	}
	return &ToolCheck{Allowed: true}, nil
}

func readPaths(toolName internal.ToolName, args json.RawMessage) ([]string, error) {
	var params struct {
		Path  string `json:"path"`
		Reads []struct {
			Path string `json:"path"`
		} `json:"reads"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return nil, err
	}
	if toolName == "read_file" && len(params.Reads) > 0 {
		paths := make([]string, 0, len(params.Reads))
		for i, read := range params.Reads {
			if strings.TrimSpace(read.Path) == "" {
				return nil, fmt.Errorf("reads[%d].path is required", i)
			}
			paths = append(paths, read.Path)
		}
		return paths, nil
	}
	// Omitted paths are authorized as the run root. The concrete tool remains
	// responsible for its schema-level required-field error; policy must not
	// turn malformed arguments into a misleading path escape.
	return []string{params.Path}, nil
}

// writePaths mirrors write_file's argument handling: a non-empty writes array
// replaces the top-level path.
func writePaths(args json.RawMessage) ([]string, error) {
	var params struct {
		Path   string `json:"path"`
		Writes []struct {
			Path string `json:"path"`
		} `json:"writes"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return nil, err
	}
	var paths []string
	if len(params.Writes) > 0 {
		for i, write := range params.Writes {
			if strings.TrimSpace(write.Path) == "" {
				return nil, fmt.Errorf("writes[%d].path is required", i)
			}
			paths = append(paths, write.Path)
		}
	} else if strings.TrimSpace(params.Path) != "" {
		paths = append(paths, params.Path)
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no target paths were provided")
	}
	return paths, nil
}
