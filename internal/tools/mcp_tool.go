package tools

import (
	"context"
	"encoding/json"

	internal "github.com/Problem99-io/kodeblue/internal"
	"github.com/Problem99-io/kodeblue/internal/mcp"
)

// mcpTool adapts a single tool exposed by an external MCP server to the
// engine's Tool interface so the agent can call it like any built-in tool.
type mcpTool struct {
	manager *mcp.Manager
	handle  mcp.ToolHandle
}

// NewMCPTool wraps an MCP tool handle as a registrable engine tool.
func NewMCPTool(manager *mcp.Manager, handle mcp.ToolHandle) Tool {
	return &mcpTool{manager: manager, handle: handle}
}

func (t *mcpTool) Name() internal.ToolName { return internal.ToolName(t.handle.QualifiedName) }

func (t *mcpTool) Description() string { return t.handle.Description }

func (t *mcpTool) Parameters() json.RawMessage {
	if len(t.handle.InputSchema) == 0 {
		return json.RawMessage(`{"type":"object"}`)
	}
	return t.handle.InputSchema
}

func (t *mcpTool) Execute(ctx context.Context, args json.RawMessage) (*Result, error) {
	content, isErr, err := t.manager.Call(ctx, t.handle.QualifiedName, args)
	meta := map[string]any{
		"mcp_server": t.handle.ServerName,
		"mcp_tool":   t.handle.RemoteName,
	}
	if err != nil {
		return &Result{Content: "MCP tool call failed: " + err.Error(), IsError: true, Metadata: meta}, nil
	}
	return &Result{Content: content, IsError: isErr, Metadata: meta}, nil
}
