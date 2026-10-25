package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// protocolVersion is the MCP revision the engine advertises during initialize.
// Servers negotiate down to a version they support.
const protocolVersion = "2025-06-18"

// RemoteTool describes a tool advertised by an MCP server.
type RemoteTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

// Client is a connected session with a single MCP server.
type Client struct {
	cfg        ServerConfig
	t          transport
	serverName string
	serverVer  string
}

// Connect establishes a transport, performs the MCP initialize handshake, and
// returns a ready client.
func Connect(ctx context.Context, cfg ServerConfig) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	var (
		t   transport
		err error
	)
	switch cfg.NormalizedTransport() {
	case TransportStdio:
		t, err = newStdioTransport(ctx, cfg)
	case TransportHTTP, TransportSSE:
		t = newHTTPTransport(cfg)
	default:
		return nil, fmt.Errorf("unsupported transport %q", cfg.Transport)
	}
	if err != nil {
		return nil, err
	}

	c := &Client{cfg: cfg, t: t}
	if err := c.initialize(ctx); err != nil {
		_ = t.close()
		return nil, err
	}
	return c, nil
}

func (c *Client) initialize(ctx context.Context) error {
	params := map[string]any{
		"protocolVersion": protocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "kodeblue-engine", "version": "1.0"},
	}
	raw, err := c.t.roundTrip(ctx, "initialize", params)
	if err != nil {
		return fmt.Errorf("initialize: %w", c.handshakeErr(err))
	}
	var res struct {
		ProtocolVersion string `json:"protocolVersion"`
		ServerInfo      struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"serverInfo"`
	}
	if err := json.Unmarshal(raw, &res); err == nil {
		c.serverName = res.ServerInfo.Name
		c.serverVer = res.ServerInfo.Version
	}
	// Per spec the client must confirm initialization before issuing requests.
	if err := c.t.notify(ctx, "notifications/initialized", map[string]any{}); err != nil {
		return fmt.Errorf("initialized notification: %w", err)
	}
	return nil
}

// handshakeErr reports why the server died rather than "outcome unknown":
// initialize and tools/list have no side effects worth checking.
func (c *Client) handshakeErr(err error) error {
	if errors.Is(err, ErrOutcomeUnknown) {
		if dead := c.t.err(); dead != nil {
			return dead
		}
	}
	return err
}

// ServerInfo returns the server-reported name and version (may be empty).
func (c *Client) ServerInfo() (name, version string) {
	return c.serverName, c.serverVer
}

// ListTools returns every tool the server advertises, following pagination.
func (c *Client) ListTools(ctx context.Context) ([]RemoteTool, error) {
	var all []RemoteTool
	cursor := ""
	for {
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		raw, err := c.t.roundTrip(ctx, "tools/list", params)
		if err != nil {
			return nil, fmt.Errorf("tools/list: %w", c.handshakeErr(err))
		}
		var res struct {
			Tools      []RemoteTool `json:"tools"`
			NextCursor string       `json:"nextCursor"`
		}
		if err := json.Unmarshal(raw, &res); err != nil {
			return nil, fmt.Errorf("decode tools/list: %w", err)
		}
		all = append(all, res.Tools...)
		if res.NextCursor == "" || len(res.Tools) == 0 {
			break
		}
		cursor = res.NextCursor
		if len(all) > 1000 {
			break // safety bound against a misbehaving server
		}
	}
	return all, nil
}

// CallTool invokes a tool and returns its rendered text content plus whether
// the server flagged the result as an error.
func (c *Client) CallTool(ctx context.Context, name string, args json.RawMessage) (string, bool, error) {
	if len(args) == 0 || strings.TrimSpace(string(args)) == "" {
		args = json.RawMessage(`{}`)
	}
	params := map[string]any{
		"name":      name,
		"arguments": json.RawMessage(args),
	}
	raw, err := c.t.roundTrip(ctx, "tools/call", params)
	if err != nil {
		return "", true, err
	}
	var res struct {
		Content           []json.RawMessage `json:"content"`
		IsError           bool              `json:"isError"`
		StructuredContent json.RawMessage   `json:"structuredContent"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		// Some servers return a bare value; surface it raw.
		return string(raw), false, nil
	}
	return renderContent(res.Content, res.StructuredContent), res.IsError, nil
}

// Done is closed when the server is gone for good — for stdio, once the child
// process has exited and been reaped. It is nil for HTTP servers.
func (c *Client) Done() <-chan struct{} { return c.t.done() }

// Err explains why Done was closed.
func (c *Client) Err() error { return c.t.err() }

// Close shuts down the transport (and the child process for stdio).
func (c *Client) Close() error {
	if c.t == nil {
		return nil
	}
	return c.t.close()
}

// renderContent flattens MCP content blocks into a single text string for the
// agent. Text blocks are concatenated; anything else is included as JSON.
func renderContent(blocks []json.RawMessage, structured json.RawMessage) string {
	var parts []string
	for _, b := range blocks {
		var typed struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}
		if err := json.Unmarshal(b, &typed); err == nil && typed.Type == "text" {
			parts = append(parts, typed.Text)
			continue
		}
		parts = append(parts, string(b))
	}
	out := strings.TrimSpace(strings.Join(parts, "\n"))
	if out == "" && len(structured) > 0 {
		out = strings.TrimSpace(string(structured))
	}
	if out == "" {
		out = "(mcp tool returned no content)"
	}
	return out
}
