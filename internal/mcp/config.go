// Package mcp implements a client for connecting the engine to external Model
// Context Protocol (MCP) servers. It supports two transports:
//
//   - "stdio": the engine spawns the server as a child process and speaks
//     newline-delimited JSON-RPC 2.0 over its stdin/stdout.
//   - "http"/"sse": the engine talks to a remote server over the Streamable HTTP
//     transport (JSON-RPC POSTs whose responses may be plain JSON or an SSE
//     stream).
//
// Tools exposed by a connected server are surfaced to the agent as regular
// engine tools, named "mcp__<server>__<tool>", so the LLM can call them with
// no special handling.
package mcp

import (
	"fmt"
	"regexp"
	"strings"
)

// TransportStdio / TransportHTTP / TransportSSE are the supported transports.
const (
	TransportStdio = "stdio"
	TransportHTTP  = "http"
	TransportSSE   = "sse"
)

// ServerConfig describes one external MCP server the engine should connect to.
type ServerConfig struct {
	Name      string            `toml:"name" json:"name"`
	Transport string            `toml:"transport" json:"transport"`
	Command   string            `toml:"command" json:"command"`
	Args      []string          `toml:"args" json:"args"`
	URL       string            `toml:"url" json:"url"`
	Env       map[string]string `toml:"env" json:"env"`
	Headers   map[string]string `toml:"headers" json:"headers"`
	Enabled   bool              `toml:"enabled" json:"enabled"`
}

// NormalizedTransport returns the lower-cased transport, defaulting to stdio
// when a command is present and http when only a URL is present.
func (c ServerConfig) NormalizedTransport() string {
	t := strings.ToLower(strings.TrimSpace(c.Transport))
	switch t {
	case TransportStdio, TransportHTTP, TransportSSE:
		return t
	}
	if strings.TrimSpace(c.Command) != "" {
		return TransportStdio
	}
	if strings.TrimSpace(c.URL) != "" {
		return TransportHTTP
	}
	return TransportStdio
}

// Validate reports whether the config has the fields its transport requires.
func (c ServerConfig) Validate() error {
	if strings.TrimSpace(c.Name) == "" {
		return fmt.Errorf("mcp server name is required")
	}
	switch c.NormalizedTransport() {
	case TransportStdio:
		if strings.TrimSpace(c.Command) == "" {
			return fmt.Errorf("mcp server %q: command is required for stdio transport", c.Name)
		}
	case TransportHTTP, TransportSSE:
		if strings.TrimSpace(c.URL) == "" {
			return fmt.Errorf("mcp server %q: url is required for http/sse transport", c.Name)
		}
	}
	return nil
}

var (
	nonToolNameChar = regexp.MustCompile(`[^a-zA-Z0-9_-]+`)
	toolNamePrefix  = "mcp__"
)

// SanitizeSegment makes a name safe to embed in a model-facing tool name.
func SanitizeSegment(s string) string {
	s = nonToolNameChar.ReplaceAllString(strings.TrimSpace(s), "_")
	s = strings.Trim(s, "_-")
	if s == "" {
		s = "x"
	}
	return s
}

// QualifiedToolName builds the agent-facing tool name for an MCP tool. The
// Anthropic / OpenAI tool-name limit is 64 characters, so the result is
// truncated if necessary while keeping it unique-ish.
func QualifiedToolName(server, tool string) string {
	name := toolNamePrefix + SanitizeSegment(server) + "__" + SanitizeSegment(tool)
	if len(name) > 64 {
		name = name[:64]
	}
	return name
}
