package api

import (
	"net/http"

	"github.com/Problem99-io/kodeblue/internal/mcp"
)

// handleListMCPServers returns the live connection status of every configured
// MCP server, including the tools each one exposed.
func handleListMCPServers(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if deps.MCP == nil {
			writeJSON(w, http.StatusOK, map[string]any{"servers": []mcp.ServerStatus{}})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"servers": deps.MCP.Status()})
	}
}
