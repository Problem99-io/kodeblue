package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mockMCPHandler implements a minimal Streamable-HTTP MCP server: initialize,
// tools/list, and tools/call over JSON-RPC.
func mockMCPHandler(useSSE bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      json.RawMessage `json:"id"`
			Method  string          `json:"method"`
			Params  json.RawMessage `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)

		// Notifications (no id) get a 202 with no body.
		if len(req.ID) == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}

		var result any
		switch req.Method {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "test-session")
			result = map[string]any{
				"protocolVersion": protocolVersion,
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      map[string]any{"name": "mock-mcp", "version": "9.9.9"},
			}
		case "tools/list":
			result = map[string]any{
				"tools": []map[string]any{
					{
						"name":        "echo",
						"description": "Echo back the message",
						"inputSchema": map[string]any{
							"type":       "object",
							"properties": map[string]any{"message": map[string]any{"type": "string"}},
							"required":   []string{"message"},
						},
					},
				},
			}
		case "tools/call":
			var p struct {
				Name      string         `json:"name"`
				Arguments map[string]any `json:"arguments"`
			}
			_ = json.Unmarshal(req.Params, &p)
			msg, _ := p.Arguments["message"].(string)
			result = map[string]any{
				"content": []map[string]any{{"type": "text", "text": "echo: " + msg}},
				"isError": false,
			}
		default:
			http.Error(w, "unknown method", http.StatusBadRequest)
			return
		}

		resp := map[string]any{"jsonrpc": "2.0", "id": json.RawMessage(req.ID), "result": result}
		if useSSE {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			b, _ := json.Marshal(resp)
			_, _ = w.Write([]byte("event: message\ndata: "))
			_, _ = w.Write(b)
			_, _ = w.Write([]byte("\n\n"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func runHTTPClientTest(t *testing.T, useSSE bool) {
	t.Helper()
	srv := httptest.NewServer(mockMCPHandler(useSSE))
	defer srv.Close()

	cfg := ServerConfig{Name: "mock", Transport: TransportHTTP, URL: srv.URL, Enabled: true}
	ctx := context.Background()

	client, err := Connect(ctx, cfg)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer client.Close()

	if name, ver := client.ServerInfo(); name != "mock-mcp" || ver != "9.9.9" {
		t.Fatalf("unexpected server info: %q %q", name, ver)
	}

	tools, err := client.ListTools(ctx)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if len(tools) != 1 || tools[0].Name != "echo" {
		t.Fatalf("unexpected tools: %+v", tools)
	}

	out, isErr, err := client.CallTool(ctx, "echo", json.RawMessage(`{"message":"hi"}`))
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if isErr {
		t.Fatalf("tool reported error: %s", out)
	}
	if out != "echo: hi" {
		t.Fatalf("unexpected output: %q", out)
	}
}

func TestHTTPClientJSON(t *testing.T) { runHTTPClientTest(t, false) }
func TestHTTPClientSSE(t *testing.T)  { runHTTPClientTest(t, true) }

func TestManagerConnectAndCall(t *testing.T) {
	srv := httptest.NewServer(mockMCPHandler(false))
	defer srv.Close()

	mgr := NewManager(nil)
	defer mgr.Close()
	mgr.Connect(context.Background(), []ServerConfig{
		{Name: "mock", Transport: TransportHTTP, URL: srv.URL, Enabled: true},
		{Name: "disabled", Transport: TransportHTTP, URL: srv.URL, Enabled: false},
	})

	handles := mgr.Tools()
	if len(handles) != 1 {
		t.Fatalf("expected 1 tool handle, got %d", len(handles))
	}
	want := QualifiedToolName("mock", "echo")
	if handles[0].QualifiedName != want {
		t.Fatalf("unexpected qualified name: %q want %q", handles[0].QualifiedName, want)
	}

	out, isErr, err := mgr.Call(context.Background(), want, json.RawMessage(`{"message":"yo"}`))
	if err != nil || isErr {
		t.Fatalf("Call failed: err=%v isErr=%v out=%s", err, isErr, out)
	}
	if out != "echo: yo" {
		t.Fatalf("unexpected output: %q", out)
	}

	status := mgr.Status()
	if len(status) != 1 || !status[0].Connected || status[0].ToolCount != 1 {
		t.Fatalf("unexpected status: %+v", status)
	}
}

func TestQualifiedToolName(t *testing.T) {
	got := QualifiedToolName("My Server!", "do/thing")
	if got != "mcp__My_Server__do_thing" {
		t.Fatalf("unexpected qualified name: %q", got)
	}
}

func TestValidate(t *testing.T) {
	if err := (ServerConfig{Transport: TransportStdio, Command: "x"}).Validate(); err == nil {
		t.Fatal("expected error for missing name")
	}
	if err := (ServerConfig{Name: "a", Transport: TransportStdio}).Validate(); err == nil {
		t.Fatal("expected error for missing command")
	}
	if err := (ServerConfig{Name: "a", Transport: TransportHTTP}).Validate(); err == nil {
		t.Fatal("expected error for missing url")
	}
	if err := (ServerConfig{Name: "a", URL: "http://x"}).Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSSEServerRequestWithSameIDIsSkipped(t *testing.T) {
	stream := "data: {\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"sampling/createMessage\",\"params\":{}}\n\n" +
		"data: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"ok\":true}}\n\n"
	want := int64(7)
	resp, err := parseSSEResponse(strings.NewReader(stream), &want)
	if err != nil {
		t.Fatalf("parseSSEResponse: %v", err)
	}
	if string(resp.Result) != `{"ok":true}` {
		t.Fatalf("got the server request instead of the response: %+v", resp)
	}
}
