package mcpserver

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

type rpcReq struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Serve speaks newline-delimited JSON-RPC 2.0 on r/w until EOF.
func (s *Server) Serve(ctx context.Context, r io.Reader, w io.Writer) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 4<<20), 4<<20)
	enc := json.NewEncoder(w)
	reply := func(id json.RawMessage, result any, rpcErr map[string]any) {
		msg := map[string]any{"jsonrpc": "2.0", "id": id}
		if rpcErr != nil {
			msg["error"] = rpcErr
		} else {
			msg["result"] = result
		}
		_ = enc.Encode(msg)
	}
	for sc.Scan() {
		var req rpcReq
		if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
			continue
		}
		if len(req.ID) == 0 { // notification
			continue
		}
		switch req.Method {
		case "initialize":
			reply(req.ID, map[string]any{
				"protocolVersion": "2025-06-18",
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      map[string]any{"name": "kodeblue", "version": "1"},
			}, nil)
		case "ping":
			reply(req.ID, map[string]any{}, nil)
		case "tools/list":
			var list []map[string]any
			for _, t := range s.tools {
				list = append(list, map[string]any{"name": t.Name, "description": t.Description, "inputSchema": t.Schema})
			}
			reply(req.ID, map[string]any{"tools": list}, nil)
		case "tools/call":
			var p struct {
				Name      string          `json:"name"`
				Arguments json.RawMessage `json:"arguments"`
			}
			_ = json.Unmarshal(req.Params, &p)
			var fn func(context.Context, json.RawMessage) (string, error)
			for _, t := range s.tools {
				if t.Name == p.Name {
					fn = t.Fn
				}
			}
			if fn == nil {
				reply(req.ID, nil, map[string]any{"code": -32602, "message": "unknown tool " + p.Name})
				continue
			}
			cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			text, err := safeCall(cctx, fn, p.Arguments)
			cancel()
			if err != nil {
				if s.fails == nil {
					s.fails = map[string]int{}
				}
				key := p.Name + "|" + string(p.Arguments)
				s.fails[key]++
				msg := "error: " + err.Error()
				if n := s.fails[key]; n >= 3 {
					msg += fmt.Sprintf("\nSTOP: this exact call has now failed %d times. Do not send it again. Fix the arguments as the error says, use a different approach, or skip this step and continue with your procedure.", n)
				}
				reply(req.ID, map[string]any{"content": []map[string]any{{"type": "text", "text": msg}}, "isError": true}, nil)
				continue
			}
			reply(req.ID, map[string]any{"content": []map[string]any{{"type": "text", "text": text}}}, nil)
		default:
			reply(req.ID, nil, map[string]any{"code": -32601, "message": "method not found"})
		}
	}
	return sc.Err()
}

func safeCall(ctx context.Context, fn func(context.Context, json.RawMessage) (string, error), args json.RawMessage) (out string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("tool panic: %v", r)
		}
	}()
	return fn(ctx, args)
}
