package runtime

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
)

// Transcript turns a session's messages into what the hub shows: each
// assistant turn with its reasoning, text and tool calls (results attached,
// bounded). Internal bookkeeping messages are skipped. For a running session
// the current run's progress is appended from the event stream.
func (k *Engine) Transcript(ctx context.Context, sessionID string, running bool) ([]hubproto.Turn, error) {
	turns, err := k.persistedTurns(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	if !running {
		k.forgetLive(sessionID)
		return turns, nil
	}
	live, err := k.liveTurns(ctx, sessionID)
	if err != nil {
		return turns, nil
	}
	return append(turns, live...), nil
}

func (k *Engine) persistedTurns(ctx context.Context, sessionID string) ([]hubproto.Turn, error) {
	var raw json.RawMessage
	if err := k.do(ctx, http.MethodGet, "/v1/sessions/"+sessionID+"/messages?include_reasoning=1", nil, &raw); err != nil {
		return nil, err
	}
	type msg struct {
		Role             string `json:"role"`
		Content          string `json:"content"`
		ReasoningContent string `json:"reasoning_content"`
		ToolCalls        []struct {
			ID        string          `json:"id"`
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
			Internal  bool            `json:"internal"`
		} `json:"tool_calls"`
		ToolResults []struct {
			ToolCallID string `json:"tool_call_id"`
			Content    string `json:"content"`
			IsError    bool   `json:"is_error"`
		} `json:"tool_results"`
		Usage *struct {
			Cost *struct {
				BilledTotalUSD float64 `json:"billed_total_usd"`
			} `json:"cost"`
		} `json:"usage"`
		CreatedAt time.Time `json:"created_at"`
		Internal  bool      `json:"internal"`
	}
	var list []msg
	if json.Unmarshal(raw, &list) != nil {
		var w struct {
			Messages []msg `json:"messages"`
		}
		_ = json.Unmarshal(raw, &w)
		list = w.Messages
	}
	var turns []hubproto.Turn
	where := map[string][2]int{} // tool call id -> (turn, step)
	for _, m := range list {
		if m.Internal {
			continue
		}
		if len(m.ToolResults) > 0 {
			for _, r := range m.ToolResults {
				if pos, ok := where[r.ToolCallID]; ok {
					st := &turns[pos[0]].Tools[pos[1]]
					st.Result, st.IsError = clip(r.Content, 3000), r.IsError
				}
			}
			if strings.TrimSpace(m.Content) == "" || m.Role == "tool" {
				continue
			}
		}
		if m.Role == "tool" {
			continue
		}
		t := hubproto.Turn{Role: m.Role, Text: clip(m.Content, 20000), Reasoning: clip(m.ReasoningContent, 12000), At: m.CreatedAt}
		if m.Usage != nil && m.Usage.Cost != nil {
			t.CostUSD = m.Usage.Cost.BilledTotalUSD
		}
		for _, c := range m.ToolCalls {
			if c.Internal {
				continue
			}
			where[c.ID] = [2]int{len(turns), len(t.Tools)}
			t.Tools = append(t.Tools, hubproto.ToolStep{ID: c.ID, Name: strings.TrimPrefix(c.Name, "mcp__kodeblue__"), Args: clip(string(c.Arguments), 3000)})
		}
		if t.Text == "" && t.Reasoning == "" && len(t.Tools) == 0 {
			continue
		}
		turns = append(turns, t)
	}
	if len(turns) > 400 {
		turns = append(turns[:20], turns[len(turns)-380:]...)
	}
	return turns, nil
}

// Running reports whether the session has a run in progress.
func (k *Engine) Running(ctx context.Context, s *Session) bool {
	var out struct {
		Status string `json:"status"`
	}
	if err := k.do(ctx, http.MethodGet, "/v1/sessions/"+s.ID+"/runs/"+s.RunID+"/outcome", nil, &out); err != nil {
		return false
	}
	return out.Status == "running"
}

// HasAgent reports whether agent is registered.
func (k *Engine) HasAgent(name string) bool {
	_, ok := k.agents[name]
	return ok
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "\n…(truncated)"
}
