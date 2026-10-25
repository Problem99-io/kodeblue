package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
)

// The engine persists a run's assistant and tool messages when the run ends.
// While it runs, progress exists only as events, so live transcripts are
// rebuilt from the event stream: each model step's reasoning (streamed
// tokens on the reasoning channel), its text, and its tool calls with
// results. A per-session cursor keeps each poll incremental.
type liveTrail struct {
	after     int64
	run       string
	turns     []hubproto.Turn
	pos       map[string][2]int
	reasoning strings.Builder
	last      time.Time
}

func (k *Engine) liveTurns(ctx context.Context, sessionID string) ([]hubproto.Turn, error) {
	k.mu.Lock()
	if k.trails == nil {
		k.trails = map[string]*liveTrail{}
	}
	tr := k.trails[sessionID]
	if tr == nil {
		tr = &liveTrail{pos: map[string][2]int{}}
		k.trails[sessionID] = tr
	}
	k.mu.Unlock()

	var events []struct {
		Type      string          `json:"type"`
		Timestamp time.Time       `json:"timestamp"`
		RunID     string          `json:"run_id"`
		Seq       int64           `json:"seq"`
		Payload   json.RawMessage `json:"payload"`
	}
	path := fmt.Sprintf("/v1/sessions/%s/events/history?include_tokens=1&after_seq=%d&limit=20000", sessionID, tr.after)
	if err := k.do(ctx, http.MethodGet, path, nil, &events); err != nil {
		return nil, err
	}
	for _, ev := range events {
		if ev.Seq > tr.after {
			tr.after = ev.Seq
		}
		tr.last = ev.Timestamp
		if ev.RunID != "" && ev.RunID != tr.run {
			// A new run: earlier runs are already persisted as messages.
			tr.run, tr.turns, tr.pos = ev.RunID, nil, map[string][2]int{}
			tr.reasoning.Reset()
		}
		var p struct {
			Channel    string          `json:"channel"`
			Content    string          `json:"content"`
			Internal   bool            `json:"internal"`
			ToolCallID string          `json:"tool_call_id"`
			ToolName   string          `json:"tool_name"`
			Arguments  json.RawMessage `json:"arguments"`
			Status     string          `json:"status"`
			Cost       *struct {
				BilledTotalUSD float64 `json:"billed_total_usd"`
			} `json:"cost"`
		}
		_ = json.Unmarshal(ev.Payload, &p)
		switch ev.Type {
		case "model.token":
			if p.Channel == "reasoning" && tr.reasoning.Len() < 12000 {
				tr.reasoning.WriteString(p.Content)
			}
		case "model.completed":
			if p.Internal {
				tr.reasoning.Reset()
				continue
			}
			t := hubproto.Turn{Role: "assistant", Text: clip(p.Content, 20000), Reasoning: clip(tr.reasoning.String(), 12000), At: ev.Timestamp}
			if p.Cost != nil {
				t.CostUSD = p.Cost.BilledTotalUSD
			}
			tr.reasoning.Reset()
			tr.turns = append(tr.turns, t)
		case "tool.requested":
			if len(tr.turns) == 0 {
				tr.turns = append(tr.turns, hubproto.Turn{Role: "assistant", At: ev.Timestamp})
			}
			args := string(p.Arguments)
			var s string
			if json.Unmarshal(p.Arguments, &s) == nil {
				args = s // arguments arrive as a JSON-encoded string
			}
			last := len(tr.turns) - 1
			tr.pos[p.ToolCallID] = [2]int{last, len(tr.turns[last].Tools)}
			tr.turns[last].Tools = append(tr.turns[last].Tools, hubproto.ToolStep{ID: p.ToolCallID, Name: strings.TrimPrefix(p.ToolName, "mcp__kodeblue__"), Args: clip(args, 3000)})
		case "tool.output":
			if at, ok := tr.pos[p.ToolCallID]; ok {
				tr.turns[at[0]].Tools[at[1]].Result = clip(p.Content, 3000)
			}
		case "tool.finished":
			if at, ok := tr.pos[p.ToolCallID]; ok && p.Status != "" && p.Status != "success" {
				tr.turns[at[0]].Tools[at[1]].IsError = true
			}
		}
	}
	out := append([]hubproto.Turn(nil), tr.turns...)
	if tr.reasoning.Len() > 0 {
		// The model is thinking right now.
		out = append(out, hubproto.Turn{Role: "assistant", Reasoning: clip(tr.reasoning.String(), 12000), At: tr.last})
	}
	return out, nil
}

// forgetLive drops the event cursor once a session's run has ended (its
// messages are persisted by then).
func (k *Engine) forgetLive(sessionID string) {
	k.mu.Lock()
	delete(k.trails, sessionID)
	k.mu.Unlock()
}
