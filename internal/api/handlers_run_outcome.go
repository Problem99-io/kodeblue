package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	internal "github.com/Problem99-io/kodeblue/internal"
)

// Outcome is deliberately bounded and run-bound: no tool bodies, reasoning,
// unrelated session messages, or inference credentials leave this endpoint.
func handleGetRunOutcome(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID := internal.SessionID(r.PathValue("id"))
		runID := internal.RunID(r.PathValue("runId"))
		run, err := deps.Runs.Get(runID)
		if err != nil {
			writeError(w, 500, "run unavailable")
			return
		}
		if run == nil || run.SessionID != sessionID {
			writeError(w, 404, "run unavailable")
			return
		}
		events, err := deps.Events.GetRunTerminal(sessionID, runID)
		if err != nil {
			writeError(w, 500, "run unavailable")
			return
		}
		status, content, failure := "running", "", ""
		if len(events) > 0 {
			e := events[0]
			switch e.Type {
			case internal.EventRunCompleted:
				status = "completed"
				var payload struct {
					FinalContent string `json:"final_content"`
				}
				if json.Unmarshal(e.Payload, &payload) == nil {
					content = payload.FinalContent
				}
			case internal.EventRunFailed:
				status = "failed"
				failure = failureText(e.Payload)
			case internal.EventRunAborted, internal.EventRunInterrupted:
				status = "aborted"
			}
		} else {
			switch run.Status {
			case internal.RunFailed:
				status = "failed"
			case internal.RunAborted, internal.RunInterrupted:
				status = "aborted"
			case internal.RunCompleted:
				status = "completed"
			}
		}
		text := []rune(content)
		truncated := len(text) > 12000
		if truncated {
			content = string(text[:12000])
		}
		out := map[string]any{"session_id": sessionID, "run_id": runID, "status": status, "text": content, "truncated": truncated}
		if failure != "" {
			out["error"] = failure
		}
		writeJSON(w, 200, out)
	}
}

// failureText is why a run failed, from its run.failed event: the reason the
// agent loop wrote for people (the provider's message, such as a rate limit,
// never the request or a key) and the HTTP status when there was one.
func failureText(payload json.RawMessage) string {
	var f struct {
		Reason     string `json:"reason"`
		HTTPStatus int    `json:"http_status"`
	}
	if json.Unmarshal(payload, &f) != nil || f.Reason == "" {
		return ""
	}
	r := []rune(f.Reason)
	if len(r) > 500 {
		f.Reason = string(r[:500]) + "…"
	}
	if f.HTTPStatus != 0 {
		return fmt.Sprintf("%s (HTTP %d)", f.Reason, f.HTTPStatus)
	}
	return f.Reason
}
