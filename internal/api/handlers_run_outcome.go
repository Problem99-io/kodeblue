package api

import (
	"encoding/json"
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
		status, content := "running", ""
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
		writeJSON(w, 200, map[string]any{"session_id": sessionID, "run_id": runID, "status": status, "text": content, "truncated": truncated})
	}
}
