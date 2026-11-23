package runtime

import (
	"strings"
	"time"
)

// FailureReason says in one line why a run did not complete, for the case
// summary the hub shows: the provider's spending or rate limit by name, with
// when it lifts if the engine said, then the engine's own message. Empty when
// the run completed or the engine gave no reason.
func (o Outcome) FailureReason() string {
	if o.Status == "completed" {
		return ""
	}
	label := ""
	switch o.ErrorClass {
	case "spend_limit", "quota_exceeded":
		label = "Model provider spending limit reached"
	case "rate_limit":
		label = "Model provider rate limit hit"
	case "":
	default:
		label = "Model provider error (" + o.ErrorClass + ")"
	}
	if label != "" && !o.ResetsAt.IsZero() {
		label += ", resets at " + o.ResetsAt.UTC().Format(time.RFC3339)
	}
	msg := strings.TrimSpace(o.Error)
	if len(msg) > 400 {
		msg = msg[:400] + "…"
	}
	switch {
	case label != "" && msg != "":
		return label + ": " + msg
	case label != "":
		return label + "."
	default:
		return msg
	}
}
