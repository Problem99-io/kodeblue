package api

import (
	internal "github.com/Problem99-io/kodeblue/internal"
	"github.com/Problem99-io/kodeblue/internal/state"
)

// Every status/pending read reconciles durable evidence, including after a
// reconnect. Cancelling obsolete waiters does not send an answer.
func reconcileSessionBlockers(deps *Dependencies, sessionID internal.SessionID) ([]state.LifecycleRepair, error) {
	if deps.DB == nil {
		return nil, nil
	}
	repairs, err := deps.DB.ReconcileSessionBlockers(sessionID)
	if err != nil {
		return nil, err
	}
	if deps.EventHub != nil {
		for _, repair := range repairs {
			if repair.Kind == "question" {
				deps.EventHub.CancelQuestion(repair.ItemID)
			}
		}
	}
	return repairs, nil
}
