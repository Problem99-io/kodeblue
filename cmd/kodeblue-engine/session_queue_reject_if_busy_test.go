package main

import (
	"fmt"
	"testing"

	internal "github.com/Problem99-io/kodeblue/internal"
	"github.com/Problem99-io/kodeblue/internal/api"
)

func TestRejectIfBusyPreservesBusyAndUserQueueGuards(t *testing.T) {
	for _, busy := range []bool{false, true} {
		for _, paused := range []bool{false, true} {
			t.Run(fmt.Sprintf("busy=%v/paused=%v", busy, paused), func(t *testing.T) {
				rig := newSessionQueueRig(t, 1)
				var first api.QueueSubmitResult
				if busy {
					var err error
					first, err = rig.adapter.SubmitUser(rig.session, "working", "first", nil, api.RunOptions{})
					if err != nil {
						t.Fatal(err)
					}
					rig.provider.awaitStart(t, 0)
				}
				if err := rig.queue.SetPaused(rig.session, paused); err != nil {
					t.Fatal(err)
				}
				// An idle session with an older user message must remain governed by
				// Continue. A busy session must reject even with an empty backlog.
				wantPending := 0
				if !busy {
					if _, err := rig.queue.Enqueue(&internal.QueueItem{
						SessionID: rig.session, Source: internal.QueueItemSourceUser, Content: "older user message",
					}); err != nil {
						t.Fatal(err)
					}
					wantPending++
				}
				if _, err := rig.adapter.SubmitUser(rig.session, "must not queue", "rejected", nil, api.RunOptions{RejectIfBusy: true}); err == nil {
					t.Fatal("accepted a message that could not start immediately")
				}
				if count, err := rig.queue.PendingCount(rig.session); err != nil || count != wantPending {
					t.Fatalf("rejected message changed inbox: %d %v", count, err)
				}
				if got, err := rig.queue.IsPaused(rig.session); err != nil || got != paused {
					t.Fatalf("rejected message changed pause state: %v %v", got, err)
				}
				if busy {
					if err := rig.adapter.Pause(rig.session); err != nil {
						t.Fatal(err)
					}
					rig.adapter.Abort(string(first.RunID))
					rig.awaitRunStatus(t, first.RunID, internal.RunAborted)
				}
			})
		}
	}
}
