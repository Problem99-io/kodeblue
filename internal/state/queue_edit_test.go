package state

import (
	"testing"

	internal "github.com/Problem99-io/kodeblue/internal"
)

func TestQueueRepoEditPreservesPositionAndPayload(t *testing.T) {
	repo, session := newQueueTestRepo(t)
	item, err := repo.Enqueue(&internal.QueueItem{
		SessionID: session, Source: internal.QueueItemSourceUser, Content: "before", ClientMessageID: "stable-id",
		Metadata: []byte(`{"model":"chosen-model"}`), Attachments: []internal.Attachment{{MediaType: "text/plain", FileName: "note.txt", Data: "c2VjcmV0"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	second := enqueueQueueTestItem(t, repo, session, "second")
	if err := repo.SetPaused(session, true); err != nil {
		t.Fatal(err)
	}
	if ok, err := repo.UpdatePendingUser(session, item.ID, "after", "before"); err != nil || !ok {
		t.Fatalf("edit: %t, %v", ok, err)
	}
	if ok, err := repo.UpdatePendingUser(session, item.ID, "stale edit", "before"); err != nil || ok {
		t.Fatalf("stale edit: %t, %v", ok, err)
	}
	if ok, err := repo.UpdatePendingUser(internal.NewSessionID(), item.ID, "foreign edit", "after"); err != nil || ok {
		t.Fatalf("foreign edit: %t, %v", ok, err)
	}
	if paused, err := repo.IsPaused(session); err != nil || !paused {
		t.Fatalf("edit resumed queue: %t, %v", paused, err)
	}
	if err := repo.SetPaused(session, false); err != nil {
		t.Fatal(err)
	}
	claimed, err := repo.ClaimPending(session, "run-edit")
	if err != nil || len(claimed) != 2 {
		t.Fatalf("claim: %#v, %v", claimed, err)
	}
	got := claimed[0]
	if got.ID != item.ID || got.Content != "after" || got.Sequence != item.Sequence || claimed[1].ID != second.ID || got.ClientMessageID != "stable-id" {
		t.Fatalf("edit changed identity/order: %#v", claimed)
	}
	if string(got.Metadata) != `{"model":"chosen-model"}` || len(got.Attachments) != 1 || got.Attachments[0].Data != "c2VjcmV0" {
		t.Fatalf("lost payload: %#v", got)
	}
	if ok, err := repo.UpdatePendingUser(session, item.ID, "too late", "after"); err != nil || ok {
		t.Fatalf("edited claimed item: %t, %v", ok, err)
	}
}

func TestQueueRepoEditRejectsRemovedItems(t *testing.T) {
	repo, session := newQueueTestRepo(t)
	user := enqueueQueueTestItem(t, repo, session, "removed")
	if _, err := repo.RemovePending(session, user.ID); err != nil {
		t.Fatal(err)
	}
	if ok, err := repo.UpdatePendingUser(session, user.ID, "revived", "removed"); err != nil || ok {
		t.Fatalf("edited removed item: %t, %v", ok, err)
	}
}
