package main

import (
	"strings"
	"testing"

	internal "github.com/Problem99-io/kodeblue/internal"
	"github.com/Problem99-io/kodeblue/internal/api"
)

func TestSessionQueueEditsAndDeletesBeforeDispatch(t *testing.T) {
	rig := newSessionQueueRig(t, 2)
	if _, err := rig.adapter.SubmitUser(rig.session, "start", "start-edit", nil, api.RunOptions{}); err != nil {
		t.Fatal(err)
	}
	rig.provider.awaitStart(t, 0)
	queued, err := rig.adapter.SubmitUser(rig.session, "original", "edit-id", []internal.Attachment{{MediaType: "text/plain", FileName: "note.txt", Data: "c2VjcmV0"}}, api.RunOptions{Model: "edited-model"})
	if err != nil || queued.Item == nil {
		t.Fatalf("queue edit: %#v, %v", queued, err)
	}
	deleted, err := rig.adapter.SubmitUser(rig.session, "delete this", "delete-id", nil, api.RunOptions{})
	if err != nil || deleted.Item == nil {
		t.Fatalf("queue delete: %#v, %v", deleted, err)
	}
	if ok, err := rig.adapter.UpdateQueuedUser(rig.session, queued.Item.ID, "edited instruction", "original"); err != nil || !ok {
		t.Fatalf("edit: %t, %v", ok, err)
	}
	if ok, err := rig.adapter.RemoveQueuedUser(rig.session, deleted.Item.ID); err != nil || !ok {
		t.Fatalf("delete: %t, %v", ok, err)
	}
	rig.provider.release(0)
	rig.provider.awaitStart(t, 1)
	req := rig.provider.request(1)
	last := req.Messages[len(req.Messages)-1]
	if !strings.Contains(last.Content, "edited instruction") || strings.Contains(last.Content, "original") || strings.Contains(last.Content, "delete this") {
		t.Fatalf("wrong dispatched prompt: %s", last.Content)
	}
	if req.Model != "edited-model" || len(last.Attachments) != 1 || last.Attachments[0].Data != "c2VjcmV0" {
		t.Fatalf("edit lost model or attachment: %#v", req)
	}
	if ok, err := rig.adapter.UpdateQueuedUser(rig.session, queued.Item.ID, "late edit", "edited instruction"); err != nil || ok {
		t.Fatalf("edited dispatched item: %t, %v", ok, err)
	}
	rig.provider.release(1)
}
