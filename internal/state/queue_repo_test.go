package state

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	internal "github.com/Problem99-io/kodeblue/internal"
)

func newQueueTestRepo(t *testing.T) (*QueueRepo, internal.SessionID) {
	t.Helper()
	db := newTestDB(t)
	sessionID := internal.NewSessionID()
	now := time.Now().UTC()
	if err := NewSessionRepo(db).Create(&internal.Session{
		ID: sessionID, Status: internal.SessionActive, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("create session: %v", err)
	}
	return NewQueueRepo(db), sessionID
}

func enqueueQueueTestItem(t *testing.T, repo *QueueRepo, sessionID internal.SessionID, content string) *internal.QueueItem {
	t.Helper()
	item, err := repo.Enqueue(&internal.QueueItem{
		SessionID: sessionID,
		Source:    internal.QueueItemSourceUser,
		Heading:   "User message",
		Content:   content,
	})
	if err != nil {
		t.Fatalf("Enqueue(%q): %v", content, err)
	}
	return item
}

func TestQueueRepoFIFOAndSanitizedList(t *testing.T) {
	repo, sessionID := newQueueTestRepo(t)
	first := enqueueQueueTestItem(t, repo, sessionID, "first")
	second, err := repo.Enqueue(&internal.QueueItem{
		SessionID: sessionID,
		Source:    internal.QueueItemSourceUser,
		Heading:   "User message",
		Content:   "second",
		Metadata:  []byte(`{"model":"one"}`),
		Attachments: []internal.Attachment{{
			MediaType: "text/plain", FileName: "secret.txt", Data: "c2VjcmV0",
		}},
	})
	if err != nil {
		t.Fatalf("Enqueue second: %v", err)
	}
	items, err := repo.ListPending(sessionID)
	if err != nil {
		t.Fatalf("ListPending: %v", err)
	}
	if len(items) != 2 || items[0].ID != first.ID || items[1].ID != second.ID || items[0].Sequence >= items[1].Sequence {
		t.Fatalf("FIFO items = %#v", items)
	}
	if got := items[1].Attachments[0]; got.Data != "" || got.FileName != "secret.txt" {
		t.Fatalf("sanitized attachment = %#v", got)
	}
	if string(items[1].Metadata) != `{"model":"one"}` {
		t.Fatalf("metadata = %s", items[1].Metadata)
	}
	claimed, err := repo.ClaimPending(sessionID, "run-fifo")
	if err != nil {
		t.Fatalf("ClaimPending: %v", err)
	}
	if len(claimed) != 2 || claimed[1].Attachments[0].Data != "c2VjcmV0" {
		t.Fatalf("claimed attachment payloads = %#v", claimed)
	}
}

func TestQueueRepoClaimSnapshotBoundary(t *testing.T) {
	repo, sessionID := newQueueTestRepo(t)
	first := enqueueQueueTestItem(t, repo, sessionID, "before")
	claimed, err := repo.ClaimPending(sessionID, "run-one")
	if err != nil || len(claimed) != 1 || claimed[0].ID != first.ID {
		t.Fatalf("first claim = %#v, err=%v", claimed, err)
	}
	second := enqueueQueueTestItem(t, repo, sessionID, "after")
	pending, err := repo.ListPending(sessionID)
	if err != nil || len(pending) != 1 || pending[0].ID != second.ID {
		t.Fatalf("pending after snapshot = %#v, err=%v", pending, err)
	}
	claimed, err = repo.ClaimPending(sessionID, "run-two")
	if err != nil || len(claimed) != 1 || claimed[0].ID != second.ID {
		t.Fatalf("second claim = %#v, err=%v", claimed, err)
	}
}

func TestQueueRepoConcurrentClaimOnlyOneWins(t *testing.T) {
	repo, sessionID := newQueueTestRepo(t)
	enqueueQueueTestItem(t, repo, sessionID, "one")
	enqueueQueueTestItem(t, repo, sessionID, "two")
	start := make(chan struct{})
	results := make(chan []internal.QueueItem, 2)
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, runID := range []internal.RunID{"run-a", "run-b"} {
		wg.Add(1)
		go func(runID internal.RunID) {
			defer wg.Done()
			<-start
			items, err := repo.ClaimPending(sessionID, runID)
			if err != nil {
				errs <- err
				return
			}
			results <- items
		}(runID)
	}
	close(start)
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent ClaimPending: %v", err)
	}
	total := 0
	nonEmpty := 0
	for items := range results {
		total += len(items)
		if len(items) > 0 {
			nonEmpty++
		}
	}
	if total != 2 || nonEmpty != 1 {
		t.Fatalf("concurrent claims total=%d nonempty=%d, want 2 and 1", total, nonEmpty)
	}
}

func TestQueueRepoRemovePendingOnly(t *testing.T) {
	repo, sessionID := newQueueTestRepo(t)
	pending := enqueueQueueTestItem(t, repo, sessionID, "remove")
	removed, err := repo.RemovePending(sessionID, pending.ID)
	if err != nil || !removed {
		t.Fatalf("RemovePending pending = %t, %v", removed, err)
	}
	if removed, err := repo.RemovePending(sessionID, pending.ID); err != nil || removed {
		t.Fatalf("RemovePending already removed = %t, %v", removed, err)
	}
	claimedItem := enqueueQueueTestItem(t, repo, sessionID, "claimed")
	if _, err := repo.ClaimPending(sessionID, "run-claimed"); err != nil {
		t.Fatalf("ClaimPending: %v", err)
	}
	if removed, err := repo.RemovePending(sessionID, claimedItem.ID); err != nil || removed {
		t.Fatalf("RemovePending claimed = %t, %v", removed, err)
	}
}

func TestQueueRepoPauseBlocksClaimUntilUnpaused(t *testing.T) {
	repo, sessionID := newQueueTestRepo(t)
	enqueueQueueTestItem(t, repo, sessionID, "wait")
	if err := repo.SetPaused(sessionID, true); err != nil {
		t.Fatalf("SetPaused(true): %v", err)
	}
	if paused, err := repo.IsPaused(sessionID); err != nil || !paused {
		t.Fatalf("IsPaused = %t, %v", paused, err)
	}
	if claimed, err := repo.ClaimPending(sessionID, "run-paused"); err != nil || len(claimed) != 0 {
		t.Fatalf("paused ClaimPending = %#v, %v", claimed, err)
	}
	if err := repo.SetPaused(sessionID, false); err != nil {
		t.Fatalf("SetPaused(false): %v", err)
	}
	if claimed, err := repo.ClaimPending(sessionID, "run-unpaused"); err != nil || len(claimed) != 1 {
		t.Fatalf("unpaused ClaimPending = %#v, %v", claimed, err)
	}
}

func TestQueueRepoReleaseFailedClaimAndRecovery(t *testing.T) {
	repo, sessionID := newQueueTestRepo(t)
	first := enqueueQueueTestItem(t, repo, sessionID, "first")
	second := enqueueQueueTestItem(t, repo, sessionID, "second")
	if claimed, err := repo.ClaimPending(sessionID, "failed-run"); err != nil || len(claimed) != 2 {
		t.Fatalf("ClaimPending = %#v, %v", claimed, err)
	}
	if released, err := repo.ReleaseClaim(sessionID, "failed-run"); err != nil || released != 2 {
		t.Fatalf("ReleaseClaim = %d, %v", released, err)
	}
	if pending, err := repo.ListPending(sessionID); err != nil || len(pending) != 2 || pending[0].ID != first.ID || pending[1].ID != second.ID {
		t.Fatalf("released pending = %#v, %v", pending, err)
	}
	if _, err := repo.ClaimPending(sessionID, "restart-run"); err != nil {
		t.Fatalf("ClaimPending restart: %v", err)
	}
	if released, err := repo.RecoverClaims(); err != nil || released != 2 {
		t.Fatalf("RecoverClaims = %d, %v", released, err)
	}
	if pending, err := repo.ListPending(sessionID); err != nil || len(pending) != 2 {
		t.Fatalf("recovered pending = %#v, %v", pending, err)
	}
}

func TestQueueRepoDeliveredWipesAttachmentPayloads(t *testing.T) {
	repo, sessionID := newQueueTestRepo(t)
	item, err := repo.Enqueue(&internal.QueueItem{
		SessionID: sessionID, Source: internal.QueueItemSourceUser, Content: "attached",
		Attachments: []internal.Attachment{{MediaType: "image/png", FileName: "x.png", Data: "aGVsbG8="}},
	})
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if _, err := repo.ClaimPending(sessionID, "delivery-run"); err != nil {
		t.Fatalf("ClaimPending: %v", err)
	}
	if delivered, err := repo.MarkDelivered(sessionID, "delivery-run"); err != nil || delivered != 1 {
		t.Fatalf("MarkDelivered = %d, %v", delivered, err)
	}
	var attachmentJSON, state string
	if err := repo.db.conn.QueryRow(`SELECT attachments, state FROM session_queue_items WHERE id = ?`, string(item.ID)).Scan(&attachmentJSON, &state); err != nil {
		t.Fatalf("load stored delivery: %v", err)
	}
	if state != string(internal.QueueItemDelivered) || attachmentJSON == "" || containsAttachmentPayload(t, attachmentJSON, "aGVsbG8=") {
		t.Fatalf("stored delivered state=%q attachments=%s", state, attachmentJSON)
	}
}

func TestQueueRepoPersistClaimedMessageIsAtomic(t *testing.T) {
	repo, sessionID := newQueueTestRepo(t)
	item := enqueueQueueTestItem(t, repo, sessionID, "atomic handoff")
	runID := internal.RunID("atomic-run")
	run := &internal.Run{ID: runID, SessionID: sessionID, Status: internal.RunRunning, CreatedAt: time.Now()}
	if claimed, err := repo.ClaimPendingAndCreateRun(sessionID, run); err != nil || len(claimed) != 1 {
		t.Fatalf("ClaimPendingAndCreateRun = %#v, %v", claimed, err)
	}
	message := &internal.Message{ID: internal.NewMessageID(), Role: "user", Content: "atomic handoff", CreatedAt: time.Now()}
	if err := repo.PersistClaimedMessage(sessionID, runID, message); err != nil {
		t.Fatalf("PersistClaimedMessage: %v", err)
	}
	var state string
	if err := repo.db.conn.QueryRow(`SELECT state FROM session_queue_items WHERE id = ?`, string(item.ID)).Scan(&state); err != nil || state != "delivered" {
		t.Fatalf("queue state = %q, %v", state, err)
	}
	var count int
	if err := repo.db.conn.QueryRow(`SELECT COUNT(*) FROM messages WHERE id = ? AND run_id = ?`, message.ID, string(runID)).Scan(&count); err != nil || count != 1 {
		t.Fatalf("persisted message count = %d, %v", count, err)
	}
}

func containsAttachmentPayload(t *testing.T, raw, data string) bool {
	t.Helper()
	var attachments []internal.Attachment
	if err := json.Unmarshal([]byte(raw), &attachments); err != nil {
		t.Fatalf("decode attachments: %v", err)
	}
	for _, attachment := range attachments {
		if attachment.Data == data {
			return true
		}
	}
	return false
}

func TestQueueRepoMetadataMustBeJSON(t *testing.T) {
	repo, sessionID := newQueueTestRepo(t)
	if _, err := repo.Enqueue(&internal.QueueItem{SessionID: sessionID, Source: internal.QueueItemSourceUser, Metadata: []byte("nope")}); err == nil {
		t.Fatal("Enqueue accepted invalid metadata")
	}
}

func TestQueueRepoDeduplicatesUserClientMessageID(t *testing.T) {
	repo, sessionID := newQueueTestRepo(t)
	first, inserted, err := repo.EnqueueUnique(&internal.QueueItem{
		SessionID: sessionID, Source: internal.QueueItemSourceUser,
		Content: "first", ClientMessageID: "client-42",
	})
	if err != nil || !inserted {
		t.Fatalf("first EnqueueUnique = %#v, %v, %v", first, inserted, err)
	}
	duplicate, inserted, err := repo.EnqueueUnique(&internal.QueueItem{
		SessionID: sessionID, Source: internal.QueueItemSourceUser,
		Content: "retry", ClientMessageID: "client-42",
	})
	if err != nil || inserted || duplicate.ID != first.ID || duplicate.Content != "first" {
		t.Fatalf("duplicate EnqueueUnique = %#v, %v, %v", duplicate, inserted, err)
	}
	if count, err := repo.PendingCount(sessionID); err != nil || count != 1 {
		t.Fatalf("PendingCount = %d, %v", count, err)
	}
}

func TestQueueRepoConcurrentEnqueueRetainsEveryItem(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queue.db")
	dbA, err := NewDB(path)
	if err != nil {
		t.Fatalf("NewDB A: %v", err)
	}
	defer dbA.Close()
	if err := dbA.Migrate(); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	sessionID := internal.NewSessionID()
	now := time.Now().UTC()
	if err := NewSessionRepo(dbA).Create(&internal.Session{ID: sessionID, Status: internal.SessionActive, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatalf("create session: %v", err)
	}
	dbB, err := NewDB(path)
	if err != nil {
		t.Fatalf("NewDB B: %v", err)
	}
	defer dbB.Close()
	repoA, repoB := NewQueueRepo(dbA), NewQueueRepo(dbB)
	start := make(chan struct{})
	errs := make(chan error, 2)
	for i, repo := range []*QueueRepo{repoA, repoB} {
		go func(i int, repo *QueueRepo) {
			<-start
			_, err := repo.Enqueue(&internal.QueueItem{SessionID: sessionID, Source: internal.QueueItemSourceUser, Content: string(rune('a' + i))})
			errs <- err
		}(i, repo)
	}
	close(start)
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent Enqueue: %v", err)
		}
	}
	if count, err := repoA.PendingCount(sessionID); err != nil || count != 2 {
		t.Fatalf("PendingCount = %d, %v", count, err)
	}
}

func TestQueueRepoConcurrentEnqueueAndClaimDoesNotLoseItem(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queue-claim.db")
	dbA, err := NewDB(path)
	if err != nil {
		t.Fatalf("NewDB A: %v", err)
	}
	defer dbA.Close()
	if err := dbA.Migrate(); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	sessionID := internal.NewSessionID()
	now := time.Now().UTC()
	if err := NewSessionRepo(dbA).Create(&internal.Session{ID: sessionID, Status: internal.SessionActive, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatalf("create session: %v", err)
	}
	dbB, err := NewDB(path)
	if err != nil {
		t.Fatalf("NewDB B: %v", err)
	}
	defer dbB.Close()
	repoA, repoB := NewQueueRepo(dbA), NewQueueRepo(dbB)
	start := make(chan struct{})
	claimResult := make(chan []internal.QueueItem, 1)
	errResult := make(chan error, 2)
	go func() {
		<-start
		items, err := repoA.ClaimPending(sessionID, "concurrent-run")
		claimResult <- items
		errResult <- err
	}()
	go func() {
		<-start
		_, err := repoB.Enqueue(&internal.QueueItem{SessionID: sessionID, Source: internal.QueueItemSourceUser, Content: "racing"})
		errResult <- err
	}()
	close(start)
	for range 2 {
		if err := <-errResult; err != nil {
			t.Fatalf("concurrent enqueue/claim: %v", err)
		}
	}
	claimed := <-claimResult
	pending, err := repoA.ListPending(sessionID)
	if err != nil {
		t.Fatalf("ListPending: %v", err)
	}
	if len(claimed)+len(pending) != 1 {
		t.Fatalf("item lost or duplicated: claimed=%#v pending=%#v", claimed, pending)
	}
}

func TestQueueDispatchRetryDoesNotDuplicateItem(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared.db")
	db, err := NewDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	other, err := NewDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	sid := internal.NewSessionID()
	if err := NewSessionRepo(db).Create(&internal.Session{ID: sid, CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	repo := NewQueueRepo(db)
	item, err := repo.Enqueue(&internal.QueueItem{SessionID: sid, Source: internal.QueueItemSourceUser, Content: "retry after connection reset by peer"})
	if err != nil {
		t.Fatal(err)
	}
	run := &internal.Run{ID: internal.NewRunID(), SessionID: sid, Status: internal.RunRunning, CreatedAt: time.Now()}
	attempts := 0
	batch, err := repo.DispatchPending(sid, run, func(items []internal.QueueItem) (*internal.Message, error) {
		attempts++
		if attempts == 1 {
			// Commit through another connection after the dispatch SELECT and before
			// its first write: deterministically produces SQLITE_BUSY_SNAPSHOT.
			if err := NewQueueRepo(other).SetPaused(sid, false); err != nil {
				t.Fatal(err)
			}
		}
		return &internal.Message{ID: internal.NewMessageID(), Role: "user", Content: fmt.Sprintf("%d reports", len(items)), CreatedAt: time.Now()}, nil
	})
	if err != nil {
		t.Fatalf("dispatch after %d attempts: %v", attempts, err)
	}
	if attempts != 2 || len(batch) != 1 || batch[0].ID != item.ID {
		t.Fatalf("attempts=%d batch=%+v", attempts, batch)
	}
	messages, err := NewMessageRepo(db).GetBySession(sid)
	if err != nil || len(messages) != 1 || messages[0].Content != "1 reports" {
		t.Fatalf("messages=%+v err=%v", messages, err)
	}
	pending, err := repo.ListPending(sid)
	if err != nil || len(pending) != 0 {
		t.Fatalf("pending=%+v err=%v", pending, err)
	}
}

func TestRestoreUndispatchedPreservesAttachmentsAndHistory(t *testing.T) {
	repo, sid := newQueueTestRepo(t)
	_, err := repo.Enqueue(&internal.QueueItem{SessionID: sid, Source: internal.QueueItemSourceUser, Content: "inspect", Attachments: []internal.Attachment{{FileName: "input.txt", MediaType: "text/plain", Data: "aGVsbG8="}}})
	if err != nil {
		t.Fatal(err)
	}
	run := &internal.Run{ID: internal.NewRunID(), SessionID: sid, Status: internal.RunRunning, CreatedAt: time.Now()}
	batch, err := repo.DispatchPending(sid, run, func(items []internal.QueueItem) (*internal.Message, error) {
		return &internal.Message{ID: internal.NewMessageID(), Role: "user", Content: "inspect", Attachments: items[0].Attachments, CreatedAt: time.Now()}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.RestoreUndispatched(sid, run.ID, batch); err != nil {
		t.Fatal(err)
	}
	claimed, err := repo.ClaimPending(sid, internal.NewRunID())
	if err != nil || len(claimed) != 1 || claimed[0].Attachments[0].Data != "aGVsbG8=" {
		t.Fatalf("restored=%+v err=%v", claimed, err)
	}
	history, err := NewMessageRepo(repo.db).GetBySession(sid)
	if err != nil || len(history) != 0 {
		t.Fatalf("history=%+v err=%v", history, err)
	}
}

func TestQueueRepoAtomicUserResumeAndReplayAfterStop(t *testing.T) {
	repo, session := newQueueTestRepo(t)
	makeItem := func() *internal.QueueItem {
		return &internal.QueueItem{SessionID: session, Source: internal.QueueItemSourceUser, ClientMessageID: "same-send", Content: "resume me", Attachments: []internal.Attachment{{MediaType: "image/png", Data: "aGVsbG8="}}}
	}
	if err := repo.SetPaused(session, true); err != nil {
		t.Fatal(err)
	}
	// Invalid input must never release pause.
	invalid := makeItem()
	invalid.Metadata = []byte("invalid json")
	if _, _, err := repo.EnqueueUserAndResume(invalid); err == nil {
		t.Fatal("expected validation error")
	}
	if paused, _ := repo.IsPaused(session); !paused {
		t.Fatal("invalid send resumed queue")
	}
	first, inserted, err := repo.EnqueueUserAndResume(makeItem())
	if err != nil || !inserted {
		t.Fatalf("enqueue %v %v", inserted, err)
	}
	if paused, _ := repo.IsPaused(session); paused {
		t.Fatal("valid input failed to resume")
	}
	// Replaying a pending request does not duplicate it and can recover acceptance.
	if err := repo.SetPaused(session, true); err != nil {
		t.Fatal(err)
	}
	second, inserted, err := repo.EnqueueUserAndResume(makeItem())
	if err != nil || inserted || second.ID != first.ID {
		t.Fatalf("replay=%#v %v %v", second, inserted, err)
	}
	run := &internal.Run{ID: internal.NewRunID(), SessionID: session, Status: internal.RunRunning, CreatedAt: time.Now()}
	items, err := repo.DispatchPending(session, run, func(items []internal.QueueItem) (*internal.Message, error) {
		return &internal.Message{ID: internal.NewMessageID(), Role: "user", Content: items[0].Content, CreatedAt: time.Now()}, nil
	})
	if err != nil || len(items) != 1 || items[0].Attachments[0].Data != "aGVsbG8=" {
		t.Fatalf("dispatch=%#v %v", items, err)
	}
	if err := repo.SetPaused(session, true); err != nil {
		t.Fatal(err)
	}
	if _, inserted, err := repo.EnqueueUserAndResume(makeItem()); err != nil || inserted {
		t.Fatal("delivered replay was inserted", err)
	}
	if paused, _ := repo.IsPaused(session); !paused {
		t.Fatal("replaying an already delivered message undid a newer Stop")
	}
}
