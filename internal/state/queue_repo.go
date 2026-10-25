package state

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	internal "github.com/Problem99-io/kodeblue/internal"
)

// QueueRepo persists the per-session inbox of user messages. All state
// transitions that decide delivery ownership happen in a transaction, so no
// queue item is dispatched twice.
type QueueRepo struct {
	db *DB
}

func NewQueueRepo(db *DB) *QueueRepo { return &QueueRepo{db: db} }

func queueNow() time.Time { return time.Now().UTC() }

func queueTimeValue(t time.Time) int64 { return t.UnixNano() }

func queueTimeFromValue(v int64) time.Time { return time.Unix(0, v).UTC() }

func marshalQueueAttachments(attachments []internal.Attachment) (string, error) {
	if attachments == nil {
		attachments = []internal.Attachment{}
	}
	encoded, err := json.Marshal(attachments)
	if err != nil {
		return "", fmt.Errorf("marshal queue attachments: %w", err)
	}
	return string(encoded), nil
}

func marshalQueueMetadata(metadata json.RawMessage) (string, error) {
	if len(metadata) == 0 {
		return "{}", nil
	}
	if !json.Valid(metadata) {
		return "", errors.New("queue item metadata must be valid JSON")
	}
	return string(metadata), nil
}

func queueSanitize(item internal.QueueItem) internal.QueueItem {
	if len(item.Attachments) == 0 {
		return item
	}
	item.Attachments = append([]internal.Attachment(nil), item.Attachments...)
	for i := range item.Attachments {
		item.Attachments[i].Data = ""
	}
	return item
}

// Enqueue inserts an item in deterministic FIFO order. The returned item is
// always attachment-sanitized.
func (r *QueueRepo) Enqueue(item *internal.QueueItem) (*internal.QueueItem, error) {
	stored, _, err := r.EnqueueUnique(item)
	return stored, err
}

// EnqueueUnique also reports whether this call inserted the item. A user
// message's client_message_id is a durable idempotency key.
func (r *QueueRepo) EnqueueUnique(item *internal.QueueItem) (*internal.QueueItem, bool, error) {
	return r.enqueueUnique(item, false)
}

// EnqueueUserAndResume commits the input and releases pause in one transaction.
// A replay of an already delivered message never resumes a later Stop.
func (r *QueueRepo) EnqueueUserAndResume(item *internal.QueueItem) (*internal.QueueItem, bool, error) {
	if item == nil || item.Source != internal.QueueItemSourceUser {
		return nil, false, errors.New("user message required")
	}
	return r.enqueueUnique(item, true)
}
func (r *QueueRepo) enqueueUnique(item *internal.QueueItem, resume bool) (*internal.QueueItem, bool, error) {
	if item == nil {
		return nil, false, errors.New("queue item is required")
	}
	if item.SessionID == "" {
		return nil, false, errors.New("queue item session ID is required")
	}
	if item.Source != internal.QueueItemSourceUser {
		return nil, false, fmt.Errorf("invalid queue item source %q", item.Source)
	}
	if item.ID == "" {
		item.ID = internal.NewQueueItemID()
	}
	if item.CreatedAt.IsZero() {
		item.CreatedAt = queueNow()
	}
	item.State = internal.QueueItemPending
	item.ClaimRunID = ""
	item.ClaimedAt = nil
	item.DeliveredAt = nil
	item.RemovedAt = nil
	attachments, err := marshalQueueAttachments(item.Attachments)
	if err != nil {
		return nil, false, err
	}
	metadata, err := marshalQueueMetadata(item.Metadata)
	if err != nil {
		return nil, false, err
	}

	var stored internal.QueueItem
	inserted := false
	err = r.db.WithTx(func(tx *sql.Tx) error {
		inserted = false
		unpause := func() error {
			if !resume || stored.State != internal.QueueItemPending {
				return nil
			}
			_, err := tx.Exec(`INSERT INTO session_queue_state (session_id, delivery_paused, failure_reason, updated_at) VALUES (?, 0, '', ?)
 ON CONFLICT(session_id) DO UPDATE SET delivery_paused = 0, failure_reason = '', updated_at = excluded.updated_at`, string(item.SessionID), queueTimeValue(queueNow()))
			return err
		}
		_, insertErr := tx.Exec(
			`INSERT INTO session_queue_items
			 (id, session_id, source, heading, content, client_message_id, source_run_id, metadata, attachments, state, claim_run_id, created_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', '', ?)`,
			string(item.ID), string(item.SessionID), string(item.Source), item.Heading, item.Content,
			item.ClientMessageID, string(item.SourceRunID), metadata, attachments, queueTimeValue(item.CreatedAt),
		)
		if insertErr != nil {
			if item.ClientMessageID == "" {
				return insertErr
			}
			loadErr := scanQueueItem(tx.QueryRow(queueItemSelect+` WHERE source = 'user' AND session_id = ? AND client_message_id = ?`,
				string(item.SessionID), item.ClientMessageID), &stored)
			if loadErr != nil {
				return fmt.Errorf("load deduplicated queue item: %w", loadErr)
			}
			return unpause()
		}
		inserted = true
		if err := scanQueueItem(tx.QueryRow(queueItemSelect+` WHERE id = ?`, string(item.ID)), &stored); err != nil {
			return err
		}
		return unpause()
	})
	if err != nil {
		return nil, false, err
	}
	stored = queueSanitize(stored)
	return &stored, inserted, nil
}

const queueItemSelect = `SELECT id, session_id, source, heading, content, client_message_id, source_run_id,
	metadata, attachments, state, claim_run_id, sequence, created_at, claimed_at, delivered_at, removed_at
 FROM session_queue_items`

type queueRow interface {
	Scan(dest ...any) error
}

func scanQueueItem(row queueRow, item *internal.QueueItem) error {
	var source, state, attachmentJSON, metadataJSON, sourceRunID, claimRunID string
	var createdAt int64
	var claimedAt, deliveredAt, removedAt sql.NullInt64
	err := row.Scan(&item.ID, &item.SessionID, &source, &item.Heading, &item.Content, &item.ClientMessageID,
		&sourceRunID, &metadataJSON, &attachmentJSON, &state, &claimRunID, &item.Sequence, &createdAt, &claimedAt, &deliveredAt, &removedAt)
	if err != nil {
		return err
	}
	item.Source = internal.QueueItemSource(source)
	item.State = internal.QueueItemState(state)
	item.SourceRunID = internal.RunID(sourceRunID)
	item.ClaimRunID = internal.RunID(claimRunID)
	item.Metadata = json.RawMessage(metadataJSON)
	item.CreatedAt = queueTimeFromValue(createdAt)
	if claimedAt.Valid {
		value := queueTimeFromValue(claimedAt.Int64)
		item.ClaimedAt = &value
	}
	if deliveredAt.Valid {
		value := queueTimeFromValue(deliveredAt.Int64)
		item.DeliveredAt = &value
	}
	if removedAt.Valid {
		value := queueTimeFromValue(removedAt.Int64)
		item.RemovedAt = &value
	}
	if err := json.Unmarshal([]byte(attachmentJSON), &item.Attachments); err != nil {
		return fmt.Errorf("decode queue attachments: %w", err)
	}
	return nil
}

// ListPending returns pending items in FIFO order, without attachment bytes.
func (r *QueueRepo) ListPending(sessionID internal.SessionID) ([]internal.QueueItem, error) {
	rows, err := r.db.conn.Query(queueItemSelect+` WHERE session_id = ? AND state = 'pending' ORDER BY sequence ASC`, string(sessionID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]internal.QueueItem, 0)
	for rows.Next() {
		var item internal.QueueItem
		if err := scanQueueItem(rows, &item); err != nil {
			return nil, err
		}
		items = append(items, queueSanitize(item))
	}
	return items, rows.Err()
}

func (r *QueueRepo) PendingCount(sessionID internal.SessionID) (int, error) {
	var count int
	err := r.db.conn.QueryRow(`SELECT COUNT(*) FROM session_queue_items WHERE session_id = ? AND state = 'pending'`, string(sessionID)).Scan(&count)
	return count, err
}

// UpdatePendingUser edits only a pending user item whose content still matches
// the editor's snapshot. The guarded update also protects against dispatch by
// another process and preserves its FIFO position, options and attachments.
func (r *QueueRepo) UpdatePendingUser(sessionID internal.SessionID, itemID internal.QueueItemID, content, expectedContent string) (bool, error) {
	result, err := r.db.Exec(`UPDATE session_queue_items SET content = ?
 WHERE id = ? AND session_id = ? AND source = 'user' AND state = 'pending' AND content = ?`,
		content, string(itemID), string(sessionID), expectedContent)
	if err != nil {
		return false, err
	}
	changed, err := result.RowsAffected()
	return changed == 1, err
}

// RemovePending marks one still-pending item as removed. It returns false when
// the item was missing or had already been claimed/delivered/removed.
func (r *QueueRepo) RemovePending(sessionID internal.SessionID, itemID internal.QueueItemID) (bool, error) {
	now := queueTimeValue(queueNow())
	result, err := r.db.Exec(`UPDATE session_queue_items SET state = 'removed', removed_at = ?
 WHERE id = ? AND session_id = ? AND state = 'pending'`, now, string(itemID), string(sessionID))
	if err != nil {
		return false, err
	}
	changed, err := result.RowsAffected()
	return changed == 1, err
}

func (r *QueueRepo) IsPaused(sessionID internal.SessionID) (bool, error) {
	var paused int
	err := r.db.conn.QueryRow(`SELECT delivery_paused FROM session_queue_state WHERE session_id = ?`, string(sessionID)).Scan(&paused)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return paused != 0, err
}

// SetPaused records whether automatic delivery for a session is paused.
// Resuming clears any recorded delivery failure; pausing keeps it visible.
func (r *QueueRepo) SetPaused(sessionID internal.SessionID, paused bool) error {
	now := queueTimeValue(queueNow())
	if paused {
		_, err := r.db.Exec(`INSERT INTO session_queue_state (session_id, delivery_paused, updated_at) VALUES (?, 1, ?)
 ON CONFLICT(session_id) DO UPDATE SET delivery_paused = 1, updated_at = excluded.updated_at`, string(sessionID), now)
		return err
	}
	_, err := r.db.Exec(`INSERT INTO session_queue_state (session_id, delivery_paused, failure_reason, updated_at) VALUES (?, 0, '', ?)
 ON CONFLICT(session_id) DO UPDATE SET delivery_paused = 0, failure_reason = '', updated_at = excluded.updated_at`, string(sessionID), now)
	return err
}

// PauseWithFailure stops automatic delivery after an undeliverable dispatch and
// records why, so the queue panel can explain the pause until the user resumes.
func (r *QueueRepo) PauseWithFailure(sessionID internal.SessionID, reason string) error {
	_, err := r.db.Exec(`INSERT INTO session_queue_state (session_id, delivery_paused, failure_reason, updated_at) VALUES (?, 1, ?, ?)
 ON CONFLICT(session_id) DO UPDATE SET delivery_paused = 1, failure_reason = excluded.failure_reason, updated_at = excluded.updated_at`, string(sessionID), reason, queueTimeValue(queueNow()))
	return err
}

// FailureReason returns the recorded reason delivery was paused, if any.
func (r *QueueRepo) FailureReason(sessionID internal.SessionID) (string, error) {
	var reason string
	err := r.db.conn.QueryRow(`SELECT failure_reason FROM session_queue_state WHERE session_id = ?`, string(sessionID)).Scan(&reason)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return reason, err
}

// ClaimPending atomically snapshots every pending item currently available for
// a session and assigns it to runID. New enqueues commit after this transaction
// and therefore remain pending for the following continuation. A paused session
// deliberately returns an empty claim.
func (r *QueueRepo) ClaimPending(sessionID internal.SessionID, runID internal.RunID) ([]internal.QueueItem, error) {
	return r.claimPending(sessionID, runID, nil)
}

// ClaimPendingAndCreateRun combines the per-session busy check, run creation,
// and FIFO claim in one transaction. This is the cross-process serialization
// point: two server processes cannot start overlapping main runs for a session.
func (r *QueueRepo) ClaimPendingAndCreateRun(sessionID internal.SessionID, run *internal.Run) ([]internal.QueueItem, error) {
	if run == nil || run.ID == "" || run.SessionID != sessionID {
		return nil, errors.New("matching queue run is required")
	}
	return r.claimPending(sessionID, run.ID, run)
}

// DispatchPending atomically snapshots the inbox, creates its run, persists
// the exact synthetic user turn built from that snapshot, and marks the items
// delivered. There is no crash-visible claimed/run gap to reconcile.
func (r *QueueRepo) DispatchPending(sessionID internal.SessionID, run *internal.Run, build func([]internal.QueueItem) (*internal.Message, error)) ([]internal.QueueItem, error) {
	if run == nil || run.ID == "" || run.SessionID != sessionID || build == nil {
		return nil, errors.New("valid queue dispatch is required")
	}
	items := make([]internal.QueueItem, 0)
	err := r.db.WithTx(func(tx *sql.Tx) error {
		// WithTx may replay this closure after SQLITE_BUSY_SNAPSHOT.
		// Each attempt must build a fresh batch from its own snapshot.
		items = items[:0]
		var paused int
		err := tx.QueryRow(`SELECT delivery_paused FROM session_queue_state WHERE session_id = ?`, string(sessionID)).Scan(&paused)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if paused != 0 {
			return nil
		}
		var active int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM runs WHERE session_id = ? AND status = 'running'`, string(sessionID)).Scan(&active); err != nil {
			return err
		}
		if active != 0 {
			return nil
		}
		rows, err := tx.Query(queueItemSelect+` WHERE session_id = ? AND state = 'pending' ORDER BY sequence ASC`, string(sessionID))
		if err != nil {
			return err
		}
		for rows.Next() {
			var item internal.QueueItem
			if err := scanQueueItem(rows, &item); err != nil {
				rows.Close()
				return err
			}
			items = append(items, item)
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if len(items) == 0 {
			return nil
		}
		message, err := build(items)
		if err != nil {
			return err
		}
		if message == nil {
			return errors.New("dispatch message is required")
		}
		if _, err := tx.Exec(`INSERT INTO runs (id, session_id, status, tool_calls, tokens_used, created_at, completed_at) VALUES (?, ?, ?, ?, ?, ?, NULL)`, string(run.ID), string(sessionID), string(run.Status), run.ToolCalls, run.TokensUsed, run.CreatedAt.Unix()); err != nil {
			return err
		}
		if err := insertMessageTx(tx, sessionID, run.ID, message, 0); err != nil {
			return err
		}
		now := queueTimeValue(queueNow())
		for _, item := range items {
			attachmentsJSON, err := marshalQueueAttachments(queueSanitize(item).Attachments)
			if err != nil {
				return err
			}
			result, err := tx.Exec(`UPDATE session_queue_items SET state = 'delivered', claim_run_id = ?, claimed_at = ?, delivered_at = ?, attachments = ? WHERE id = ? AND state = 'pending'`, string(run.ID), now, now, attachmentsJSON, string(item.ID))
			if err != nil {
				return err
			}
			if changed, _ := result.RowsAffected(); changed != 1 {
				return fmt.Errorf("queue item %q changed during dispatch", item.ID)
			}
		}
		return nil
	})
	return items, err
}

func (r *QueueRepo) claimPending(sessionID internal.SessionID, runID internal.RunID, run *internal.Run) ([]internal.QueueItem, error) {
	if runID == "" {
		return nil, errors.New("claim run ID is required")
	}
	items := make([]internal.QueueItem, 0)
	err := r.db.WithTx(func(tx *sql.Tx) error {
		// WithTx may replay this closure after SQLITE_BUSY_SNAPSHOT.
		// Each attempt must build a fresh batch from its own snapshot.
		items = items[:0]
		var paused int
		err := tx.QueryRow(`SELECT delivery_paused FROM session_queue_state WHERE session_id = ?`, string(sessionID)).Scan(&paused)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if paused != 0 {
			return nil
		}
		if run != nil {
			var active int
			if err := tx.QueryRow(`SELECT COUNT(*) FROM runs WHERE session_id = ? AND status = 'running'`, string(sessionID)).Scan(&active); err != nil {
				return err
			}
			if active != 0 {
				return nil
			}
		}
		rows, err := tx.Query(queueItemSelect+` WHERE session_id = ? AND state = 'pending' ORDER BY sequence ASC`, string(sessionID))
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item internal.QueueItem
			if err := scanQueueItem(rows, &item); err != nil {
				return err
			}
			items = append(items, item)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if len(items) == 0 {
			return nil
		}
		if run != nil {
			if _, err := tx.Exec(`INSERT INTO runs (id, session_id, status, tool_calls, tokens_used, created_at, completed_at)
			 VALUES (?, ?, ?, ?, ?, ?, NULL)`, string(run.ID), string(run.SessionID), string(run.Status),
				run.ToolCalls, run.TokensUsed, run.CreatedAt.Unix()); err != nil {
				return err
			}
		}
		now := queueTimeValue(queueNow())
		for i := range items {
			result, err := tx.Exec(`UPDATE session_queue_items SET state = 'claimed', claim_run_id = ?, claimed_at = ?
 WHERE id = ? AND session_id = ? AND state = 'pending'`, string(runID), now, string(items[i].ID), string(sessionID))
			if err != nil {
				return err
			}
			changed, err := result.RowsAffected()
			if err != nil {
				return err
			}
			if changed != 1 {
				return fmt.Errorf("queue item %q changed while claiming", items[i].ID)
			}
			items[i].State = internal.QueueItemClaimed
			items[i].ClaimRunID = runID
			claimedAt := queueTimeFromValue(now)
			items[i].ClaimedAt = &claimedAt
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return items, nil
}

// ReleaseClaim returns a failed continuation's items to the pending queue in
// their original sequence order.
func (r *QueueRepo) ReleaseClaim(sessionID internal.SessionID, runID internal.RunID) (int, error) {
	result, err := r.db.Exec(`UPDATE session_queue_items SET state = 'pending', claim_run_id = '', claimed_at = NULL
 WHERE session_id = ? AND claim_run_id = ? AND state = 'claimed'`, string(sessionID), string(runID))
	if err != nil {
		return 0, err
	}
	changed, err := result.RowsAffected()
	return int(changed), err
}

// RestoreUndispatched returns a batch to the inbox when RunAsync failed
// before launching the provider loop. Remove only that attempt's synthetic
// message, and restore original attachment payloads for the retry.
func (r *QueueRepo) RestoreUndispatched(sessionID internal.SessionID, runID internal.RunID, items []internal.QueueItem) error {
	return r.db.WithTx(func(tx *sql.Tx) error {
		for _, item := range items {
			if item.SessionID != sessionID {
				return errors.New("dispatch session mismatch")
			}
			attachments, err := marshalQueueAttachments(item.Attachments)
			if err != nil {
				return err
			}
			result, err := tx.Exec(`UPDATE session_queue_items SET state = 'pending', claim_run_id = '', claimed_at = NULL, delivered_at = NULL, attachments = ? WHERE id = ? AND session_id = ? AND claim_run_id = ? AND state = 'delivered'`, attachments, string(item.ID), string(sessionID), string(runID))
			if err != nil {
				return err
			}
			changed, err := result.RowsAffected()
			if err != nil {
				return err
			}
			if changed != 1 {
				return fmt.Errorf("queue item %q no longer belongs to failed dispatch", item.ID)
			}
		}
		if _, err := tx.Exec(`DELETE FROM messages WHERE session_id = ? AND run_id = ?`, string(sessionID), string(runID)); err != nil {
			return err
		}
		_, err := tx.Exec(`UPDATE runs SET status = 'failed', completed_at = ? WHERE id = ? AND session_id = ?`, time.Now().Unix(), string(runID), string(sessionID))
		return err
	})
}

// RecoverClaims releases orphaned claims whose dispatch run is no longer
// running. Claims owned by a running row may belong to another process sharing
// the database and must not be stolen during startup.
func (r *QueueRepo) RecoverClaims() (int, error) {
	result, err := r.db.Exec(`UPDATE session_queue_items SET state = 'pending', claim_run_id = '', claimed_at = NULL
	 WHERE state = 'claimed' AND NOT EXISTS (
	   SELECT 1 FROM runs WHERE runs.id = session_queue_items.claim_run_id AND runs.status = 'running'
	 )`)
	if err != nil {
		return 0, err
	}
	changed, err := result.RowsAffected()
	return int(changed), err
}

// MarkDelivered finalizes a claim and removes inline attachment data while
// retaining each descriptor in the stored JSON for transcript/history display.
func (r *QueueRepo) MarkDelivered(sessionID internal.SessionID, runID internal.RunID) (int, error) {
	returned := 0
	err := r.db.WithTx(func(tx *sql.Tx) error {
		rows, err := tx.Query(queueItemSelect+` WHERE session_id = ? AND claim_run_id = ? AND state = 'claimed' ORDER BY sequence ASC`, string(sessionID), string(runID))
		if err != nil {
			return err
		}
		defer rows.Close()
		items := make([]internal.QueueItem, 0)
		for rows.Next() {
			var item internal.QueueItem
			if err := scanQueueItem(rows, &item); err != nil {
				return err
			}
			items = append(items, item)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if len(items) == 0 {
			return nil
		}
		now := queueTimeValue(queueNow())
		for _, item := range items {
			attachments, err := marshalQueueAttachments(queueSanitize(item).Attachments)
			if err != nil {
				return err
			}
			result, err := tx.Exec(`UPDATE session_queue_items
 SET state = 'delivered', delivered_at = ?, attachments = ?
 WHERE id = ? AND session_id = ? AND claim_run_id = ? AND state = 'claimed'`,
				now, attachments, string(item.ID), string(sessionID), string(runID))
			if err != nil {
				return err
			}
			changed, err := result.RowsAffected()
			if err != nil {
				return err
			}
			if changed != 1 {
				return fmt.Errorf("queue item %q changed while delivering", item.ID)
			}
			returned++
		}
		return nil
	})
	return returned, err
}

// PersistClaimedMessage atomically commits the transcript copy of a claimed
// batch and marks that batch delivered. A crash can therefore leave the batch
// on exactly one side of the handoff, never both pending and persisted.
func (r *QueueRepo) PersistClaimedMessage(sessionID internal.SessionID, runID internal.RunID, message *internal.Message) error {
	if message == nil {
		return errors.New("claimed queue message is required")
	}
	return r.db.WithTx(func(tx *sql.Tx) error {
		var claimed int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM session_queue_items
		 WHERE session_id = ? AND claim_run_id = ? AND state = 'claimed'`, string(sessionID), string(runID)).Scan(&claimed); err != nil {
			return err
		}
		if claimed == 0 {
			return errors.New("queue claim is no longer available")
		}
		if err := insertMessageTx(tx, sessionID, runID, message, 0); err != nil {
			return err
		}
		now := queueTimeValue(queueNow())
		rows, err := tx.Query(queueItemSelect+` WHERE session_id = ? AND claim_run_id = ? AND state = 'claimed'`, string(sessionID), string(runID))
		if err != nil {
			return err
		}
		items := make([]internal.QueueItem, 0, claimed)
		for rows.Next() {
			var item internal.QueueItem
			if err := scanQueueItem(rows, &item); err != nil {
				rows.Close()
				return err
			}
			items = append(items, item)
		}
		if err := rows.Close(); err != nil {
			return err
		}
		for _, item := range items {
			attachments, err := marshalQueueAttachments(queueSanitize(item).Attachments)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(`UPDATE session_queue_items SET state = 'delivered', delivered_at = ?, attachments = ?
			 WHERE id = ? AND session_id = ? AND claim_run_id = ? AND state = 'claimed'`, now, attachments,
				string(item.ID), string(sessionID), string(runID)); err != nil {
				return err
			}
		}
		return nil
	})
}

// OutstandingCount includes legacy in-flight claims: neither claimed nor queued
// input is proof of delivery. Completion must wait for both.
func (r *QueueRepo) OutstandingCount(sessionID internal.SessionID) (int, error) {
	var count int
	err := r.db.conn.QueryRow(`SELECT COUNT(*) FROM session_queue_items WHERE session_id = ? AND state IN ('pending', 'claimed')`, string(sessionID)).Scan(&count)
	return count, err
}
