package state

import (
	"database/sql"
	"fmt"
	"time"

	internal "github.com/Problem99-io/kodeblue/internal"
)

// LifecycleRepair is durable evidence of an automatic dismissal, never a user
// decision. Keeping the journal lets clients retry projection after disconnects.
type LifecycleRepair struct {
	SessionID internal.SessionID `json:"session_id"`
	RunID     internal.RunID     `json:"run_id"`
	Kind      string             `json:"kind"`
	ItemID    string             `json:"item_id"`
	Reason    string             `json:"reason"`
}

// ReconcileSessionBlockers repairs only requests with a proven terminal owner.
// Age, missing process-local waiters, a newer run, and absent main-run rows are
// NOT terminal evidence. In particular, interrupted questions stay resumable and
// children have their own lifecycle independent of the parent. All evidence,
// conditional updates, and audit records share a transaction.
func (db *DB) ReconcileSessionBlockers(sessionID internal.SessionID) ([]LifecycleRepair, error) {
	err := db.WithTx(func(tx *sql.Tx) error {
		rows, err := tx.Query(`SELECT 'question', id, run_id FROM pending_questions WHERE session_id = ? AND status IN ('pending', 'resuming')`, string(sessionID))
		if err != nil {
			return err
		}
		var candidates []LifecycleRepair
		for rows.Next() {
			item := LifecycleRepair{SessionID: sessionID}
			if err := rows.Scan(&item.Kind, &item.ItemID, &item.RunID); err != nil {
				rows.Close()
				return err
			}
			candidates = append(candidates, item)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, item := range candidates {
			status, err := terminalOwner(tx, sessionID, item.RunID)
			if err != nil {
				return err
			}
			if status == "" {
				continue
			}
			item.Reason = "owner_run_" + status
			now := time.Now().Unix()
			// Do not fabricate an answer or erase an already recorded one.
			result, err := tx.Exec(`UPDATE pending_questions SET status = 'ignored', resolved_at = ? WHERE session_id = ? AND id = ? AND status IN ('pending', 'resuming')`, now, string(sessionID), item.ItemID)
			if err != nil {
				return err
			}
			changed, err := result.RowsAffected()
			if err != nil {
				return err
			}
			if changed == 0 {
				continue
			}
			if _, err = tx.Exec(`INSERT INTO lifecycle_repairs(session_id, run_id, kind, item_id, reason, created_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(kind, item_id) DO NOTHING`, string(sessionID), string(item.RunID), item.Kind, item.ItemID, item.Reason, now); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("reconcile session blockers: %w", err)
	}
	rows, err := db.conn.Query(`SELECT session_id, run_id, kind, item_id, reason FROM lifecycle_repairs WHERE session_id = ? ORDER BY created_at, kind, item_id`, string(sessionID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	repairs := []LifecycleRepair{}
	for rows.Next() {
		var item LifecycleRepair
		if err := rows.Scan(&item.SessionID, &item.RunID, &item.Kind, &item.ItemID, &item.Reason); err != nil {
			return nil, err
		}
		repairs = append(repairs, item)
	}
	return repairs, rows.Err()
}

func terminalOwner(tx *sql.Tx, sessionID internal.SessionID, runID internal.RunID) (string, error) {
	var status, ownerSession string
	err := tx.QueryRow(`SELECT status, session_id FROM runs WHERE id = ?`, string(runID)).Scan(&status, &ownerSession)
	if err == nil {
		if ownerSession != string(sessionID) {
			return "", nil
		}
		switch status {
		case "completed", "failed", "aborted":
			return status, nil
		default:
			return "", nil // Includes interrupted, paused and live runs.
		}
	}
	if err != sql.ErrNoRows {
		return "", err
	}
	// A run without a runs row: use its latest durable lifecycle event, never a
	// model-turn completion.
	err = tx.QueryRow(`SELECT type FROM events WHERE session_id = ? AND run_id = ? AND type IN
        ('run.started', 'run.completed', 'run.failed', 'run.aborted', 'run.interrupted')
        ORDER BY seq DESC, id DESC LIMIT 1`, string(sessionID), string(runID)).Scan(&status)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	switch status {
	case "run.completed":
		return "completed", nil
	case "run.failed":
		return "failed", nil
	case "run.aborted":
		return "aborted", nil
	default:
		return "", nil
	}
}
