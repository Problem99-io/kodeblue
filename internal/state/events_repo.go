package state

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	internal "github.com/Problem99-io/kodeblue/internal"
)

type EventRepo struct {
	db *DB
	mu sync.Mutex
}

func NewEventRepo(db *DB) *EventRepo {
	return &EventRepo{db: db}
}

// Append stores an event and sets its per-session seq.
//
// The seq is allocated inside the INSERT itself: MAX(seq) over the session is
// a single descent of idx_events_session_seq, and doing it in the same
// statement makes allocation atomic under SQLite's write lock, so two
// processes sharing the database can no longer read the same MAX and write a
// duplicate seq (the old separate SELECT was only guarded by this process's
// mutex).
func (r *EventRepo) Append(e *internal.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	payload, err := json.Marshal(e.Payload)
	if err != nil {
		payload = []byte("{}")
	}
	meta, err := json.Marshal(e.Meta)
	if err != nil {
		meta = []byte("{}")
	}
	for attempt := 0; ; attempt++ {
		err = r.db.conn.QueryRow(
			`INSERT INTO events (session_id, run_id, seq, type, payload, meta, created_at, created_at_ns)
			 SELECT ?, ?, COALESCE(MAX(seq), 0) + 1, ?, ?, ?, ?, ? FROM events WHERE session_id = ?
			 RETURNING seq`,
			string(e.SessionID), string(e.RunID), e.Type,
			string(payload), string(meta), e.Timestamp.Unix(), e.Timestamp.UnixNano(), string(e.SessionID),
		).Scan(&e.Seq)
		if err == nil || !IsBusyErr(err) || attempt+1 >= writeAttempts {
			return err
		}
		if attempt < len(writeRetryBackoff) {
			sleepWithJitter(writeRetryBackoff[attempt])
		}
	}
}

func (r *EventRepo) GetBySession(sessionID internal.SessionID, afterSeq int64, limit int) ([]*internal.Event, error) {
	rows, err := r.db.conn.Query(
		`SELECT session_id, run_id, seq, type, payload, meta, created_at, created_at_ns
		 FROM events WHERE session_id = ? AND seq > ? ORDER BY seq ASC LIMIT ?`,
		string(sessionID), afterSeq, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return r.scanEvents(rows)
}

func (r *EventRepo) GetByRun(runID internal.RunID) ([]*internal.Event, error) {
	return r.GetByRunAfter(runID, 0, 0)
}

// transientEventTypes are the per-delta streaming events. They matter only
// while their run streams: the finished run's messages hold the same text.
const transientEventTypes = `'model.token', 'tool.streaming'`

// terminalEventTypes record how a run ended; pruning never removes them.
const terminalEventTypes = `'run.completed', 'run.failed', 'run.aborted', 'run.interrupted'`

// SummaryEventLimit caps GetBySessionSummary: a long-lived session's history
// is served as its most recent events rather than every tool output it ever
// produced.
const SummaryEventLimit = 2000

// GetBySessionSummary returns a session's most recent SummaryEventLimit
// events, oldest first, excluding the high-volume streaming deltas.
func (r *EventRepo) GetBySessionSummary(sessionID internal.SessionID) ([]*internal.Event, error) {
	rows, err := r.db.conn.Query(
		`SELECT session_id, run_id, seq, type, payload, meta, created_at, created_at_ns FROM (
		   SELECT session_id, run_id, seq, type, payload, meta, created_at, created_at_ns
		   FROM events WHERE session_id = ? AND type NOT IN (`+transientEventTypes+`)
		   ORDER BY seq DESC LIMIT ?
		 ) ORDER BY seq ASC`,
		string(sessionID), SummaryEventLimit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return r.scanEvents(rows)
}

// EventRetention bounds the events table.
type EventRetention struct {
	// TransientGrace is how long after a run finishes its streaming deltas
	// are kept, so a poller that is still catching up can read them.
	TransientGrace time.Duration
	// MaxEventsPerSession caps how many events a session keeps. Beyond it the
	// oldest events of finished runs are deleted, except run terminal events.
	MaxEventsPerSession int
	// BatchSize is the most rows one DELETE removes. The engine has one
	// SQLite connection and other processes share the file, so a single large
	// DELETE would hold both the connection and the write lock for seconds:
	// event appends would stall and transcript saves elsewhere would fail
	// with SQLITE_BUSY.
	BatchSize int
	// BatchPause is the shortest pause between batches. Each pause also lasts
	// at least as long as the batch before it took, so pruning never holds
	// more than about half of the database's time, however busy the host.
	BatchPause time.Duration
}

// DefaultEventRetention is the engine's standing retention policy.
var DefaultEventRetention = EventRetention{
	TransientGrace:      10 * time.Minute,
	MaxEventsPerSession: 5000,
	BatchSize:           1000,
	BatchPause:          5 * time.Millisecond,
}

// Prune applies the retention policy and returns how many events it deleted.
// It works in bounded batches, each a short statement found through an index,
// and pauses between them so other statements get the connection. A
// session's newest event is never deleted, so its seq never moves backwards
// and an after_seq cursor stays valid.
func (r *EventRepo) Prune(now time.Time, policy EventRetention) (int64, error) {
	if policy.BatchSize <= 0 {
		policy.BatchSize = DefaultEventRetention.BatchSize
	}
	var deleted int64

	// Streaming deltas of runs that finished before the grace window. The
	// candidates come from the runs table, each probed through
	// idx_events_transient, so even a large backlog is never scanned.
	type runRef struct{ run, session string }
	rows, err := r.db.conn.Query(
		`SELECT runs.id, runs.session_id FROM runs
		 WHERE runs.status != 'running' AND runs.completed_at IS NOT NULL AND runs.completed_at <= ?
		   AND EXISTS (SELECT 1 FROM events WHERE events.run_id = runs.id AND type IN (`+transientEventTypes+`))`,
		now.Add(-policy.TransientGrace).Unix(),
	)
	if err != nil {
		return deleted, fmt.Errorf("find runs with streaming events: %w", err)
	}
	var finished []runRef
	for rows.Next() {
		var ref runRef
		if err := rows.Scan(&ref.run, &ref.session); err != nil {
			rows.Close()
			return deleted, err
		}
		finished = append(finished, ref)
	}
	if err := rows.Close(); err != nil {
		return deleted, err
	}
	for _, ref := range finished {
		var newest int64
		if err := r.db.conn.QueryRow(`SELECT COALESCE(MAX(seq), 0) FROM events WHERE session_id = ?`, ref.session).Scan(&newest); err != nil {
			return deleted, err
		}
		n, err := r.deleteInBatches(policy,
			`SELECT id FROM events WHERE run_id = ? AND type IN (`+transientEventTypes+`) AND seq < ? LIMIT ?`,
			ref.run, newest)
		deleted += n
		if err != nil {
			return deleted, fmt.Errorf("prune streaming events of run %s: %w", ref.run, err)
		}
	}

	if policy.MaxEventsPerSession <= 0 {
		return deleted, nil
	}
	// Sessions over the cap. seq increases by one per event and pruning only
	// removes old rows, so MAX-MIN+1 bounds the row count from above: two
	// index probes per session rather than a COUNT over the table.
	rows, err = r.db.conn.Query(`SELECT id FROM sessions`)
	if err != nil {
		return deleted, err
	}
	var sessionIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return deleted, err
		}
		sessionIDs = append(sessionIDs, id)
	}
	if err := rows.Close(); err != nil {
		return deleted, err
	}
	for _, sessionID := range sessionIDs {
		var lo, hi sql.NullInt64
		if err := r.db.conn.QueryRow(`SELECT MIN(seq), MAX(seq) FROM events WHERE session_id = ?`, sessionID).Scan(&lo, &hi); err != nil {
			return deleted, err
		}
		if !lo.Valid || hi.Int64-lo.Int64+1 <= int64(policy.MaxEventsPerSession) {
			continue
		}
		var cutoff int64
		if err := r.db.conn.QueryRow(`SELECT seq FROM events WHERE session_id = ? ORDER BY seq DESC LIMIT 1 OFFSET ?`,
			sessionID, policy.MaxEventsPerSession).Scan(&cutoff); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			return deleted, err
		}
		n, err := r.deleteInBatches(policy,
			`SELECT id FROM events
			 WHERE session_id = ? AND seq <= ?
			   AND type NOT IN (`+terminalEventTypes+`)
			   AND run_id NOT IN (SELECT id FROM runs WHERE status = 'running')
			 LIMIT ?`,
			sessionID, cutoff)
		deleted += n
		if err != nil {
			return deleted, fmt.Errorf("prune events of session %s: %w", sessionID, err)
		}
	}
	return deleted, nil
}

// deleteInBatches deletes the events selectQuery finds, at most
// policy.BatchSize per statement, until none are left. selectQuery returns
// event ids and takes args followed by the batch size as its last parameter.
func (r *EventRepo) deleteInBatches(policy EventRetention, selectQuery string, args ...any) (int64, error) {
	var deleted int64
	batchArgs := append(append([]any(nil), args...), policy.BatchSize)
	for {
		started := time.Now()
		result, err := r.db.Exec(`DELETE FROM events WHERE id IN (`+selectQuery+`)`, batchArgs...)
		if err != nil {
			return deleted, err
		}
		n, _ := result.RowsAffected()
		deleted += n
		if n < int64(policy.BatchSize) {
			return deleted, nil
		}
		time.Sleep(max(policy.BatchPause, time.Since(started)))
	}
}

func (r *EventRepo) scanEvents(rows *sql.Rows) ([]*internal.Event, error) {
	var events []*internal.Event
	for rows.Next() {
		var e internal.Event
		var payloadStr, metaStr string
		var createdAt int64
		var createdAtNS sql.NullInt64
		if err := rows.Scan(&e.SessionID, &e.RunID, &e.Seq, &e.Type, &payloadStr, &metaStr, &createdAt, &createdAtNS); err != nil {
			return nil, err
		}
		e.Payload = json.RawMessage(payloadStr)
		if err := json.Unmarshal([]byte(metaStr), &e.Meta); err != nil {
			e.Meta = map[string]string{}
		}
		if createdAtNS.Valid && createdAtNS.Int64 != 0 {
			e.Timestamp = time.Unix(0, createdAtNS.Int64)
		} else {
			e.Timestamp = time.Unix(createdAt, 0)
		}
		events = append(events, &e)
	}
	return events, rows.Err()
}

// GetRunTerminal reads only one exact run's durable terminal event.
func (r *EventRepo) GetRunTerminal(sessionID internal.SessionID, runID internal.RunID) ([]*internal.Event, error) {
	rows, err := r.db.conn.Query(`SELECT session_id, run_id, seq, type, payload, meta, created_at, created_at_ns
 FROM events WHERE session_id = ? AND run_id = ? AND type IN ('run.completed','run.failed','run.aborted','run.interrupted') ORDER BY seq DESC LIMIT 1`, string(sessionID), string(runID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return r.scanEvents(rows)
}

// LatestProviderConnection restores retry presentation when a panel reconnects.
func (r *EventRepo) LatestProviderConnection(runID internal.RunID) (json.RawMessage, error) {
	rows, err := r.db.conn.Query(`SELECT session_id, run_id, seq, type, payload, meta, created_at, created_at_ns FROM events WHERE run_id = ? AND type = 'provider.connection' ORDER BY seq DESC LIMIT 1`, string(runID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events, err := r.scanEvents(rows)
	if err != nil || len(events) == 0 {
		return nil, err
	}
	return events[0].Payload, nil
}

func (r *EventRepo) GetByRunAfter(runID internal.RunID, afterSeq int64, limit int) ([]*internal.Event, error) {
	query := `SELECT session_id, run_id, seq, type, payload, meta, created_at, created_at_ns
		 FROM events WHERE run_id = ? AND seq > ? ORDER BY seq ASC`
	args := []any{string(runID), afterSeq}
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := r.db.conn.Query(
		query,
		args...,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return r.scanEvents(rows)
}
