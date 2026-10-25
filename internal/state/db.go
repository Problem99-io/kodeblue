package state

import (
	"database/sql"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// DB wraps a SQLite database connection.
type DB struct {
	conn *sql.DB
	path string
}

// NewDB opens a SQLite database at dbPath with WAL mode, busy timeout of 5s,
// and foreign keys enabled.
func NewDB(dbPath string) (*DB, error) {
	if dir := filepath.Dir(dbPath); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o775); err != nil {
			return nil, fmt.Errorf("create database directory %q: %w", dir, err)
		}
	}

	// synchronous(normal) is the standard pairing for WAL: commits stop fsyncing
	// the log every time, which is what makes a write transaction hold the
	// cross-process write lock for milliseconds instead of tens of them. Both
	// files this opens are contended — the per-project database by every task
	// instance under that project, the agents database by every instance on the
	// box — and the hot writer, the event drain, runs continuously while a run
	// streams. The durability given up is the last few transactions on host
	// power-loss or a kernel panic; a process crash is still safe.
	conn, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(wal)&_pragma=synchronous(normal)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=temp_store(memory)")
	if err != nil {
		return nil, err
	}
	conn.SetMaxOpenConns(1)
	if err := conn.Ping(); err != nil {
		conn.Close()
		return nil, err
	}
	resolvedPath, err := filepath.Abs(dbPath)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if canonical, err := filepath.EvalSymlinks(resolvedPath); err == nil {
		resolvedPath = canonical
	}
	return &DB{conn: conn, path: resolvedPath}, nil
}

// Close closes the database connection.
func (db *DB) Close() error {
	return db.conn.Close()
}

// writeAttempts is how many times Exec runs a statement that keeps losing the
// cross-process write lock, and writeRetryBackoff the pause before each retry.
// Four attempts spread over ~1s of backoff on top of the 5s per-attempt busy
// timeout: enough to ride out an event-drain burst or another instance's
// startup seeding, short enough that a genuinely wedged database still surfaces
// as an error rather than hanging a request.
const writeAttempts = 4

var writeRetryBackoff = []time.Duration{100 * time.Millisecond, 300 * time.Millisecond, 600 * time.Millisecond}

// Exec runs a write statement, retrying while SQLite reports the database as
// busy or locked.
//
// Neither file the engine opens has a single writer. The per-project database is
// shared by the project instance and one instance per task worktree; the agents
// database is shared by every instance on the box, each of which seeds the
// bundled roster into it at startup. SQLite serializes writers across processes,
// so any write can lose that race — most often to the event drain, which writes
// continuously while a run streams. Without a retry those collisions surfaced as
// hard failures on user-facing writes: a 500 with "failed to update agent" when
// saving agent settings while anything else on the box was busy.
//
// The retry deliberately re-Execs rather than sitting in one long busy wait:
// SetMaxOpenConns(1) means a blocked writer also holds this process's only
// connection, so releasing it between attempts keeps the rest of the process
// alive.
func (db *DB) Exec(query string, args ...any) (sql.Result, error) {
	var result sql.Result
	var err error
	for attempt := 0; attempt < writeAttempts; attempt++ {
		result, err = db.conn.Exec(query, args...)
		if err == nil || !IsBusyErr(err) {
			return result, err
		}
		if attempt < len(writeRetryBackoff) {
			sleepWithJitter(writeRetryBackoff[attempt])
		}
	}
	return result, err
}

// WithTx runs fn inside a transaction, retrying the whole transaction on the
// same busy/locked conditions Exec retries. fn must be safe to run more than
// once: a retried attempt starts from a rolled-back transaction, so it sees the
// database as it was before the failed try.
func (db *DB) WithTx(fn func(*sql.Tx) error) error {
	var err error
	for attempt := 0; attempt < writeAttempts; attempt++ {
		err = func() error {
			tx, beginErr := db.conn.Begin()
			if beginErr != nil {
				return beginErr
			}
			defer tx.Rollback()
			if fnErr := fn(tx); fnErr != nil {
				return fnErr
			}
			return tx.Commit()
		}()
		if err == nil || !IsBusyErr(err) {
			return err
		}
		if attempt < len(writeRetryBackoff) {
			sleepWithJitter(writeRetryBackoff[attempt])
		}
	}
	return err
}

// sleepWithJitter spreads retries out so two instances that collided once do
// not line up again on the next attempt.
func sleepWithJitter(backoff time.Duration) {
	time.Sleep(backoff + time.Duration(rand.Int63n(int64(backoff/2)+1)))
}

// IsBusyErr reports whether err is SQLite refusing a write because another
// connection — in this process or another one sharing the database file — holds
// the write lock. Callers that surface HTTP status codes should treat it as a
// retryable condition (503) rather than an internal error.
//
// modernc.org/sqlite returns a driver error whose Error() carries the SQLITE_
// symbol, and matching on its concrete type would pull the driver into every
// caller's imports, so match on the message.
func IsBusyErr(err error) bool {
	if err == nil || errors.Is(err, sql.ErrNoRows) {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "database is locked") ||
		strings.Contains(msg, "database table is locked") ||
		strings.Contains(msg, "sqlite_busy") ||
		strings.Contains(msg, "sqlite_locked")
}

// Migrate runs the migration SQL to create all tables and indexes.
func (db *DB) Migrate() error {
	_, err := db.Exec(migrationSQL)
	if err != nil {
		return err
	}
	// Add columns that may be missing in older databases.
	for _, stmt := range []string{
		`ALTER TABLE sessions ADD COLUMN agent_id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE sessions ADD COLUMN cwd TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE messages ADD COLUMN attachments TEXT NOT NULL DEFAULT '[]'`,
		`ALTER TABLE messages ADD COLUMN reasoning_content TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE messages ADD COLUMN reasoning_details TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE messages ADD COLUMN usage TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE messages ADD COLUMN compacted INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE messages ADD COLUMN internal INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE pending_questions ADD COLUMN answer TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE pending_questions ADD COLUMN kind TEXT NOT NULL DEFAULT 'ask_user'`,
		// created_at remains seconds for legacy readers. New event writes use this
		// nanosecond column; COALESCE in EventRepo keeps older databases readable.
		`ALTER TABLE events ADD COLUMN created_at_ns INTEGER`,
		`ALTER TABLE session_queue_state ADD COLUMN failure_reason TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE messages ADD COLUMN position INTEGER NOT NULL DEFAULT 0`,
	} {
		if err := db.addColumn(stmt); err != nil {
			return err
		}
	}
	if err := db.backfillMessagePositions(); err != nil {
		return fmt.Errorf("migrate: backfill message positions: %w", err)
	}
	if _, err := db.Exec(postColumnMigrationSQL); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}

// postColumnMigrationSQL creates the objects that depend on columns added by
// ALTER TABLE above, so it runs after them on databases created by older
// engines.
//
// messages.position is a session's explicit transcript order. Wall-clock
// created_at cannot order a transcript: compaction writes its summary now but
// places it before an older raw tail. The trigger gives every insert that does
// not choose a position the next one in its session, so plain appends from any
// writer (run checkpoints, queue dispatch, initial context) need no change,
// while compaction inserts its summary at an explicit position.
const postColumnMigrationSQL = `
CREATE INDEX IF NOT EXISTS idx_messages_session_position ON messages(session_id, position);
CREATE INDEX IF NOT EXISTS idx_events_run_seq ON events(run_id, seq);
-- Lets retention find the runs that still hold streaming deltas without
-- scanning the table. Deltas are coalesced, so this index stays small.
CREATE INDEX IF NOT EXISTS idx_events_transient ON events(run_id) WHERE type IN ('model.token', 'tool.streaming');
CREATE TRIGGER IF NOT EXISTS messages_assign_position AFTER INSERT ON messages
WHEN NEW.position = 0
BEGIN
    UPDATE messages
    SET position = (SELECT COALESCE(MAX(position), 0) + 1 FROM messages WHERE session_id = NEW.session_id)
    WHERE rowid = NEW.rowid;
END;
`

// backfillMessagePositions numbers messages written before the position
// column existed, in their old created_at order. Those databases may already
// hold a session whose active compaction summary sorts after the raw tail it
// precedes (the summary was stamped at compaction time); the backfill moves
// that summary back in front of the first active message it follows.
func (db *DB) backfillMessagePositions() error {
	var pending int
	if err := db.conn.QueryRow(`SELECT COUNT(*) FROM messages WHERE position = 0`).Scan(&pending); err != nil {
		return err
	}
	if pending == 0 {
		return nil
	}
	return db.WithTx(func(tx *sql.Tx) error {
		rows, err := tx.Query(`SELECT rowid, session_id, position, compacted, role, ltrim(content) LIKE '[Compacted context%'
			FROM messages ORDER BY session_id, created_at, rowid`)
		if err != nil {
			return err
		}
		type row struct {
			rowid     int64
			session   string
			position  int64
			compacted bool
			role      string
			summary   bool
		}
		var all []row
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.rowid, &r.session, &r.position, &r.compacted, &r.role, &r.summary); err != nil {
				rows.Close()
				return err
			}
			all = append(all, r)
		}
		if err := rows.Close(); err != nil {
			return err
		}
		for start := 0; start < len(all); {
			end := start
			for end < len(all) && all[end].session == all[start].session {
				end++
			}
			session := all[start:end]
			start = end

			var maxPosition int64
			unpositioned := 0
			for _, r := range session {
				if r.position > maxPosition {
					maxPosition = r.position
				}
				if r.position == 0 {
					unpositioned++
				}
			}
			if unpositioned == 0 {
				continue
			}
			if unpositioned < len(session) {
				// Rows written after the migration keep their place; any stragglers
				// are appended in created_at order.
				for _, r := range session {
					if r.position != 0 {
						continue
					}
					maxPosition++
					if _, err := tx.Exec(`UPDATE messages SET position = ? WHERE rowid = ?`, maxPosition, r.rowid); err != nil {
						return err
					}
				}
				continue
			}

			ordered := append([]row(nil), session...)
			summaryAt, firstActive := -1, -1
			for i, r := range ordered {
				if r.compacted {
					continue
				}
				if firstActive < 0 && r.role != "system" {
					firstActive = i
				}
				if r.summary {
					summaryAt = i
				}
			}
			if summaryAt > firstActive && firstActive >= 0 {
				summary := ordered[summaryAt]
				copy(ordered[firstActive+1:summaryAt+1], ordered[firstActive:summaryAt])
				ordered[firstActive] = summary
			}
			for i, r := range ordered {
				if _, err := tx.Exec(`UPDATE messages SET position = ? WHERE rowid = ?`, i+1, r.rowid); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// addColumn runs an ALTER TABLE ... ADD COLUMN statement. A column that
// already exists is the expected case on every start after the first and is
// not an error; any other failure is returned with the statement.
func (db *DB) addColumn(stmt string) error {
	if _, err := db.Exec(stmt); err != nil && !isDuplicateColumnErr(err) {
		return fmt.Errorf("migrate: %s: %w", stmt, err)
	}
	return nil
}

// isDuplicateColumnErr reports whether err is SQLite rejecting ADD COLUMN for
// a column that already exists. Like IsBusyErr it matches the message to keep
// the driver out of callers' imports.
func isDuplicateColumnErr(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "duplicate column name")
}

const migrationSQL = `
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'active',
    provider TEXT NOT NULL DEFAULT '',
    model TEXT NOT NULL DEFAULT '',
    agent_id TEXT NOT NULL DEFAULT '',
    cwd TEXT NOT NULL DEFAULT '',
    instructions TEXT NOT NULL DEFAULT '[]',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(id),
    status TEXT NOT NULL DEFAULT 'running',
    tool_calls INTEGER NOT NULL DEFAULT 0,
    tokens_used INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    completed_at INTEGER
);

CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(id),
    run_id TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL,
    content TEXT NOT NULL DEFAULT '',
    reasoning_content TEXT NOT NULL DEFAULT '',
    reasoning_details TEXT NOT NULL DEFAULT '',
    attachments TEXT NOT NULL DEFAULT '[]',
    tool_calls TEXT NOT NULL DEFAULT '[]',
    tool_results TEXT NOT NULL DEFAULT '[]',
    usage TEXT NOT NULL DEFAULT '',
    compacted INTEGER NOT NULL DEFAULT 0,
    internal INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    run_id TEXT NOT NULL DEFAULT '',
    seq INTEGER NOT NULL,
    type TEXT NOT NULL,
    payload TEXT NOT NULL DEFAULT '{}',
    meta TEXT NOT NULL DEFAULT '{}',
    created_at INTEGER NOT NULL,
    created_at_ns INTEGER
);

CREATE TABLE IF NOT EXISTS lifecycle_repairs (
    session_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    item_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (kind, item_id)
);
CREATE INDEX IF NOT EXISTS idx_lifecycle_repairs_session ON lifecycle_repairs(session_id);

CREATE INDEX IF NOT EXISTS idx_events_session_seq ON events(session_id, seq);
CREATE INDEX IF NOT EXISTS idx_runs_session ON runs(session_id, created_at);
CREATE INDEX IF NOT EXISTS idx_messages_session ON messages(session_id, created_at);


CREATE TABLE IF NOT EXISTS pending_questions (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    run_id TEXT NOT NULL DEFAULT '',
    kind TEXT NOT NULL DEFAULT 'ask_user',
    title TEXT NOT NULL DEFAULT '',
    question TEXT NOT NULL,
    mode TEXT NOT NULL DEFAULT '',
    options TEXT NOT NULL DEFAULT '[]',
    custom INTEGER NOT NULL DEFAULT 0,
    recommended TEXT NOT NULL DEFAULT '',
    recommended_choices TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'pending',
    answer TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    resolved_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_pending_questions_session_status ON pending_questions(session_id, status, created_at);
CREATE INDEX IF NOT EXISTS idx_pending_questions_run ON pending_questions(run_id, status, created_at);

CREATE TABLE IF NOT EXISTS session_queue_state (
    session_id TEXT PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
    delivery_paused INTEGER NOT NULL DEFAULT 0,
    failure_reason TEXT NOT NULL DEFAULT '',
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS session_queue_items (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL UNIQUE,
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    source TEXT NOT NULL CHECK(source IN ('user')),
    heading TEXT NOT NULL DEFAULT '',
    content TEXT NOT NULL DEFAULT '',
    client_message_id TEXT NOT NULL DEFAULT '',
    source_run_id TEXT NOT NULL DEFAULT '',
    metadata TEXT NOT NULL DEFAULT '{}',
    attachments TEXT NOT NULL DEFAULT '[]',
    state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending', 'claimed', 'delivered', 'removed')),
    claim_run_id TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    claimed_at INTEGER,
    delivered_at INTEGER,
    removed_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_session_queue_pending ON session_queue_items(session_id, state, sequence);
CREATE INDEX IF NOT EXISTS idx_session_queue_claim ON session_queue_items(session_id, claim_run_id, state, sequence);
CREATE UNIQUE INDEX IF NOT EXISTS idx_session_queue_user_client_message
    ON session_queue_items(session_id, client_message_id)
    WHERE source = 'user' AND client_message_id != '';
`
