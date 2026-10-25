package state

import (
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	internal "github.com/Problem99-io/kodeblue/internal"
)

// SessionRunLease proves that no other runtime is executing this session.
// The kernel releases the lock on process exit, including SIGKILL. Lock files
// must remain in place: unlinking one could let callers lock different inodes.
type SessionRunLease struct {
	mu       sync.Mutex
	file     *os.File
	database string
	session  internal.SessionID
	closed   bool
}

func (l *SessionRunLease) Release() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.closed {
		l.closed = true
		_ = l.file.Close()
	}
}

// TryAcquireSessionRunLease returns nil without error when another runtime
// owns the session. A durable runs.status value alone cannot prove liveness.
func (r *RunRepo) TryAcquireSessionRunLease(sessionID internal.SessionID) (*SessionRunLease, error) {
	if sessionID == "" {
		return nil, errors.New("session ID is required")
	}
	dir := r.db.path + ".run-locks"
	if err := os.MkdirAll(dir, 0770); err != nil {
		return nil, err
	}
	name := fmt.Sprintf("%x.lock", sha256.Sum256([]byte(sessionID)))
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_RDWR, 0660)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, nil
		}
		return nil, err
	}
	return &SessionRunLease{file: f, database: r.db.path, session: sessionID}, nil
}

// RecoverOrphanedSessionRuns is called before creating the next run, while
// holding exclusive execution ownership. It cannot steal another process's
// live turn, even when both runtimes share the same project database.
func (r *RunRepo) RecoverOrphanedSessionRuns(lease *SessionRunLease) ([]internal.RunID, error) {
	if lease == nil {
		return nil, errors.New("session execution lease is required")
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.closed || lease.database != r.db.path {
		return nil, errors.New("invalid session execution lease")
	}
	var recovered []internal.RunID
	err := r.db.WithTx(func(tx *sql.Tx) error {
		recovered = nil
		rows, err := tx.Query(`UPDATE runs SET status = 'failed', completed_at = ? WHERE session_id = ? AND status = 'running' RETURNING id`, time.Now().Unix(), string(lease.session))
		if err != nil {
			return err
		}
		for rows.Next() {
			var id internal.RunID
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			recovered = append(recovered, id)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		_, err = tx.Exec(`UPDATE session_queue_items SET state = 'pending', claim_run_id = '', claimed_at = NULL WHERE session_id = ? AND state = 'claimed' AND NOT EXISTS (SELECT 1 FROM runs WHERE runs.id = session_queue_items.claim_run_id AND runs.status = 'running')`, string(lease.session))
		return err
	})
	return recovered, err
}
