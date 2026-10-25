package state

import (
	"database/sql"
	"time"

	internal "github.com/Problem99-io/kodeblue/internal"
)

type RunRepo struct {
	db *DB
}

func NewRunRepo(db *DB) *RunRepo {
	return &RunRepo{db: db}
}

func (r *RunRepo) Create(run *internal.Run) error {
	var completedAt *int64
	if run.CompletedAt != nil {
		v := run.CompletedAt.Unix()
		completedAt = &v
	}
	_, err := r.db.Exec(
		`INSERT INTO runs (id, session_id, status, tool_calls, tokens_used, created_at, completed_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		string(run.ID), string(run.SessionID), string(run.Status),
		run.ToolCalls, run.TokensUsed, run.CreatedAt.Unix(), completedAt,
	)
	return err
}

func (r *RunRepo) Get(id internal.RunID) (*internal.Run, error) {
	var run internal.Run
	var createdAt int64
	var completedAt sql.NullInt64
	err := r.db.conn.QueryRow(
		`SELECT id, session_id, status, tool_calls, tokens_used, created_at, completed_at
		 FROM runs WHERE id = ?`, string(id),
	).Scan(&run.ID, &run.SessionID, &run.Status, &run.ToolCalls, &run.TokensUsed, &createdAt, &completedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	run.CreatedAt = time.Unix(createdAt, 0)
	if completedAt.Valid {
		t := time.Unix(completedAt.Int64, 0)
		run.CompletedAt = &t
	}
	return &run, nil
}

func (r *RunRepo) Update(run *internal.Run) error {
	var completedAt *int64
	if run.CompletedAt != nil {
		v := run.CompletedAt.Unix()
		completedAt = &v
	}
	_, err := r.db.Exec(
		`UPDATE runs SET status = ?, tool_calls = ?, tokens_used = ?, completed_at = ? WHERE id = ?`,
		string(run.Status), run.ToolCalls, run.TokensUsed, completedAt, string(run.ID),
	)
	return err
}

func (r *RunRepo) GetBySession(sessionID internal.SessionID) ([]*internal.Run, error) {
	rows, err := r.db.conn.Query(
		`SELECT id, session_id, status, tool_calls, tokens_used, created_at, completed_at
		 FROM runs WHERE session_id = ? ORDER BY created_at DESC`, string(sessionID),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var runs []*internal.Run
	for rows.Next() {
		var run internal.Run
		var createdAt int64
		var completedAt sql.NullInt64
		if err := rows.Scan(&run.ID, &run.SessionID, &run.Status, &run.ToolCalls, &run.TokensUsed, &createdAt, &completedAt); err != nil {
			return nil, err
		}
		run.CreatedAt = time.Unix(createdAt, 0)
		if completedAt.Valid {
			t := time.Unix(completedAt.Int64, 0)
			run.CompletedAt = &t
		}
		runs = append(runs, &run)
	}
	return runs, rows.Err()
}
