package state

import (
	"database/sql"
	"encoding/json"
	"time"

	internal "github.com/Problem99-io/kodeblue/internal"
)

type SessionRepo struct {
	db *DB
}

func NewSessionRepo(db *DB) *SessionRepo {
	return &SessionRepo{db: db}
}

func (r *SessionRepo) Create(s *internal.Session) error {
	instJSON, err := json.Marshal(s.Instructions)
	if err != nil {
		return err
	}
	_, err = r.db.Exec(
		`INSERT INTO sessions (id, status, provider, model, agent_id, cwd, instructions, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		string(s.ID), string(s.Status), s.Provider, s.Model, s.AgentID, s.CWD,
		string(instJSON), s.CreatedAt.Unix(), s.UpdatedAt.Unix(),
	)
	return err
}

func (r *SessionRepo) Get(id internal.SessionID) (*internal.Session, error) {
	var s internal.Session
	var instStr string
	var createdAt, updatedAt int64
	err := r.db.conn.QueryRow(
		`SELECT id, status, provider, model, agent_id, cwd, instructions, created_at, updated_at
		 FROM sessions WHERE id = ?`, string(id),
	).Scan(&s.ID, &s.Status, &s.Provider, &s.Model, &s.AgentID, &s.CWD, &instStr, &createdAt, &updatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	s.CreatedAt = time.Unix(createdAt, 0)
	s.UpdatedAt = time.Unix(updatedAt, 0)
	if err := json.Unmarshal([]byte(instStr), &s.Instructions); err != nil {
		s.Instructions = []string{}
	}
	return &s, nil
}

func (r *SessionRepo) Update(s *internal.Session) error {
	instJSON, err := json.Marshal(s.Instructions)
	if err != nil {
		return err
	}
	s.UpdatedAt = time.Now()
	_, err = r.db.Exec(
		`UPDATE sessions SET status = ?, provider = ?, model = ?, agent_id = ?, cwd = ?, instructions = ?, updated_at = ? WHERE id = ?`,
		string(s.Status), s.Provider, s.Model, s.AgentID, s.CWD, string(instJSON), s.UpdatedAt.Unix(), string(s.ID),
	)
	return err
}

func (r *SessionRepo) List() ([]*internal.Session, error) {
	rows, err := r.db.conn.Query(
		`SELECT id, status, provider, model, agent_id, cwd, instructions, created_at, updated_at FROM sessions ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sessions []*internal.Session
	for rows.Next() {
		var s internal.Session
		var instStr string
		var createdAt, updatedAt int64
		if err := rows.Scan(&s.ID, &s.Status, &s.Provider, &s.Model, &s.AgentID, &s.CWD, &instStr, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		s.CreatedAt = time.Unix(createdAt, 0)
		s.UpdatedAt = time.Unix(updatedAt, 0)
		if err := json.Unmarshal([]byte(instStr), &s.Instructions); err != nil {
			s.Instructions = []string{}
		}
		sessions = append(sessions, &s)
	}
	return sessions, rows.Err()
}

func (r *SessionRepo) Delete(id internal.SessionID) error {
	_, err := r.db.Exec(`DELETE FROM sessions WHERE id = ?`, string(id))
	return err
}
