package store

import (
	"encoding/json"
	"errors"
	"time"
)

// FileChange retains compared listing lines or file signatures, never file
// contents. IDs are monotonically increasing cursors for an append-only history.
type FileChange struct {
	ID         int64  `json:"id,omitempty"`
	ObservedAt string `json:"observed_at,omitempty"`
	ObjectID   string `json:"object_id"`
	Path       string `json:"path"`
	Name       string `json:"name,omitempty"`
	Kind       string `json:"kind"`               // entry (legacy listing line) or signature
	Encoding   string `json:"encoding,omitempty"` // base64 for non-UTF-8 before/after bytes
	Before     string `json:"before,omitempty"`
	After      string `json:"after,omitempty"`
}

// CommitFileObservation preserves evidence, its original finding lifecycle, and
// every compared reference in one transaction. A failed write advances nothing.
// A nil finding is allowed only for an unchanged/initial observation.
func (s *Store) CommitFileObservation(f *Finding, states map[string]string, changes []FileChange) error {
	if f == nil && len(changes) > 0 {
		return errors.New("file changes require a finding")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var saved Finding
	if f != nil {
		saved = *f
		saved.Evidence = map[string]string{}
		for k, v := range f.Evidence {
			saved.Evidence[k] = v
		}
		if saved.ID == 0 {
			if err := insertFinding(tx, &saved); err != nil {
				return err
			}
		} else {
			if _, err := tx.Exec("UPDATE findings SET occurrences=occurrences+1,updated_at=? WHERE id=?", time.Now().Unix(), saved.ID); err != nil {
				return err
			}
		}
	}
	at := time.Now().UTC().Format(time.RFC3339Nano)
	for _, change := range changes {
		change.ID = 0
		if change.ObservedAt == "" {
			change.ObservedAt = at
		}
		data, err := json.Marshal(change)
		if err != nil {
			return err
		}
		if _, err := tx.Exec("INSERT INTO file_changes(finding_id,data) VALUES(?,?)", saved.ID, string(data)); err != nil {
			return err
		}
	}
	if f != nil && len(changes) > 0 {
		saved.Evidence["file_changes_available"] = "true"
		data, err := json.Marshal(saved.Evidence)
		if err != nil {
			return err
		}
		if _, err := tx.Exec("UPDATE findings SET evidence=? WHERE id=?", string(data), saved.ID); err != nil {
			return err
		}
	}
	for k, v := range states {
		if _, err := tx.Exec("INSERT INTO kv(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", k, v); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if f != nil {
		*f = saved
	}
	return nil
}

type FileChangePage struct {
	Changes     []FileChange `json:"changes"`
	ThroughID   int64        `json:"through_id"`
	NextAfterID int64        `json:"next_after_id"`
	More        bool         `json:"more"`
}

// FileChanges returns a stable page through a captured upper cursor. A caller
// can finish that range, then omit through to discover later observations.
func (s *Store) FileChanges(findingID, after, through int64, limit int) (FileChangePage, error) {
	page := FileChangePage{Changes: []FileChange{}, NextAfterID: after}
	if findingID <= 0 || after < 0 || through < 0 || limit < 1 || limit > 50 {
		return page, errors.New("invalid finding, cursor or page size")
	}
	if through == 0 {
		if err := s.db.QueryRow("SELECT COALESCE(MAX(id),0) FROM file_changes WHERE finding_id=?", findingID).Scan(&through); err != nil {
			return page, err
		}
	}
	page.ThroughID = through
	if after > through && through != 0 {
		return page, errors.New("after_id exceeds through_id")
	}
	rows, err := s.db.Query("SELECT id,data FROM file_changes WHERE finding_id=? AND id>? AND id<=? ORDER BY id LIMIT ?", findingID, after, through, limit+1)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var data string
		if err := rows.Scan(&id, &data); err != nil {
			return page, err
		}
		if len(page.Changes) == limit {
			page.More = true
			break
		}
		var change FileChange
		if err := json.Unmarshal([]byte(data), &change); err != nil {
			return page, err
		}
		change.ID = id
		page.Changes = append(page.Changes, change)
		page.NextAfterID = id
	}
	return page, rows.Err()
}
