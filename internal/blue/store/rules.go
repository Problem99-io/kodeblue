package store

import (
	"encoding/json"
	"fmt"
	"time"
)

// Containment rule proposals: what agents proposed, waiting for a person.
// Only the proposal lives here (the kodeblue user writes it); an approved
// rule is the root helper's (respond.ApproveRule), which never reads this
// table to decide anything.
const ruleSchema = `CREATE TABLE IF NOT EXISTS rule_proposals (
  id TEXT PRIMARY KEY, body TEXT NOT NULL, status TEXT NOT NULL, proposed_by TEXT NOT NULL,
  note TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)`

// RuleProposal is one proposed containment rule. Body is the rule as
// proposed (respond.Rule); Status is proposed, or rejected/withdrawn.
type RuleProposal struct {
	ID         string          `json:"id"`
	Body       json.RawMessage `json:"body"`
	Status     string          `json:"status"`
	ProposedBy string          `json:"proposed_by"`
	Note       string          `json:"note,omitempty"`
	CreatedAt  time.Time       `json:"created_at"`
	UpdatedAt  time.Time       `json:"updated_at"`
}

// PutRuleProposal records a proposal, or replaces the one with its id (a
// changed proposal needs a fresh approval: its hash changes).
func (s *Store) PutRuleProposal(id string, body []byte, by string) error {
	now := time.Now().Unix()
	_, err := s.db.Exec(`INSERT INTO rule_proposals(id,body,status,proposed_by,created_at,updated_at) VALUES(?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET body=excluded.body, status=excluded.status, proposed_by=excluded.proposed_by, note='', updated_at=excluded.updated_at`,
		id, string(body), "proposed", by, now, now)
	if err == nil {
		s.Journal(by, "rule.proposed", id)
	}
	return err
}

// SetRuleProposalStatus marks a proposal rejected (or proposed again).
func (s *Store) SetRuleProposalStatus(id, status, by, note string) error {
	res, err := s.db.Exec(`UPDATE rule_proposals SET status=?, note=?, updated_at=? WHERE id=?`, status, note, time.Now().Unix(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("no proposed containment rule %q", id)
	}
	s.Journal(by, "rule."+status, id+": "+note)
	return nil
}

// RuleProposals lists every proposal, oldest first.
func (s *Store) RuleProposals() []RuleProposal {
	rows, err := s.db.Query(`SELECT id,body,status,proposed_by,note,created_at,updated_at FROM rule_proposals ORDER BY created_at, id`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []RuleProposal
	for rows.Next() {
		var p RuleProposal
		var body string
		var c, u int64
		if rows.Scan(&p.ID, &body, &p.Status, &p.ProposedBy, &p.Note, &c, &u) == nil {
			p.Body, p.CreatedAt, p.UpdatedAt = json.RawMessage(body), time.Unix(c, 0), time.Unix(u, 0)
			out = append(out, p)
		}
	}
	return out
}
