package state

import (
	"database/sql"
	"encoding/json"
	"time"

	internal "github.com/Problem99-io/kodeblue/internal"
)

type AgentRepo struct {
	db *DB
}

func NewAgentRepo(db *DB) *AgentRepo {
	return &AgentRepo{db: db}
}

func (r *AgentRepo) Create(a *internal.AgentDefinition) error {
	toolsJSON, err := json.Marshal(a.Tools)
	if err != nil {
		return err
	}
	_, err = r.db.Exec(
		`INSERT INTO agent_definitions (id, name, disabled, description, instructions, tools, provider, model, reasoning_effort, max_iterations, max_output_tokens, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.Name, boolToInt(a.Disabled), a.Description, a.Instructions, string(toolsJSON),
		a.Provider, a.Model, a.ReasoningEffort, a.MaxIterations, a.MaxOutputTokens,
		a.CreatedAt.Unix(), a.UpdatedAt.Unix(),
	)
	return err
}

func (r *AgentRepo) Get(id string) (*internal.AgentDefinition, error) {
	return r.scanOne(`SELECT id, name, disabled, description, instructions, tools, provider, model, reasoning_effort, max_iterations, max_output_tokens, created_at, updated_at
		FROM agent_definitions WHERE id = ?`, id)
}

func (r *AgentRepo) GetByName(name string) (*internal.AgentDefinition, error) {
	return r.scanOne(`SELECT id, name, disabled, description, instructions, tools, provider, model, reasoning_effort, max_iterations, max_output_tokens, created_at, updated_at
		FROM agent_definitions WHERE name = ?`, name)
}

func (r *AgentRepo) Update(a *internal.AgentDefinition) error {
	toolsJSON, err := json.Marshal(a.Tools)
	if err != nil {
		return err
	}
	a.UpdatedAt = time.Now()
	_, err = r.db.Exec(
		`UPDATE agent_definitions SET name = ?, disabled = ?, description = ?, instructions = ?, tools = ?, provider = ?, model = ?, reasoning_effort = ?, max_iterations = ?, max_output_tokens = ?, updated_at = ?
		 WHERE id = ?`,
		a.Name, boolToInt(a.Disabled), a.Description, a.Instructions, string(toolsJSON),
		a.Provider, a.Model, a.ReasoningEffort, a.MaxIterations, a.MaxOutputTokens,
		a.UpdatedAt.Unix(), a.ID,
	)
	return err
}

func (r *AgentRepo) Delete(id string) error {
	_, err := r.db.Exec(`DELETE FROM agent_definitions WHERE id = ?`, id)
	return err
}

func (r *AgentRepo) List() ([]*internal.AgentDefinition, error) {
	rows, err := r.db.conn.Query(
		`SELECT id, name, disabled, description, instructions, tools, provider, model, reasoning_effort, max_iterations, max_output_tokens, created_at, updated_at
		 FROM agent_definitions ORDER BY name ASC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var agents []*internal.AgentDefinition
	for rows.Next() {
		a, err := r.scanRow(rows)
		if err != nil {
			return nil, err
		}
		agents = append(agents, a)
	}
	return agents, rows.Err()
}

func (r *AgentRepo) scanOne(query string, args ...any) (*internal.AgentDefinition, error) {
	var a internal.AgentDefinition
	var toolsStr string
	var disabled int64
	var createdAt, updatedAt int64
	err := r.db.conn.QueryRow(query, args...).Scan(
		&a.ID, &a.Name, &disabled, &a.Description, &a.Instructions, &toolsStr,
		&a.Provider, &a.Model, &a.ReasoningEffort, &a.MaxIterations, &a.MaxOutputTokens,
		&createdAt, &updatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	a.Disabled = disabled != 0
	a.CreatedAt = time.Unix(createdAt, 0)
	a.UpdatedAt = time.Unix(updatedAt, 0)
	if err := json.Unmarshal([]byte(toolsStr), &a.Tools); err != nil {
		a.Tools = []string{}
	}
	return &a, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func (r *AgentRepo) scanRow(row rowScanner) (*internal.AgentDefinition, error) {
	var a internal.AgentDefinition
	var toolsStr string
	var disabled int64
	var createdAt, updatedAt int64
	err := row.Scan(
		&a.ID, &a.Name, &disabled, &a.Description, &a.Instructions, &toolsStr,
		&a.Provider, &a.Model, &a.ReasoningEffort, &a.MaxIterations, &a.MaxOutputTokens,
		&createdAt, &updatedAt,
	)
	if err != nil {
		return nil, err
	}
	a.Disabled = disabled != 0
	a.CreatedAt = time.Unix(createdAt, 0)
	a.UpdatedAt = time.Unix(updatedAt, 0)
	if err := json.Unmarshal([]byte(toolsStr), &a.Tools); err != nil {
		a.Tools = []string{}
	}
	return &a, nil
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
