package state

// MigrateAgents creates the agent tables. Every statement is conditional, so
// it is safe to run on every start.
func (db *DB) MigrateAgents() error {
	if _, err := db.Exec(agentSchemaSQL); err != nil {
		return err
	}
	// Columns that may be missing in databases created by older builds.
	for _, stmt := range []string{
		`ALTER TABLE agent_definitions ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE agent_definitions ADD COLUMN description TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE agent_definitions ADD COLUMN provider TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE agent_definitions ADD COLUMN model TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE agent_definitions ADD COLUMN max_iterations INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE agent_definitions ADD COLUMN max_output_tokens INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE agent_definitions ADD COLUMN reasoning_effort TEXT NOT NULL DEFAULT ''`,
	} {
		if err := db.addColumn(stmt); err != nil {
			return err
		}
	}
	return nil
}

const agentSchemaSQL = `
CREATE TABLE IF NOT EXISTS agent_definitions (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    disabled INTEGER NOT NULL DEFAULT 0,
    description TEXT NOT NULL DEFAULT '',
    instructions TEXT NOT NULL DEFAULT '',
    tools TEXT NOT NULL DEFAULT '[]',
    provider TEXT NOT NULL DEFAULT '',
    model TEXT NOT NULL DEFAULT '',
	reasoning_effort TEXT NOT NULL DEFAULT '',
    max_iterations INTEGER NOT NULL DEFAULT 0,
	max_output_tokens INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_agent_definitions_name ON agent_definitions(name);
`
