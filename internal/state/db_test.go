package state

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	internal "github.com/Problem99-io/kodeblue/internal"
)

func newTestDB(t *testing.T) *DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := NewDB(dbPath)
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	if err := db.Migrate(); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestNewDB(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := NewDB(dbPath)
	if err != nil {
		t.Fatalf("NewDB failed: %v", err)
	}
	defer db.Close()
}

func TestNewDBUsesMemoryTempStore(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := NewDB(dbPath)
	if err != nil {
		t.Fatalf("NewDB failed: %v", err)
	}
	defer db.Close()

	var tempStore int
	if err := db.conn.QueryRow(`PRAGMA temp_store`).Scan(&tempStore); err != nil {
		t.Fatalf("query temp_store: %v", err)
	}
	if tempStore != 2 {
		t.Fatalf("temp_store = %d, want 2 (memory)", tempStore)
	}
}

func TestMigrate(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := NewDB(dbPath)
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatalf("Migrate failed: %v", err)
	}
	// Running migrate again should be idempotent (IF NOT EXISTS)
	if err := db.Migrate(); err != nil {
		t.Fatalf("Migrate idempotent failed: %v", err)
	}
}

func TestEventsPreserveNanosecondTimestamps(t *testing.T) {
	db := newTestDB(t)
	repo := NewEventRepo(db)
	want := time.Date(2026, 8, 15, 12, 30, 1, 987654321, time.UTC)
	if err := repo.Append(&internal.Event{
		Type:      internal.EventToolRequested,
		Timestamp: want,
		SessionID: "session-ns",
		RunID:     "run-ns",
		Payload:   json.RawMessage(`{}`),
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	events, err := repo.GetByRun("run-ns")
	if err != nil {
		t.Fatalf("GetByRun: %v", err)
	}
	if len(events) != 1 || !events[0].Timestamp.Equal(want) {
		t.Fatalf("timestamp = %#v, want %s", events, want.Format(time.RFC3339Nano))
	}
}

func TestAddColumnIgnoresOnlyDuplicateColumn(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	// The column already exists after Migrate: tolerated.
	if err := db.addColumn(`ALTER TABLE sessions ADD COLUMN cwd TEXT NOT NULL DEFAULT ''`); err != nil {
		t.Fatalf("duplicate column must be ignored, got %v", err)
	}
	// Any other failure must surface.
	if err := db.addColumn(`ALTER TABLE no_such_table ADD COLUMN x TEXT`); err == nil {
		t.Fatal("ALTER on a missing table must return an error")
	}
}

func TestMigrateLegacyAgentDefinitionsSchema(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "legacy.db")

	legacyConn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open legacy db: %v", err)
	}
	defer legacyConn.Close()

	_, err = legacyConn.Exec(`
		CREATE TABLE agent_definitions (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL UNIQUE,
			instructions TEXT NOT NULL DEFAULT '',
			tools TEXT NOT NULL DEFAULT '[]',
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)
	`)
	if err != nil {
		t.Fatalf("create legacy schema: %v", err)
	}
	if _, err := legacyConn.Exec(`INSERT INTO agent_definitions (id, name, instructions, tools, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
		"legacy-agent", "legacy agent", "legacy instructions", "[]", time.Now().Unix(), time.Now().Unix()); err != nil {
		t.Fatalf("insert legacy agent: %v", err)
	}

	db, err := NewDB(dbPath)
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()

	if err := db.Migrate(); err != nil {
		t.Fatalf("Migrate legacy schema: %v", err)
	}
	// The agent tables moved to their own database, so their column upgrades
	// moved with them — a legacy file still has to come through it intact,
	// since that is what the shared-database import reads from.
	if err := db.MigrateAgents(); err != nil {
		t.Fatalf("MigrateAgents legacy schema: %v", err)
	}

	row := db.conn.QueryRow(`SELECT disabled, description, provider, model, max_iterations, max_output_tokens, reasoning_effort FROM agent_definitions LIMIT 1`)
	var disabled int
	var description string
	var provider string
	var model string
	var maxIterations int
	var maxOutputTokens int
	var reasoningEffort string
	if err := row.Scan(&disabled, &description, &provider, &model, &maxIterations, &maxOutputTokens, &reasoningEffort); err != nil && err != sql.ErrNoRows {
		t.Fatalf("scan migrated legacy columns: %v", err)
	}
	if maxOutputTokens != 0 {
		t.Fatalf("legacy max_output_tokens = %d, want 0", maxOutputTokens)
	}
	legacy, err := NewAgentRepo(db).Get("legacy-agent")
	if err != nil || legacy == nil || legacy.MaxOutputTokens != 0 {
		t.Fatalf("migrated legacy agent = %#v, err=%v; want max_output_tokens=0", legacy, err)
	}
}

func TestAgentRepoPersistsMaxOutputTokens(t *testing.T) {
	db := newTestDB(t)
	if err := db.MigrateAgents(); err != nil {
		t.Fatalf("MigrateAgents: %v", err)
	}
	repo := NewAgentRepo(db)
	now := time.Now()
	want := &internal.AgentDefinition{
		ID:              internal.NewAgentDefinitionID(),
		Name:            "output-limit-agent",
		Tools:           []string{},
		MaxOutputTokens: 16384,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	if err := repo.Create(want); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := repo.Get(want.ID)
	if err != nil || got == nil {
		t.Fatalf("Get: got=%#v err=%v", got, err)
	}
	if got.MaxOutputTokens != want.MaxOutputTokens {
		t.Fatalf("MaxOutputTokens = %d, want %d", got.MaxOutputTokens, want.MaxOutputTokens)
	}
	got.MaxOutputTokens = 8192
	if err := repo.Update(got); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, err = repo.Get(want.ID)
	if err != nil || got == nil || got.MaxOutputTokens != 8192 {
		t.Fatalf("updated MaxOutputTokens: got=%#v err=%v", got, err)
	}
}

func TestSessionCRUD(t *testing.T) {
	db := newTestDB(t)
	repo := NewSessionRepo(db)
	now := time.Now().Truncate(time.Second)

	s := &internal.Session{
		ID:           internal.NewSessionID(),
		Status:       internal.SessionActive,
		Provider:     "anthropic",
		Model:        "claude-sonnet-4-6",
		Instructions: []string{"be helpful"},
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	// Create
	if err := repo.Create(s); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Get
	got, err := repo.Get(s.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil {
		t.Fatal("Get returned nil")
	}
	if got.ID != s.ID {
		t.Errorf("ID = %q, want %q", got.ID, s.ID)
	}
	if got.Provider != "anthropic" {
		t.Errorf("Provider = %q, want %q", got.Provider, "anthropic")
	}
	if len(got.Instructions) != 1 || got.Instructions[0] != "be helpful" {
		t.Errorf("Instructions = %v, want [be helpful]", got.Instructions)
	}

	// List
	sessions, err := repo.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("List got %d sessions, want 1", len(sessions))
	}

	// Update
	s.Status = internal.SessionCompleted
	if err := repo.Update(s); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, _ = repo.Get(s.ID)
	if got.Status != internal.SessionCompleted {
		t.Errorf("Status after update = %q, want %q", got.Status, internal.SessionCompleted)
	}

	// Delete
	if err := repo.Delete(s.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	got, _ = repo.Get(s.ID)
	if got != nil {
		t.Error("session still exists after delete")
	}
}

func TestRunCRUD(t *testing.T) {
	db := newTestDB(t)
	sessRepo := NewSessionRepo(db)
	runRepo := NewRunRepo(db)
	now := time.Now().Truncate(time.Second)

	sess := &internal.Session{
		ID:        internal.NewSessionID(),
		Status:    internal.SessionActive,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := sessRepo.Create(sess); err != nil {
		t.Fatalf("create session: %v", err)
	}

	run := &internal.Run{
		ID:        internal.NewRunID(),
		SessionID: sess.ID,
		Status:    internal.RunRunning,
		CreatedAt: now,
	}

	// Create
	if err := runRepo.Create(run); err != nil {
		t.Fatalf("Create run: %v", err)
	}

	// Get
	got, err := runRepo.Get(run.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil {
		t.Fatal("Get returned nil")
	}
	if got.Status != internal.RunRunning {
		t.Errorf("Status = %q, want %q", got.Status, internal.RunRunning)
	}

	// Update
	completedAt := now.Add(time.Minute)
	run.Status = internal.RunCompleted
	run.CompletedAt = &completedAt
	run.ToolCalls = 5
	run.TokensUsed = 1000
	if err := runRepo.Update(run); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, _ = runRepo.Get(run.ID)
	if got.Status != internal.RunCompleted {
		t.Errorf("Status after update = %q, want %q", got.Status, internal.RunCompleted)
	}
	if got.ToolCalls != 5 {
		t.Errorf("ToolCalls = %d, want 5", got.ToolCalls)
	}

	// GetBySession
	runs, err := runRepo.GetBySession(sess.ID)
	if err != nil {
		t.Fatalf("GetBySession: %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("GetBySession got %d runs, want 1", len(runs))
	}
}

func TestEventAppendAndRetrieval(t *testing.T) {
	db := newTestDB(t)
	sessRepo := NewSessionRepo(db)
	eventRepo := NewEventRepo(db)
	now := time.Now().Truncate(time.Second)

	sess := &internal.Session{
		ID:        internal.NewSessionID(),
		Status:    internal.SessionActive,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := sessRepo.Create(sess); err != nil {
		t.Fatalf("create session: %v", err)
	}

	runID := internal.NewRunID()
	// Append 3 events
	for i := 0; i < 3; i++ {
		e := &internal.Event{
			Type:      internal.EventModelToken,
			Timestamp: now,
			SessionID: sess.ID,
			RunID:     runID,
			Payload:   json.RawMessage(`{"content":"token"}`),
		}
		if err := eventRepo.Append(e); err != nil {
			t.Fatalf("Append event %d: %v", i, err)
		}
	}

	// Retrieve all
	events, err := eventRepo.GetBySession(sess.ID, 0, 100)
	if err != nil {
		t.Fatalf("GetBySession: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("got %d events, want 3", len(events))
	}

	// Verify auto-incrementing seq numbers
	for i, e := range events {
		expectedSeq := int64(i + 1)
		if e.Seq != expectedSeq {
			t.Errorf("event %d seq = %d, want %d", i, e.Seq, expectedSeq)
		}
	}

	// GetBySession with afterSeq filter
	events, err = eventRepo.GetBySession(sess.ID, 2, 100)
	if err != nil {
		t.Fatalf("GetBySession afterSeq: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("afterSeq got %d events, want 1", len(events))
	}
	if events[0].Seq != 3 {
		t.Errorf("afterSeq event seq = %d, want 3", events[0].Seq)
	}

	// GetByRun
	events, err = eventRepo.GetByRun(runID)
	if err != nil {
		t.Fatalf("GetByRun: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("GetByRun got %d events, want 3", len(events))
	}
}

func TestMessageRepoGetBySessionPreservesInsertOrderWithinSameSecond(t *testing.T) {
	db := newTestDB(t)
	sessionRepo := NewSessionRepo(db)
	messageRepo := NewMessageRepo(db)
	now := time.Now().Truncate(time.Second)

	sess := &internal.Session{
		ID:        internal.NewSessionID(),
		Status:    internal.SessionActive,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := sessionRepo.Create(sess); err != nil {
		t.Fatalf("create session: %v", err)
	}

	runID := internal.NewRunID()
	messages := []*internal.Message{
		{ID: internal.NewMessageID(), Role: "assistant", Content: "tool call", ReasoningContent: "inspect task graph", CreatedAt: now},
		{ID: internal.NewMessageID(), Role: "user", Content: "tool result wrapper", CreatedAt: now},
		{ID: internal.NewMessageID(), Role: "assistant", Content: "final answer", CreatedAt: now},
	}
	for _, message := range messages {
		if err := messageRepo.Create(sess.ID, runID, message); err != nil {
			t.Fatalf("create message: %v", err)
		}
	}

	got, err := messageRepo.GetBySession(sess.ID)
	if err != nil {
		t.Fatalf("get by session: %v", err)
	}
	if len(got) != len(messages) {
		t.Fatalf("got %d messages, want %d", len(got), len(messages))
	}
	for i := range messages {
		if got[i].ID != messages[i].ID {
			t.Fatalf("message order mismatch at %d: got %s want %s", i, got[i].ID, messages[i].ID)
		}
	}
	if got[0].ReasoningContent != messages[0].ReasoningContent {
		t.Fatalf("reasoning_content mismatch: got %q want %q", got[0].ReasoningContent, messages[0].ReasoningContent)
	}
}

func TestMessageRepoCompactMessagesPersistsCompactedHistory(t *testing.T) {
	db := newTestDB(t)
	sessionRepo := NewSessionRepo(db)
	messageRepo := NewMessageRepo(db)
	now := time.Now().Truncate(time.Second)

	sess := &internal.Session{
		ID:        internal.NewSessionID(),
		Status:    internal.SessionActive,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := sessionRepo.Create(sess); err != nil {
		t.Fatalf("create session: %v", err)
	}

	runID := internal.NewRunID()
	messages := []*internal.Message{
		{ID: internal.NewMessageID(), Role: "user", Content: "first", CreatedAt: now},
		{ID: internal.NewMessageID(), Role: "assistant", Content: "second", CreatedAt: now.Add(time.Second)},
		{ID: internal.NewMessageID(), Role: "user", Content: "third", CreatedAt: now.Add(2 * time.Second)},
		{ID: internal.NewMessageID(), Role: "assistant", Content: "fourth", CreatedAt: now.Add(3 * time.Second)},
	}
	for _, message := range messages {
		if err := messageRepo.Create(sess.ID, runID, message); err != nil {
			t.Fatalf("create message: %v", err)
		}
	}

	// The compactor stamps its summary now, which is later than the raw tail
	// it precedes: reload order must follow the active set, not timestamps.
	summary := internal.Message{
		ID:        internal.NewMessageID(),
		Role:      "user",
		Content:   "[Compacted context]\nSummary: carried forward",
		CreatedAt: now.Add(4 * time.Second),
	}
	compacted := []internal.Message{summary, *messages[2], *messages[3]}
	if err := messageRepo.CompactMessages(sess.ID, internal.NewRunID(), compacted); err != nil {
		t.Fatalf("compact messages: %v", err)
	}

	active, err := messageRepo.GetBySession(sess.ID)
	if err != nil {
		t.Fatalf("get active messages: %v", err)
	}
	if len(active) != len(compacted) {
		t.Fatalf("active messages got %d, want %d", len(active), len(compacted))
	}
	for i, want := range []string{summary.ID, messages[2].ID, messages[3].ID} {
		if active[i].ID != want {
			t.Fatalf("active message %d got %s (%q), want %s", i, active[i].ID, active[i].Content, want)
		}
	}

	// A later turn appends after the tail.
	later := &internal.Message{ID: internal.NewMessageID(), Role: "user", Content: "fifth", CreatedAt: now.Add(5 * time.Second)}
	if err := messageRepo.Create(sess.ID, runID, later); err != nil {
		t.Fatal(err)
	}
	active, err = messageRepo.GetBySession(sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := contents(active); got != "[Compacted context]\nSummary: carried forward|third|fourth|fifth" {
		t.Fatalf("active order after append = %q", got)
	}

	all, err := messageRepo.GetAllBySession(sess.ID)
	if err != nil {
		t.Fatalf("get all messages: %v", err)
	}
	// Full history shows the summary where it took effect: after the
	// messages it replaced, before the kept tail.
	if got := contents(all); got != "first|second|[Compacted context]\nSummary: carried forward|third|fourth|fifth" {
		t.Fatalf("full history order = %q", got)
	}
}

func createTestSession(t *testing.T, db *DB) *internal.Session {
	t.Helper()
	now := time.Now()
	sess := &internal.Session{ID: internal.NewSessionID(), Status: internal.SessionActive, CreatedAt: now, UpdatedAt: now}
	if err := NewSessionRepo(db).Create(sess); err != nil {
		t.Fatalf("create session: %v", err)
	}
	return sess
}

func contents(messages []internal.Message) string {
	parts := make([]string, len(messages))
	for i, m := range messages {
		parts[i] = m.Content
	}
	return strings.Join(parts, "|")
}

func TestMessageRepoRepeatedCompactionKeepsOrder(t *testing.T) {
	db := newTestDB(t)
	sess := createTestSession(t, db)
	repo := NewMessageRepo(db)
	now := time.Now()
	var history []internal.Message
	for i := 0; i < 6; i++ {
		m := internal.Message{ID: internal.NewMessageID(), Role: "user", Content: fmt.Sprintf("m%d", i), CreatedAt: now}
		if err := repo.Create(sess.ID, "", &m); err != nil {
			t.Fatal(err)
		}
		history = append(history, m)
	}
	s1 := internal.Message{ID: internal.NewMessageID(), Role: "user", Content: "S1", CreatedAt: now.Add(time.Hour)}
	if err := repo.CompactMessages(sess.ID, "r1", []internal.Message{s1, history[4], history[5]}); err != nil {
		t.Fatal(err)
	}
	// Two new turns in one save, then a second compaction that replaces S1.
	a := internal.Message{ID: internal.NewMessageID(), Role: "assistant", Content: "a", CreatedAt: now}
	b := internal.Message{ID: internal.NewMessageID(), Role: "user", Content: "b", CreatedAt: now}
	if err := repo.CompactMessages(sess.ID, "r2", []internal.Message{s1, history[4], history[5], a, b}); err != nil {
		t.Fatal(err)
	}
	s2 := internal.Message{ID: internal.NewMessageID(), Role: "user", Content: "S2", CreatedAt: now.Add(2 * time.Hour)}
	if err := repo.CompactMessages(sess.ID, "r3", []internal.Message{s2, a, b}); err != nil {
		t.Fatal(err)
	}
	active, err := repo.GetBySession(sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := contents(active); got != "S2|a|b" {
		t.Fatalf("active = %q", got)
	}
	all, err := repo.GetAllBySession(sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := contents(all); got != "m0|m1|m2|m3|S1|m4|m5|S2|a|b" {
		t.Fatalf("all = %q", got)
	}
}

func TestMessageRepoPersistsMalformedToolArguments(t *testing.T) {
	db := newTestDB(t)
	sess := createTestSession(t, db)
	repo := NewMessageRepo(db)
	truncated := `{"command":"journalctl -u ssh 2>`
	m := internal.Message{
		ID: internal.NewMessageID(), Role: "assistant", CreatedAt: time.Now(),
		ToolCalls: []internal.ToolCall{
			{ID: "c1", Name: "bash", Arguments: json.RawMessage(truncated)},
			{ID: "c2", Name: "stats", Arguments: nil},
			{ID: "c3", Name: "read", Arguments: json.RawMessage(`{"path":"/etc/passwd"}`)},
		},
		ToolResults: []internal.ToolResult{{ToolCallID: "c1", Content: "x", Metadata: map[string]any{"bad": make(chan int)}}},
	}
	// Both write paths: plain create and the transcript snapshot.
	if err := repo.CompactMessages(sess.ID, "run", []internal.Message{m}); err != nil {
		t.Fatalf("compact with malformed tool arguments: %v", err)
	}
	m2 := m
	m2.ID = internal.NewMessageID()
	if err := repo.Create(sess.ID, "run", &m2); err != nil {
		t.Fatalf("create with malformed tool arguments: %v", err)
	}
	got, err := repo.GetBySession(sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || len(got[0].ToolCalls) != 3 {
		t.Fatalf("reloaded %+v", got)
	}
	var kept string
	if err := json.Unmarshal(got[0].ToolCalls[0].Arguments, &kept); err != nil || kept != truncated {
		t.Fatalf("malformed arguments not kept verbatim as a JSON string: %s (%v)", got[0].ToolCalls[0].Arguments, err)
	}
	if string(got[0].ToolCalls[1].Arguments) != "{}" || string(got[0].ToolCalls[2].Arguments) != `{"path":"/etc/passwd"}` {
		t.Fatalf("arguments = %s / %s", got[0].ToolCalls[1].Arguments, got[0].ToolCalls[2].Arguments)
	}
	if len(got[0].ToolResults) != 1 || got[0].ToolResults[0].Content != "x" {
		t.Fatalf("tool results = %+v", got[0].ToolResults)
	}
	// The caller's message is not modified.
	if string(m.ToolCalls[0].Arguments) != truncated {
		t.Fatalf("caller's arguments mutated: %s", m.ToolCalls[0].Arguments)
	}
}

func TestMessageRepoCompactSnapshotKeepsMessagesAddedMeanwhile(t *testing.T) {
	db := newTestDB(t)
	sess := createTestSession(t, db)
	repo := NewMessageRepo(db)
	now := time.Now()
	var history []internal.Message
	for i := 0; i < 4; i++ {
		m := internal.Message{ID: internal.NewMessageID(), Role: "user", Content: fmt.Sprintf("m%d", i), CreatedAt: now}
		if err := repo.Create(sess.ID, "", &m); err != nil {
			t.Fatal(err)
		}
		history = append(history, m)
	}
	snapshot := []string{history[0].ID, history[1].ID, history[2].ID, history[3].ID}

	// A new message arrives while the summary is being written.
	arrived := internal.Message{ID: internal.NewMessageID(), Role: "user", Content: "new question", CreatedAt: now}
	if err := repo.Create(sess.ID, "run-2", &arrived); err != nil {
		t.Fatal(err)
	}

	summary := internal.Message{ID: internal.NewMessageID(), Role: "user", Content: "S", CreatedAt: now.Add(time.Minute)}
	if err := repo.CompactSnapshot(sess.ID, "compact-run", snapshot, []internal.Message{summary, history[3]}); err != nil {
		t.Fatal(err)
	}
	active, err := repo.GetBySession(sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := contents(active); got != "S|m3|new question" {
		t.Fatalf("active = %q", got)
	}
}

func TestMigrateBackfillsPositionsAndRepairsSummaryOrder(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "legacy.db")
	db, err := NewDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// A database written before messages.position existed, holding the old
	// bug: an active summary stamped after the raw tail it precedes.
	if _, err := db.Exec(`CREATE TABLE sessions (id TEXT PRIMARY KEY, status TEXT NOT NULL DEFAULT 'active', provider TEXT NOT NULL DEFAULT '', model TEXT NOT NULL DEFAULT '', instructions TEXT NOT NULL DEFAULT '[]', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
CREATE TABLE messages (id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES sessions(id), run_id TEXT NOT NULL DEFAULT '', role TEXT NOT NULL, content TEXT NOT NULL DEFAULT '', tool_calls TEXT NOT NULL DEFAULT '[]', tool_results TEXT NOT NULL DEFAULT '[]', compacted INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL);
INSERT INTO sessions (id, created_at, updated_at) VALUES ('s1', 1, 1);
INSERT INTO messages (id, session_id, role, content, compacted, created_at) VALUES
 ('a', 's1', 'user', 'old-1', 1, 100),
 ('b', 's1', 'assistant', 'old-2', 1, 101),
 ('c', 's1', 'user', 'tail-1', 0, 102),
 ('d', 's1', 'assistant', 'tail-2', 0, 103),
 ('e', 's1', 'user', '[Compacted context — 2 messages summarized]' || char(10) || 'sum', 0, 200),
 ('f', 's1', 'user', 'after', 0, 300);`); err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(); err != nil {
		t.Fatalf("migrate legacy db: %v", err)
	}
	if err := db.Migrate(); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	repo := NewMessageRepo(db)
	active, err := repo.GetBySession("s1")
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, m := range active {
		ids = append(ids, m.ID)
	}
	if got := strings.Join(ids, ","); got != "e,c,d,f" {
		t.Fatalf("active order after migration = %s", got)
	}
	all, err := repo.GetAllBySession("s1")
	if err != nil {
		t.Fatal(err)
	}
	ids = ids[:0]
	for _, m := range all {
		ids = append(ids, m.ID)
	}
	if got := strings.Join(ids, ","); got != "a,b,e,c,d,f" {
		t.Fatalf("full order after migration = %s", got)
	}
	// New writes append after the backfilled rows.
	if err := repo.Create("s1", "", &internal.Message{ID: "g", Role: "user", Content: "new", CreatedAt: time.Unix(1, 0)}); err != nil {
		t.Fatal(err)
	}
	active, _ = repo.GetBySession("s1")
	if active[len(active)-1].ID != "g" {
		t.Fatalf("new message not appended: %+v", active)
	}
}

func TestMessageRepoClearReasoningBySessionPreservesConversation(t *testing.T) {
	db := newTestDB(t)
	sessionRepo := NewSessionRepo(db)
	messageRepo := NewMessageRepo(db)
	now := time.Now().Truncate(time.Second)

	target := &internal.Session{ID: internal.NewSessionID(), Status: internal.SessionActive, CreatedAt: now, UpdatedAt: now}
	other := &internal.Session{ID: internal.NewSessionID(), Status: internal.SessionActive, CreatedAt: now, UpdatedAt: now}
	for _, session := range []*internal.Session{target, other} {
		if err := sessionRepo.Create(session); err != nil {
			t.Fatalf("create session: %v", err)
		}
	}
	newMessage := func(content string) *internal.Message {
		return &internal.Message{
			ID:               internal.NewMessageID(),
			Role:             "assistant",
			Content:          content,
			ReasoningContent: "private thought",
			ReasoningDetails: json.RawMessage(`[{"type":"reasoning.encrypted","data":"ciphertext"}]`),
			ToolCalls:        []internal.ToolCall{{ID: "call-1"}},
			CreatedAt:        now,
		}
	}
	if err := messageRepo.Create(target.ID, internal.NewRunID(), newMessage("target answer")); err != nil {
		t.Fatal(err)
	}
	if err := messageRepo.Create(other.ID, internal.NewRunID(), newMessage("other answer")); err != nil {
		t.Fatal(err)
	}

	if err := messageRepo.ClearReasoningBySession(target.ID); err != nil {
		t.Fatalf("clear reasoning: %v", err)
	}
	targetMessages, err := messageRepo.GetBySession(target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(targetMessages) != 1 || targetMessages[0].ReasoningContent != "" || len(targetMessages[0].ReasoningDetails) != 0 {
		t.Fatalf("target reasoning was not cleared: %+v", targetMessages)
	}
	if targetMessages[0].Content != "target answer" || len(targetMessages[0].ToolCalls) != 1 {
		t.Fatalf("target portable history changed: %+v", targetMessages[0])
	}
	otherMessages, err := messageRepo.GetBySession(other.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(otherMessages) != 1 || otherMessages[0].ReasoningContent == "" || len(otherMessages[0].ReasoningDetails) == 0 {
		t.Fatalf("other session was modified: %+v", otherMessages)
	}
}

func TestMessageRepoDropsAttachmentPayloadsOnPersist(t *testing.T) {
	db := newTestDB(t)
	sessionRepo := NewSessionRepo(db)
	messageRepo := NewMessageRepo(db)
	now := time.Now().Truncate(time.Second)

	sess := &internal.Session{
		ID:        internal.NewSessionID(),
		Status:    internal.SessionActive,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := sessionRepo.Create(sess); err != nil {
		t.Fatalf("create session: %v", err)
	}

	message := &internal.Message{
		ID:      internal.NewMessageID(),
		Role:    "user",
		Content: "what is wrong with this screen?",
		Attachments: []internal.Attachment{{
			MediaType: "image/png",
			FileName:  "shot.png",
			Data:      "aW1hZ2UtYnl0ZXM=",
		}},
		CreatedAt: now,
	}
	if err := messageRepo.Create(sess.ID, internal.NewRunID(), message); err != nil {
		t.Fatalf("create message: %v", err)
	}

	// The in-memory message must keep its payload — the run that carried it
	// still needs to send the image to the provider.
	if message.Attachments[0].Data == "" {
		t.Fatalf("Create mutated the caller's attachment payload")
	}

	got, err := messageRepo.GetBySession(sess.ID)
	if err != nil {
		t.Fatalf("get by session: %v", err)
	}
	if len(got) != 1 || len(got[0].Attachments) != 1 {
		t.Fatalf("got %d messages with attachments %v, want 1 message with 1 attachment", len(got), got)
	}
	stored := got[0].Attachments[0]
	if stored.Data != "" {
		t.Errorf("attachment payload was persisted: %q", stored.Data)
	}
	if stored.FileName != "shot.png" || stored.MediaType != "image/png" {
		t.Errorf("attachment descriptor lost: %+v", stored)
	}
}

func TestIsBusyErr(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"no rows", sql.ErrNoRows, false},
		{"unrelated", errors.New("no such column: bogus"), false},
		{"locked", errors.New("database is locked (5) (SQLITE_BUSY)"), true},
		{"table locked", errors.New("database table is locked"), true},
		{"locked symbol", errors.New("SQLITE_LOCKED: table agent_definitions"), true},
	}
	for _, tc := range cases {
		if got := IsBusyErr(tc.err); got != tc.want {
			t.Errorf("%s: IsBusyErr(%v) = %v, want %v", tc.name, tc.err, got, tc.want)
		}
	}
}

// Two handles on one file stand in for two engine instances sharing the agents
// database. Every write must land: losing the cross-process write race is normal
// here, and used to surface as a 500 on saving agent settings.
func TestConcurrentWritersAcrossHandles(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "shared-agents.db")

	first, err := NewDB(dbPath)
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer first.Close()
	if err := first.MigrateAgents(); err != nil {
		t.Fatalf("MigrateAgents: %v", err)
	}

	second, err := NewDB(dbPath)
	if err != nil {
		t.Fatalf("NewDB (second handle): %v", err)
	}
	defer second.Close()

	const writesPerHandle = 40
	errCh := make(chan error, 2*writesPerHandle)
	var wg sync.WaitGroup

	for handleIndex, db := range []*DB{first, second} {
		wg.Add(1)
		go func(handleIndex int, db *DB) {
			defer wg.Done()
			repo := NewAgentRepo(db)
			for i := 0; i < writesPerHandle; i++ {
				name := fmt.Sprintf("handle-%d-agent-%d", handleIndex, i)
				agent := &internal.AgentDefinition{
					ID:        name,
					Name:      name,
					Tools:     []string{},
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}
				if err := repo.Create(agent); err != nil {
					errCh <- err
					return
				}
				agent.Model = "gpt-5.4-nano"
				if err := repo.Update(agent); err != nil {
					errCh <- err
					return
				}
			}
		}(handleIndex, db)
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("agent write lost the cross-handle race: %v", err)
	}

	agents, err := NewAgentRepo(first).List()
	if err != nil {
		t.Fatalf("list agents: %v", err)
	}
	if len(agents) != 2*writesPerHandle {
		t.Fatalf("agents database has %d rows, want %d", len(agents), 2*writesPerHandle)
	}
}
