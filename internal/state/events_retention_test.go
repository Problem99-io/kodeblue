package state

import (
	"strings"
	"sync"
	"testing"
	"time"

	internal "github.com/Problem99-io/kodeblue/internal"
)

func countEvents(t *testing.T, db *DB, where string, args ...any) int {
	t.Helper()
	var n int
	if err := db.conn.QueryRow(`SELECT COUNT(*) FROM events WHERE `+where, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestEventAppendSeqIsIndexedAndUniqueAcrossRepos(t *testing.T) {
	db := newTestDB(t)
	// Two repos stand in for two processes: each has its own mutex.
	a, b := NewEventRepo(db), NewEventRepo(db)
	var wg sync.WaitGroup
	for _, repo := range []*EventRepo{a, b} {
		wg.Add(1)
		go func(repo *EventRepo) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				if err := repo.Append(&internal.Event{SessionID: "s", Type: "tool.output", Timestamp: time.Now()}); err != nil {
					t.Error(err)
					return
				}
			}
		}(repo)
	}
	wg.Wait()
	if dup := countEvents(t, db, `session_id = 's' AND seq IN (SELECT seq FROM events WHERE session_id = 's' GROUP BY seq HAVING COUNT(*) > 1)`); dup != 0 {
		t.Fatalf("%d events share a seq", dup)
	}
	var maxSeq int
	_ = db.conn.QueryRow(`SELECT MAX(seq) FROM events WHERE session_id = 's'`).Scan(&maxSeq)
	if maxSeq != 200 {
		t.Fatalf("max seq = %d, want 200", maxSeq)
	}

	rows, err := db.conn.Query(`EXPLAIN QUERY PLAN SELECT COALESCE(MAX(seq), 0) + 1 FROM events WHERE session_id = ?`, "s")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, detail)
	}
	if got := strings.Join(plan, "; "); !strings.Contains(got, "idx_events_session_seq") || strings.Contains(got, "SCAN events") {
		t.Fatalf("seq allocation is not an index lookup: %s", got)
	}
}

func TestEventSummaryIsBoundedAndSkipsDeltas(t *testing.T) {
	db := newTestDB(t)
	repo := NewEventRepo(db)
	// Older history: alternating deltas and tool outputs, then one stray
	// tool.streaming delta, then the newest SummaryEventLimit terminal events.
	if _, err := db.conn.Exec(`WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < ?)
		INSERT INTO events (session_id, run_id, seq, type, payload, meta, created_at)
		SELECT 's', '', i, CASE i % 2 WHEN 0 THEN 'model.token' ELSE 'tool.output' END, '{}', '{}', 0 FROM n`, SummaryEventLimit+50); err != nil {
		t.Fatal(err)
	}
	if err := repo.Append(&internal.Event{SessionID: "s", Type: internal.EventToolCallStreaming, Timestamp: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.conn.Exec(`WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < ?)
		INSERT INTO events (session_id, run_id, seq, type, payload, meta, created_at)
		SELECT 's', '', ? + i, 'run.completed', '{}', '{}', 0 FROM n`, SummaryEventLimit, SummaryEventLimit+51); err != nil {
		t.Fatal(err)
	}
	events, err := repo.GetBySessionSummary("s")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != SummaryEventLimit {
		t.Fatalf("summary returned %d events", len(events))
	}
	for i, e := range events {
		if e.Type != internal.EventRunCompleted {
			t.Fatalf("event %d is %s", i, e.Type)
		}
		if i > 0 && e.Seq <= events[i-1].Seq {
			t.Fatalf("summary not in seq order at %d", i)
		}
	}
}

func TestEventPruneRetention(t *testing.T) {
	db := newTestDB(t)
	repo := NewEventRepo(db)
	runs := NewRunRepo(db)
	sess := createTestSession(t, db)
	now := time.Now()
	done := now.Add(-time.Hour)
	finished := &internal.Run{ID: "finished", SessionID: sess.ID, Status: internal.RunCompleted, CreatedAt: done, CompletedAt: &done}
	recent := now.Add(-time.Minute)
	justFinished := &internal.Run{ID: "just-finished", SessionID: sess.ID, Status: internal.RunCompleted, CreatedAt: recent, CompletedAt: &recent}
	running := &internal.Run{ID: "running", SessionID: sess.ID, Status: internal.RunRunning, CreatedAt: now}
	for _, r := range []*internal.Run{finished, justFinished, running} {
		if err := runs.Create(r); err != nil {
			t.Fatal(err)
		}
	}
	appendN := func(run internal.RunID, typ string, n int) {
		for i := 0; i < n; i++ {
			if err := repo.Append(&internal.Event{SessionID: sess.ID, RunID: run, Type: typ, Timestamp: now}); err != nil {
				t.Fatal(err)
			}
		}
	}
	appendN("finished", internal.EventModelToken, 30)
	appendN("finished", internal.EventToolCallStreaming, 5)
	appendN("finished", internal.EventToolOutput, 40)
	appendN("finished", internal.EventRunCompleted, 1)
	appendN("just-finished", internal.EventModelToken, 7)
	appendN("just-finished", internal.EventRunCompleted, 1)
	appendN("running", internal.EventModelToken, 9)
	appendN("running", internal.EventToolOutput, 3)

	if _, err := repo.Prune(now, EventRetention{TransientGrace: 10 * time.Minute}); err != nil {
		t.Fatal(err)
	}
	if n := countEvents(t, db, `run_id = 'finished' AND type IN ('model.token', 'tool.streaming')`); n != 0 {
		t.Fatalf("finished run kept %d deltas", n)
	}
	if n := countEvents(t, db, `run_id = 'just-finished' AND type = 'model.token'`); n != 7 {
		t.Fatalf("run inside the grace window kept %d deltas, want 7", n)
	}
	if n := countEvents(t, db, `run_id = 'running' AND type = 'model.token'`); n != 9 {
		t.Fatalf("running run kept %d deltas, want 9", n)
	}
	if n := countEvents(t, db, `run_id = 'finished' AND type = 'tool.output'`); n != 40 {
		t.Fatalf("finished run kept %d tool outputs, want 40", n)
	}

	// Per-session cap: the finished run's old outputs go, its terminal event
	// and the running run's events stay.
	if _, err := repo.Prune(now, EventRetention{TransientGrace: 10 * time.Minute, MaxEventsPerSession: 15}); err != nil {
		t.Fatal(err)
	}
	if n := countEvents(t, db, `run_id = 'finished' AND type = 'run.completed'`); n != 1 {
		t.Fatalf("terminal event pruned")
	}
	if n := countEvents(t, db, `run_id = 'running'`); n != 12 {
		t.Fatalf("running run kept %d events, want 12", n)
	}
	if n := countEvents(t, db, `session_id = ?`, string(sess.ID)); n > 15+2 {
		t.Fatalf("session kept %d events after cap", n)
	}
	// seq keeps increasing after pruning.
	e := &internal.Event{SessionID: sess.ID, Type: "x", Timestamp: now}
	if err := repo.Append(e); err != nil {
		t.Fatal(err)
	}
	if want := int64(30 + 5 + 40 + 1 + 7 + 1 + 9 + 3 + 1); e.Seq != want {
		t.Fatalf("seq after prune = %d, want %d", e.Seq, want)
	}
}

func queryPlan(t *testing.T, db *DB, query string, args ...any) string {
	t.Helper()
	rows, err := db.conn.Query(`EXPLAIN QUERY PLAN `+query, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, detail)
	}
	return strings.Join(plan, "; ")
}

func TestEventPruneQueriesUseIndexes(t *testing.T) {
	db := newTestDB(t)
	if plan := queryPlan(t, db, `SELECT 1 FROM events WHERE events.run_id = ? AND type IN (`+transientEventTypes+`)`, "r"); !strings.Contains(plan, "idx_events_transient") {
		t.Fatalf("transient probe does not use the partial index: %s", plan)
	}
	if plan := queryPlan(t, db, `SELECT id FROM events WHERE run_id = ? AND type IN (`+transientEventTypes+`) AND seq < ? LIMIT ?`, "r", 1, 1); strings.Contains(plan, "SCAN events") {
		t.Fatalf("transient batch scans the table: %s", plan)
	}
	if plan := queryPlan(t, db, `SELECT id FROM events WHERE session_id = ? AND seq <= ? LIMIT ?`, "s", 1, 1); strings.Contains(plan, "SCAN events") {
		t.Fatalf("session batch scans the table: %s", plan)
	}
}

// A large backlog is deleted in short batches: event appends keep flowing on
// the same connection while it runs.
func TestEventPruneBatchesDoNotStallAppends(t *testing.T) {
	db := newTestDB(t)
	repo := NewEventRepo(db)
	sess := createTestSession(t, db)
	done := time.Now().Add(-time.Hour)
	if err := NewRunRepo(db).Create(&internal.Run{ID: "old", SessionID: sess.ID, Status: internal.RunCompleted, CreatedAt: done, CompletedAt: &done}); err != nil {
		t.Fatal(err)
	}
	const backlog = 20_000
	if _, err := db.conn.Exec(`WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < ?)
		INSERT INTO events (session_id, run_id, seq, type, payload, meta, created_at) SELECT ?, 'old', i, 'model.token', '{"content":"x"}', '{}', 0 FROM n`,
		backlog, string(sess.ID)); err != nil {
		t.Fatal(err)
	}
	if err := repo.Append(&internal.Event{SessionID: sess.ID, RunID: "old", Type: internal.EventRunCompleted, Timestamp: time.Now()}); err != nil {
		t.Fatal(err)
	}

	pruned := make(chan int64, 1)
	pruneStarted := time.Now()
	go func() {
		n, err := repo.Prune(time.Now(), EventRetention{TransientGrace: time.Minute, BatchSize: 1000, BatchPause: time.Millisecond})
		if err != nil {
			t.Error(err)
		}
		pruned <- n
	}()
	var worst time.Duration
	appends := 0
	for running := true; running; {
		select {
		case n := <-pruned:
			if n != backlog {
				t.Fatalf("pruned %d, want %d", n, backlog)
			}
			running = false
		default:
			started := time.Now()
			if err := repo.Append(&internal.Event{SessionID: sess.ID, RunID: "live", Type: internal.EventToolOutput, Timestamp: time.Now()}); err != nil {
				t.Fatal(err)
			}
			worst = max(worst, time.Since(started))
			appends++
		}
	}
	if appends < 10 {
		t.Fatalf("only %d appends completed while pruning", appends)
	}
	// One unbatched DELETE would make some append wait about as long as the
	// whole prune. Batches keep every wait to a small fraction of it, so the
	// bound scales with the machine: a loaded CI runner with the race detector
	// is several times slower than a laptop.
	took := time.Since(pruneStarted)
	if worst > took/5 && worst > 100*time.Millisecond {
		t.Fatalf("an append waited %v behind a %v prune", worst, took)
	}
	t.Logf("pruned %d rows in %v; %d concurrent appends, slowest %v", backlog, took, appends, worst)
}
