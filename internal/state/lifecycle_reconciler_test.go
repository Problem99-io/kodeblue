package state

import (
	internal "github.com/Problem99-io/kodeblue/internal"
	"sync"
	"testing"
	"time"
)

func TestReconcileSessionBlockersEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, status, event string
		repair              bool
	}{
		{"aborted", "aborted", "", true}, {"completed", "completed", "", true}, {"failed", "failed", "", true},
		{"interrupted", "interrupted", "", false}, {"running", "running", "", false}, {"paused", "paused", "", false},
		{"unknown owner", "", "", false}, {"live event-only run", "", "run.started", false},
		{"completed event-only run", "", "run.completed", true}, {"failed event-only run", "", "run.failed", true},
		{"aborted event-only run", "", "run.aborted", true}, {"interrupted event-only run", "", "run.interrupted", false},
		{"model EOF is not completion", "", "model.completed", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := newTestDB(t)
			session := internal.SessionID("session")
			now := time.Now()
			if err := NewSessionRepo(db).Create(&internal.Session{ID: session, Status: internal.SessionActive, CreatedAt: now, UpdatedAt: now}); err != nil {
				t.Fatal(err)
			}
			if tc.status != "" {
				if err := NewRunRepo(db).Create(&internal.Run{ID: "owner", SessionID: session, Status: internal.RunStatus(tc.status), CreatedAt: now}); err != nil {
					t.Fatal(err)
				}
			}
			if tc.event != "" {
				if err := NewEventRepo(db).Append(&internal.Event{SessionID: session, RunID: "owner", Type: tc.event, Timestamp: now}); err != nil {
					t.Fatal(err)
				}
			}
			questions := NewPendingQuestionRepo(db)
			// Deliberately old. Age never decides whether a request is obsolete.
			for _, id := range []string{"pending", "resuming"} {
				if err := questions.Create(internal.PendingQuestion{QuestionID: id, SessionID: session, RunID: "owner", CreatedAt: now.Add(-60 * 24 * time.Hour)}); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := db.Exec(`UPDATE pending_questions SET status='resuming', answer='{"text":"real user answer"}' WHERE id='resuming'`); err != nil {
				t.Fatal(err)
			}
			repairs, err := db.ReconcileSessionBlockers(session)
			if err != nil {
				t.Fatal(err)
			}
			want := 0
			if tc.repair {
				want = 2
			}
			if len(repairs) != want {
				t.Fatalf("repairs=%+v want %d", repairs, want)
			}
			_, status, _ := questions.Get("pending")
			if tc.repair && status != "ignored" || !tc.repair && status != "pending" {
				t.Fatalf("question status=%s", status)
			}
			again, err := db.ReconcileSessionBlockers(session)
			if err != nil || len(again) != want {
				t.Fatalf("idempotent journal=%+v err=%v", again, err)
			}
			var answer string
			if err := db.conn.QueryRow(`SELECT answer FROM pending_questions WHERE id='resuming'`).Scan(&answer); err != nil {
				t.Fatal(err)
			}
			if answer != `{"text":"real user answer"}` {
				t.Fatal("overwrote recorded answer")
			}
		})
	}
}

func TestReconcileIsolationDecisionsAndConcurrentRetry(t *testing.T) {
	db := newTestDB(t)
	now := time.Now()
	for _, id := range []internal.SessionID{"a", "b"} {
		if err := NewSessionRepo(db).Create(&internal.Session{ID: id, Status: internal.SessionActive, CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	runs := NewRunRepo(db)
	if err := runs.Create(&internal.Run{ID: "dead", SessionID: "a", Status: internal.RunAborted, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	questions := NewPendingQuestionRepo(db)
	for _, item := range []struct {
		id      string
		session internal.SessionID
	}{
		{"stale", "a"}, {"cross-session", "b"}, {"decided", "a"},
	} {
		if err := questions.Create(internal.PendingQuestion{QuestionID: item.id, SessionID: item.session, RunID: "dead", CreatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	if err := questions.Resolve("decided", PendingQuestionStatusAnswered, internal.QuestionAnswer{}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := db.ReconcileSessionBlockers("a"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if _, err := db.ReconcileSessionBlockers("b"); err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]string{"cross-session": PendingQuestionStatusPending, "decided": PendingQuestionStatusAnswered} {
		if _, status, _ := questions.Get(id); status != want {
			t.Fatalf("changed unrelated question %s: status=%s want %s", id, status, want)
		}
	}
	if err := questions.Resolve("stale", PendingQuestionStatusAnswered, internal.QuestionAnswer{}); err != nil {
		t.Fatal(err)
	}
	if _, status, _ := questions.Get("stale"); status != PendingQuestionStatusIgnored {
		t.Fatalf("late answer overwrote repair: status=%s", status)
	}
	repairs, _ := db.ReconcileSessionBlockers("a")
	if len(repairs) != 1 {
		t.Fatalf("duplicate journal: %+v", repairs)
	}
}

func TestReconcileEventOnlyRunUsesLatestLifecycleNotSessionRun(t *testing.T) {
	db := newTestDB(t)
	now := time.Now()
	if err := NewSessionRepo(db).Create(&internal.Session{ID: "s", Status: internal.SessionActive, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := NewRunRepo(db).Create(&internal.Run{ID: "parent", SessionID: "s", Status: internal.RunCompleted, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	for _, event := range []string{"run.completed", "run.started"} {
		if err := NewEventRepo(db).Append(&internal.Event{SessionID: "s", RunID: "child", Type: event, Timestamp: now}); err != nil {
			t.Fatal(err)
		}
	}
	if err := NewPendingQuestionRepo(db).Create(internal.PendingQuestion{QuestionID: "q", SessionID: "s", RunID: "child", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	repairs, err := db.ReconcileSessionBlockers("s")
	if err != nil || len(repairs) != 0 {
		t.Fatalf("repaired live event-only run: %+v %v", repairs, err)
	}
}

func TestReconcileRollsBackAllRepairsOnStorageFailure(t *testing.T) {
	db := newTestDB(t)
	now := time.Now()
	if err := NewSessionRepo(db).Create(&internal.Session{ID: "s", Status: internal.SessionActive, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := NewRunRepo(db).Create(&internal.Run{ID: "r", SessionID: "s", Status: internal.RunAborted, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	questions := NewPendingQuestionRepo(db)
	for _, id := range []string{"q1", "q2"} {
		if err := questions.Create(internal.PendingQuestion{QuestionID: id, SessionID: "s", RunID: "r", CreatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	// Fail only the second repair so the first one must be rolled back.
	if _, err := db.Exec(`CREATE TRIGGER simulate_disk_failure BEFORE UPDATE ON pending_questions WHEN OLD.id = 'q2' BEGIN SELECT RAISE(ABORT, 'storage unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ReconcileSessionBlockers("s"); err == nil {
		t.Fatal("ignored storage error")
	}
	for _, id := range []string{"q1", "q2"} {
		if _, status, err := questions.Get(id); err != nil || status != PendingQuestionStatusPending {
			t.Fatalf("partial repair of %s: status=%s err=%v", id, status, err)
		}
	}
	var count int
	if err := db.conn.QueryRow(`SELECT COUNT(*) FROM lifecycle_repairs`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("partial journal: %d %v", count, err)
	}
}
