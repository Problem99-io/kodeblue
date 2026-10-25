package agent

import (
	"context"
	"errors"
	internal "github.com/Problem99-io/kodeblue/internal"
	"github.com/Problem99-io/kodeblue/internal/state"
	"path/filepath"
	"testing"
	"time"
)

func TestContinuationPersistsHeldToolResultsBeforeQuestion(t *testing.T) {
	loop, _, cfg := buildToolLoopRun(t, &eventCollector{}, 1)
	cfg.MaxIterations = 1
	dbPath := filepath.Join(t.TempDir(), "checkpoint.db")
	db, err := state.NewDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err := state.NewSessionRepo(db).Create(&internal.Session{ID: cfg.SessionID, CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := state.NewRunRepo(db).Create(&internal.Run{ID: cfg.RunID, SessionID: cfg.SessionID, Status: internal.RunRunning, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	repo := state.NewMessageRepo(db)
	cfg.SaveCheckpoint = func(messages []internal.Message) error {
		return repo.CompactMessages(cfg.SessionID, cfg.RunID, messages)
	}
	asked := false
	loop.SetContinuationGate(func(context.Context, ContinuationRequest) (ContinuationDecision, error) {
		asked = true
		// A separate database connection represents the restarted process. The gate
		// must not be visible until the held result is durably available there.
		reopened, err := state.NewDB(dbPath)
		if err != nil {
			t.Fatal(err)
		}
		defer reopened.Close()
		saved, err := state.NewMessageRepo(reopened).GetBySession(cfg.SessionID)
		if err != nil {
			t.Fatal(err)
		}
		results := 0
		for _, m := range saved {
			results += len(m.ToolResults)
		}
		if results != 1 {
			t.Fatalf("persisted tool results=%d", results)
		}
		return ContinuationDecision{}, errors.New("simulated shutdown while waiting")
	})
	_, err = loop.Run(context.Background(), cfg, "work", nil)
	if err == nil || !asked {
		t.Fatalf("checkpoint not exercised: %v", err)
	}
}

func TestContinuationPersistenceFailureDoesNotExposeQuestion(t *testing.T) {
	loop, mp, cfg := buildToolLoopRun(t, &eventCollector{}, 1)
	cfg.MaxIterations = 1
	cfg.SaveCheckpoint = func([]internal.Message) error { return errors.New("disk full") }
	loop.SetContinuationGate(func(context.Context, ContinuationRequest) (ContinuationDecision, error) {
		t.Fatal("question exposed without durable transcript")
		return ContinuationDecision{}, nil
	})
	_, err := loop.Run(context.Background(), cfg, "work", nil)
	if err == nil || mp.callCount() != 1 {
		t.Fatalf("error=%v provider calls=%d", err, mp.callCount())
	}
}
