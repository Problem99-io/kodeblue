package state

import (
	internal "github.com/Problem99-io/kodeblue/internal"
	"path/filepath"
	"testing"
	"time"
)

func TestPrivateMessageFlagSurvivesUpgradeAndReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.db")
	db, err := NewDB(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	session := &internal.Session{ID: "session", Status: internal.SessionActive, CreatedAt: now, UpdatedAt: now}
	if err := NewSessionRepo(db).Create(session); err != nil {
		t.Fatal(err)
	}
	repo := NewMessageRepo(db)
	if err := repo.Create("session", "run", &internal.Message{ID: "old", Role: "user", Content: "existing history", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`ALTER TABLE messages DROP COLUMN internal`); err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err := repo.Create("session", "run", &internal.Message{ID: "private", Role: "assistant", Content: "report summary", Internal: true, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = NewDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	messages, err := NewMessageRepo(db).GetAllBySession("session")
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 2 || messages[0].Internal || !messages[1].Internal {
		t.Fatalf("lost migration/history flags: %#v", messages)
	}
}
