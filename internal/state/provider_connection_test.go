package state

import (
	"encoding/json"
	internal "github.com/Problem99-io/kodeblue/internal"
	"testing"
	"time"
)

func TestLatestProviderConnectionScopedAndRestored(t *testing.T) {
	db := newTestDB(t)
	now := time.Now()
	session := internal.SessionID("recovery-session")
	if err := NewSessionRepo(db).Create(&internal.Session{ID: session, Status: internal.SessionActive, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	repo := NewEventRepo(db)
	for _, entry := range []struct{ run, state string }{{"main", "waiting"}, {"child", "retrying"}, {"main", "recovered"}} {
		payload, _ := json.Marshal(map[string]any{"state": entry.state, "attempt": 1, "max_attempts": 10})
		if err := repo.Append(&internal.Event{SessionID: session, RunID: internal.RunID(entry.run), Type: "provider.connection", Payload: payload, Timestamp: now}); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := repo.LatestProviderConnection("main")
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err = json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	if value["state"] != "recovered" {
		t.Fatalf("snapshot=%s", raw)
	}
	raw, err = repo.LatestProviderConnection("missing")
	if err != nil || len(raw) != 0 {
		t.Fatalf("missing=%s err=%v", raw, err)
	}
}
