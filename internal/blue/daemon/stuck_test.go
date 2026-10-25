package daemon

import (
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/config"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

func TestStuckSensorRaisedOncePerEpisode(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Server.StateDir = dir
	st, err := store.Open(filepath.Join(dir, "kb.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	d := New(cfg, st, slog.Default())
	stuck := func() int {
		n := 0
		for _, f := range st.FindingsByStatus("new", 100) {
			if f.Rule == "kodeblue.sensor_stuck" {
				n++
			}
		}
		return n
	}

	// A slow read is not a finding yet.
	d.reportStuckSensors(map[string]time.Time{"integrity": time.Now().Add(-time.Minute)})
	if n := stuck(); n != 0 {
		t.Fatalf("raised after a minute: %d findings", n)
	}

	episode := time.Now().Add(-stuckSensorAfter - time.Second)
	for i := 0; i < 3; i++ { // every sweep while it stays stuck
		d.reportStuckSensors(map[string]time.Time{"integrity": episode})
	}
	if n := stuck(); n != 1 {
		t.Fatalf("one stuck run gave %d findings, want 1", n)
	}

	// It recovered and got stuck again: a new finding.
	d.reportStuckSensors(map[string]time.Time{"integrity": episode.Add(time.Second)})
	if n := stuck(); n != 2 {
		t.Fatalf("second stuck run: %d findings, want 2", n)
	}
}
