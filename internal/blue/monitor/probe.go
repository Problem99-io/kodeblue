package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/sensors"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

// Probe runs spec once on a scratch store under stateDir: the run records no
// finding, moves no live log cursor and contains nothing. It reports whether
// the check passes now and what it saw.
func Probe(ctx context.Context, stateDir string, env *sensors.Env, spec Spec) (bool, string, error) {
	dbPath := filepath.Join(stateDir, "tmp", fmt.Sprintf("probe-%d.db", time.Now().UnixNano()))
	tmp, err := store.Open(dbPath)
	if err != nil {
		return false, "", err
	}
	defer func() {
		tmp.Close()
		_ = os.Remove(dbPath)
		_ = os.Remove(dbPath + "-wal")
		_ = os.Remove(dbPath + "-shm")
	}()
	spec.ConsecutiveFailures = 1
	spec.Contain = false
	b, _ := json.Marshal(spec)
	if err := tmp.PutMonitor(spec.ID, b, "probe"); err != nil {
		return false, "", err
	}
	if env != nil {
		e := *env
		e.State = nil
		env = &e
	}
	NewRunner(tmp, env).RunDue(ctx, true)
	rows := tmp.Monitors(true)
	if len(rows) == 0 {
		return false, "", fmt.Errorf("monitor %s did not run", spec.ID)
	}
	return rows[0].LastOK, rows[0].LastOutput, nil
}
