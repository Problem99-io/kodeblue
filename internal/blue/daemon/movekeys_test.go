package daemon

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Problem99-io/kodeblue/internal/blue/hublink"
	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
)

// A server upgraded before its hub kept its model key: once the hub runs a
// version at least as new, the daemon has the root helper move it, once.
func TestMoveKeysWhenTheHubCatchesUp(t *testing.T) {
	d, st, _, _ := newTestDaemon(t)
	old := hubproto.Version
	hubproto.Version = "v0.3.0"
	t.Cleanup(func() { hubproto.Version = old })
	keyFile := filepath.Join(t.TempDir(), "inference.key")
	if err := os.WriteFile(keyFile, []byte("sk-own\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	d.cfg.Hub.URL, d.cfg.Hub.AcceptSettings = "https://hub.test", true
	d.cfg.Inference.APIKeyFile = keyFile
	calls := 0
	answer := `{"status":"started","result":"moving"}`
	realHelper := invokeHelper
	t.Cleanup(func() { invokeHelper = realHelper })
	invokeHelper = func(_ context.Context, _ string, payload []byte) ([]byte, error) {
		if string(payload) != `{"op":"move_keys"}` {
			t.Fatalf("payload %s", payload)
		}
		calls++
		return []byte(answer), nil
	}
	step := func(hub string, want int) {
		t.Helper()
		_ = st.Set(hublink.HubVersionKey, hub)
		d.maybeMoveKeys(context.Background())
		if calls != want {
			t.Fatalf("hub %q: %d helper calls, want %d", hub, calls, want)
		}
	}
	step("", 0)       // no sync yet
	step("v0.2.9", 0) // the hub is behind
	step("v0.3.0", 1) // caught up
	step("v0.3.0", 1) // once per pair of versions
	step("v0.3.1", 2) // the hub upgraded again: once more (the key is still here)
	_ = os.WriteFile(keyFile, nil, 0o600)
	step("v0.3.2", 2) // nothing left to move
	_ = os.WriteFile(keyFile, []byte("sk-own\n"), 0o600)
	d.cfg.Hub.AcceptSettings = false
	step("v0.3.3", 2) // the hub does not give this server its models
	d.cfg.Hub.AcceptSettings = true
	answer = `{"status":"refused","result":"no"}`
	step("v0.3.4", 3) // a refusal is not retried for the same versions
	step("v0.3.4", 3)
}
