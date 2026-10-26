package daemon

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
	"github.com/Problem99-io/kodeblue/internal/blue/upgrade"
)

// An operator's upgrade waits for learning and agent sessions to finish,
// then goes to the root helper once; what the helper refuses is reported.
func TestUpgradeWaitsThenHandsToTheHelper(t *testing.T) {
	d, _, _, _ := newTestDaemon(t)
	old := hubproto.Version
	hubproto.Version = "v0.1.6"
	t.Cleanup(func() { hubproto.Version = old })
	var calls []map[string]string
	answer := `{"status":"started","result":"upgrading"}`
	realHelper := invokeHelper
	t.Cleanup(func() { invokeHelper = realHelper })
	invokeHelper = func(_ context.Context, _ string, payload []byte) ([]byte, error) {
		var m map[string]string
		_ = json.Unmarshal(payload, &m)
		calls = append(calls, m)
		return []byte(answer), nil
	}

	for _, bad := range []string{"v0.1.5", "v0.1.6", "latest"} {
		if r := d.Upgrade(hubproto.OperatorMessage{Author: "alice", Command: hubproto.CommandUpgrade, Body: bad}); r.Status != "refused" {
			t.Errorf("%s: %+v", bad, r)
		}
	}
	d.learning.Store(true)
	r := d.Upgrade(hubproto.OperatorMessage{Author: "alice", Command: hubproto.CommandUpgrade, Body: "v0.1.7"})
	if r.Status != "done" || !strings.Contains(r.Text, "once learning finishes") {
		t.Fatalf("reply: %+v", r)
	}
	d.maybeUpgrade(context.Background())
	if len(calls) != 0 {
		t.Fatal("upgrade started while learning")
	}
	if s := d.UpgradeStatus(); s.State != upgrade.Waiting || s.By != "hub:alice" || s.From != "v0.1.6" {
		t.Errorf("waiting: %+v", s)
	}
	d.learning.Store(false)
	done := d.track("sess-1", 7)
	d.maybeUpgrade(context.Background())
	if s := d.UpgradeStatus(); len(calls) != 0 || !strings.Contains(s.Detail, "agent session") {
		t.Fatalf("started during an agent session: %d calls, %+v", len(calls), s)
	}
	done()
	d.maybeUpgrade(context.Background())
	if len(calls) != 1 || calls[0]["op"] != "upgrade" || calls[0]["version"] != "v0.1.7" || calls[0]["by"] != "hub:alice" {
		t.Fatalf("helper calls: %+v", calls)
	}
	if s := d.UpgradeStatus(); s.State != upgrade.Installing {
		t.Errorf("installing: %+v", s)
	}
	d.maybeUpgrade(context.Background())
	if len(calls) != 1 {
		t.Error("asked the helper twice")
	}
	if r := d.Upgrade(hubproto.OperatorMessage{Author: "bob", Body: "v0.1.7"}); r.Status != "refused" {
		t.Errorf("second request during the install: %+v", r)
	}

	// The restarted daemon runs the new version: done.
	hubproto.Version = "v0.1.7"
	if s := d.UpgradeStatus(); s.State != upgrade.Done {
		t.Errorf("after the restart: %+v", s)
	}

	// The helper refuses (accept_upgrades off in the root config).
	hubproto.Version = "v0.1.7"
	answer = `{"status":"refused","result":"upgrades from the hub are off on this server (hub.accept_upgrades)"}`
	_ = d.Upgrade(hubproto.OperatorMessage{Author: "alice", Body: "v0.1.8"})
	d.maybeUpgrade(context.Background())
	if s := d.UpgradeStatus(); s.State != upgrade.Failed || !strings.Contains(s.Detail, "accept_upgrades") {
		t.Errorf("refused: %+v", s)
	}
}

// An install that neither finished nor reported is not shown as running
// forever.
func TestUpgradeInstallTimesOut(t *testing.T) {
	d, _, _, _ := newTestDaemon(t)
	_ = upgrade.Write(d.cfg.Server.StateDir, upgrade.Status{To: "v9.0.0", State: upgrade.Installing, At: time.Now().Add(-upgrade.InstallTimeout - time.Minute)}, -1)
	if s := d.UpgradeStatus(); s.State != upgrade.Failed || !strings.Contains(s.Detail, "journalctl -u kodeblue-upgrade") {
		t.Errorf("stale install: %+v", s)
	}
}
