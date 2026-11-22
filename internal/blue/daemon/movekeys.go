package daemon

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/hublink"
	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
	"github.com/Problem99-io/kodeblue/internal/blue/respond"
	"github.com/Problem99-io/kodeblue/internal/blue/upgrade"
)

// moveKeysTriedKey holds the hub and server versions the root helper was
// last asked to move the model keys for.
const moveKeysTriedKey = "move_keys_tried"

// maybeMoveKeys asks the root helper to move this server's own model key to
// the hub (kodeblue move-keys) once the hub runs a version at least as new
// as this server. The installer moves it on upgrade, but leaves it while the
// hub is behind: this finishes the move when the hub catches up. It asks
// once per pair of versions, so a key the hub refuses (an endpoint only this
// server reaches) is not offered again until one of them is upgraded.
func (d *Daemon) maybeMoveKeys(ctx context.Context) {
	if !d.cfg.Hub.Enabled() || !d.cfg.Hub.AcceptSettings || !holdsOwnKey(d) {
		return
	}
	hv := d.st.Get(hublink.HubVersionKey)
	if hv == "" || upgrade.Behind(hv, hubproto.Version) {
		return
	}
	mark := hv + " " + hubproto.Version
	if d.st.Get(moveKeysTriedKey) == mark {
		return
	}
	_ = d.st.Set(moveKeysTriedKey, mark)
	hctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	out, err := invokeHelper(hctx, d.cfg.Path(), []byte(`{"op":"move_keys"}`))
	var rec respond.Record
	if err == nil && json.Unmarshal(out, &rec) != nil {
		rec.Result = strings.TrimSpace(string(out))
	}
	if err != nil || rec.Status != "started" {
		why := rec.Result
		if err != nil {
			why = err.Error()
		}
		d.log.Warn("model keys not moved to the hub", "hub", hv, "reason", why)
		d.st.Journal("kodeblue", "keys.move_failed", why)
		return
	}
	d.log.Info("moving the model keys to the hub", "hub", hv)
	d.st.Journal("kodeblue", "keys.move_started", "hub runs "+hv+": "+rec.Result)
}

// holdsOwnKey reports whether the server's own [inference] key is in its
// config or key file (one in the environment cannot be moved).
func holdsOwnKey(d *Daemon) bool {
	in := d.cfg.Inference
	if strings.TrimSpace(in.APIKey) != "" {
		return true
	}
	if in.APIKeyFile == "" {
		return false
	}
	b, err := os.ReadFile(in.APIKeyFile)
	return err == nil && strings.TrimSpace(string(b)) != ""
}
