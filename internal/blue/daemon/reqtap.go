package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"

	"github.com/Problem99-io/kodeblue/internal/blue/reqtap"
)

// TapStatusKey is where the request tap's state is kept for agents
// (sensor_coverage reads it from the store).
const TapStatusKey = "request_tap"

// TapStatus says whether the request tap runs and where it writes.
type TapStatus struct {
	Status string   `json:"status"` // ok | unavailable | disabled
	Log    string   `json:"log,omitempty"`
	Ports  []uint16 `json:"ports,omitempty"`
	Error  string   `json:"error,omitempty"`
}

func (d *Daemon) setTapStatus(s TapStatus) {
	b, _ := json.Marshal(s)
	_ = d.st.Set(TapStatusKey, string(b))
}

// startRequestTap records the HTTP requests reaching this namespace's
// services before learning starts, so the learner already has them to read.
func (d *Daemon) startRequestTap(ctx context.Context) {
	if d.cfg.Requests.Disabled {
		d.setTapStatus(TapStatus{Status: "disabled", Error: "[requests] disabled = true"})
		return
	}
	dir := d.cfg.RequestsDir()
	log := filepath.Join(dir, reqtap.LogName)
	rec := reqtap.NewRecorder(dir)
	d.setTapStatus(TapStatus{Status: "ok", Log: log})
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		err := reqtap.Run(ctx, rec, func(ports []uint16) {
			sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
			d.log.Info("request tap recording", "ports", fmt.Sprint(ports), "log", log)
			d.setTapStatus(TapStatus{Status: "ok", Log: log, Ports: ports})
		})
		if err != nil && ctx.Err() == nil {
			d.log.Warn("request tap unavailable: request monitors must rely on the applications' own logs", "error", err)
			d.setTapStatus(TapStatus{Status: "unavailable", Error: err.Error()})
		}
	}()
}
