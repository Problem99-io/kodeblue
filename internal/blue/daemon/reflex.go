package daemon

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/mcpserver"
	"github.com/Problem99-io/kodeblue/internal/blue/monitor"
	"github.com/Problem99-io/kodeblue/internal/blue/respond"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

// reflex contains what a failing contain monitor names, at once and without
// an agent: an attacker's payload can do its work in less time than a model
// takes to read the finding. Each action goes through the same policy as the
// responder's (mode, allowed actions, per-action rules, protected targets,
// rate limit), so with response off it only journals what it would have done.
func (d *Daemon) reflex(s monitor.Spec, f *store.Finding, targets []monitor.Reflex) string {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var lines []string
	for _, t := range targets {
		req := respond.Request{
			ID: respond.NewID(), IncidentID: f.IncidentID, Action: t.Action, Params: t.Params,
			Justification: fmt.Sprintf("monitor %s failed: %s", s.ID, t.Why),
			RequestedBy:   "monitor:" + s.ID, RequestedAt: time.Now(),
		}
		target := t.Params["path"]
		if target == "" {
			target = fmt.Sprintf("pid %s (%s)", t.Params["pid"], t.Params["expect_exe"])
		}
		res, err := mcpserver.Submit(ctx, d.cfg, d.st, d.slack, req)
		switch {
		case err != nil && d.cfg.Response.Mode == "off":
			res = "not done, response is off: would have run " + t.Action + " on " + target
			d.st.Journal(req.RequestedBy, "respond.would", fmt.Sprintf("%s %s: %s", t.Action, target, t.Why))
		case err != nil:
			res = t.Action + " " + target + " refused: " + err.Error()
			d.st.Journal(req.RequestedBy, "respond.refused", res)
		default:
			res = t.Action + " " + target + ": " + res
		}
		d.log.Info("monitor reflex", "monitor", s.ID, "result", res)
		lines = append(lines, res)
	}
	return strings.Join(lines, "\n")
}
