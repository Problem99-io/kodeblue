package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/notify"
	"github.com/Problem99-io/kodeblue/internal/blue/sensors"
)

func (s *Server) sensorCoverage(ctx context.Context, args json.RawMessage) (string, error) {
	type row struct {
		sensors.Coverage
		Disabled *sensors.DisabledSensor `json:"disabled,omitempty"`
	}
	off := sensors.ParseDisabled(s.st.Get(sensors.DisabledKey))
	var out []row
	for _, c := range sensors.CheckCoverage(s.env) {
		r := row{Coverage: c}
		if d, ok := off[c.Collector]; ok {
			r.Disabled = &d
		}
		out = append(out, r)
	}
	tap := s.st.Get("request_tap")
	if tap == "" {
		tap = `{"status":"unavailable","error":"kodeblue has not started the tap"}`
	}
	return jsonOut(out) + "\nrequest_tap (every plaintext HTTP request to this network namespace's listening ports, whatever the application logs; " +
		"combined log format, client address first; point request log monitors at its directory): " + tap + untrusted, nil
}

// sensorDisable turns off a sensor that cannot see this server, once
// monitors cover for it. kodeblue decides whether a sensor is blind, not the
// agent: a sensor that still sees part of the server is never turned off.
func (s *Server) sensorDisable(ctx context.Context, args json.RawMessage) (string, error) {
	var a struct {
		Collector  string          `json:"collector"`
		Reason     string          `json:"reason"`
		ReplacedBy json.RawMessage `json:"replaced_by"`
	}
	if err := decode(args, &a); err != nil {
		return "", err
	}
	replacedBy, err := idList(a.ReplacedBy)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(a.Reason) == "" {
		return "", errors.New("reason is required")
	}
	var cov *sensors.Coverage
	for _, c := range sensors.CheckCoverage(s.env) {
		if c.Collector == a.Collector {
			cov = &c
			break
		}
	}
	if cov == nil {
		return "", fmt.Errorf("unknown sensor %q (sensors: %s)", a.Collector, strings.Join(sensors.CollectorNames(), ", "))
	}
	if cov.Status != sensors.CoverageBlind && cov.Status != sensors.CoverageUnavailable {
		return "", fmt.Errorf("%s is %s, not blind: it still sees part of this server, so it stays on. Cover what it misses with monitors and leave it running", a.Collector, cov.Status)
	}
	if cov.Status == sensors.CoverageBlind && len(replacedBy) == 0 {
		return "", errors.New("replaced_by is required: create and test the monitors that cover for this sensor first")
	}
	mons := map[string]bool{}
	for _, m := range s.st.Monitors(false) {
		mons[m.ID] = !m.Disabled && (m.Runs == 0 || m.LastOK)
	}
	for _, id := range replacedBy {
		ok, found := mons[id]
		switch {
		case !found:
			return "", fmt.Errorf("monitor %q does not exist or is disabled", id)
		case !ok:
			return "", fmt.Errorf("monitor %q is failing; fix it before relying on it", id)
		}
	}
	off := sensors.ParseDisabled(s.st.Get(sensors.DisabledKey))
	off[a.Collector] = sensors.DisabledSensor{Reason: a.Reason, ReplacedBy: replacedBy, By: "agent", At: time.Now().UTC().Format(time.RFC3339)}
	b, _ := json.Marshal(off)
	if err := s.st.Set(sensors.DisabledKey, string(b)); err != nil {
		return "", err
	}
	detail := fmt.Sprintf("%s (%s): %s; replaced by %s", a.Collector, cov.Status, a.Reason, strings.Join(replacedBy, ", "))
	s.st.Journal("agent", "sensor.disable", detail)
	s.slack.Async(notify.Message{Server: s.cfg.Server.Name, Kind: "agent", Severity: "medium",
		Title: "kodeblue turned off the " + a.Collector + " sensor",
		Body:  cov.Reason + "\nAgent's reason: " + a.Reason + "\nCovered by monitors: " + strings.Join(replacedBy, ", ") + "\nIt turns back on by itself if those monitors are disabled or the sensor can see the server again; `kodeblue sensors on " + a.Collector + "` turns it on now."}, nil)
	return fmt.Sprintf("sensor %s is off from the next sweep. It turns back on by itself if %s is disabled or the sensor can see this server again.", a.Collector, strings.Join(replacedBy, " or ")), nil
}

// idList accepts monitor ids as a JSON array or as one comma-separated
// string: some models flatten array arguments.
func idList(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var ids []string
	if err := json.Unmarshal(raw, &ids); err != nil {
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return nil, errors.New("replaced_by must be a list of monitor ids")
		}
		ids = strings.Split(s, ",")
	}
	var out []string
	for _, id := range ids {
		if id = strings.TrimSpace(id); id != "" {
			out = append(out, id)
		}
	}
	return out, nil
}

func (s *Server) sensorEnable(ctx context.Context, args json.RawMessage) (string, error) {
	var a struct {
		Collector string `json:"collector"`
	}
	if err := decode(args, &a); err != nil {
		return "", err
	}
	off := sensors.ParseDisabled(s.st.Get(sensors.DisabledKey))
	if _, ok := off[a.Collector]; !ok {
		if !slices.Contains(sensors.CollectorNames(), a.Collector) {
			return "", fmt.Errorf("unknown sensor %q", a.Collector)
		}
		return a.Collector + " is already on", nil
	}
	delete(off, a.Collector)
	b, _ := json.Marshal(off)
	if err := s.st.Set(sensors.DisabledKey, string(b)); err != nil {
		return "", err
	}
	s.st.Journal("agent", "sensor.enable", a.Collector)
	return "sensor " + a.Collector + " is on from the next sweep", nil
}
