package config

import (
	"math"
	"slices"
	"strconv"
	"strings"

	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
)

// tuningField points at the config field behind a hub tuning key
// (hubproto.Tunings). Exactly one of the pointers is set.
type tuningField struct {
	i *int
	f *float64
	b *bool
	s *string
}

func (c *Config) tuningFields() map[string]tuningField {
	return map[string]tuningField{
		"budget.daily_usd":                {f: &c.Budget.DailyUSD},
		"budget.input_usd_per_mtok":       {f: &c.Budget.InputUSDPerMTok},
		"budget.output_usd_per_mtok":      {f: &c.Budget.OutputUSDPerMTok},
		"budget.max_concurrent_incidents": {i: &c.Budget.MaxConcurrentIncidents},
		"budget.max_incidents_per_hour":   {i: &c.Budget.MaxIncidentsPerHour},
		"budget.incident_max_iterations":  {i: &c.Budget.IncidentMaxIterations},
		"schedule.review_hours":           {i: &c.Schedule.ReviewHours},
		"schedule.learning_minutes":       {i: &c.Schedule.LearningMinutes},
		"schedule.learning_sweeps":        {i: &c.Schedule.LearningSweeps},
		"schedule.retention_days":         {i: &c.Schedule.RetentionDays},
		"detect.realert_hours":            {i: &c.Detect.RealertHours},
		"detect.bruteforce_threshold":     {i: &c.Detect.BruteForceThreshold},
		"detect.debounce_sweeps":          {i: &c.Detect.DebounceSweeps},
		"notify.min_severity":             {s: &c.Notify.MinSeverity},
		"notify.agent_messages_per_hour":  {i: &c.Notify.AgentMessagesPerHour},
		"hub.sync_seconds":                {i: &c.Hub.SyncSeconds},
		"hub.messages_per_hour":           {i: &c.Hub.MessagesPerHour},
		"hub.share_transcripts":           {b: &c.Hub.ShareTranscripts},
		"requests.disabled":               {b: &c.Requests.Disabled},
	}
}

// applyTuning sets the hub's tuning values that pass their checks, and caps
// the daily budget at the root-owned hub_max_daily_usd.
func (c *Config) applyTuning(m map[string]string) {
	fields := c.tuningFields()
	for k, v := range m {
		t, ok := hubproto.TuningFor(k)
		fd, known := fields[k]
		if !ok || !known || t.Check(v) != nil {
			continue
		}
		v = strings.TrimSpace(v)
		switch {
		case fd.i != nil:
			*fd.i, _ = strconv.Atoi(v)
		case fd.f != nil:
			*fd.f, _ = strconv.ParseFloat(v, 64)
		case fd.b != nil:
			*fd.b = v == "true"
		case fd.s != nil:
			*fd.s = v
		}
	}
	if _, set := m["budget.daily_usd"]; set && c.Budget.HubMaxDailyUSD > 0 {
		c.Budget.DailyUSD = math.Min(c.Budget.DailyUSD, c.Budget.HubMaxDailyUSD)
	}
}

// applyProtections adds the hub's protected users, IPs and units to the
// server's own lists and lowers (never raises) its containment rate limit.
// The root helper does not read them: the agents' respond tool checks them
// before a request reaches it.
func (c *Config) applyProtections(s *hubproto.Settings) {
	if hubproto.CheckProtected(s.ProtectedUsers, s.ProtectedIPs, s.ProtectedUnits) != nil {
		return
	}
	add := func(own, more []string) []string {
		out := slices.Clone(own)
		for _, v := range more {
			if v = strings.TrimSpace(v); v != "" && !slices.Contains(out, v) {
				out = append(out, v)
			}
		}
		return out
	}
	c.Response.ProtectedUsers = add(c.Response.ProtectedUsers, s.ProtectedUsers)
	c.Response.ProtectedIPs = add(c.Response.ProtectedIPs, s.ProtectedIPs)
	c.Response.ProtectedUnits = add(c.Response.ProtectedUnits, s.ProtectedUnits)
	if n := s.MaxActionsPerHour; n > 0 && (c.Response.MaxActionsPerHour <= 0 || n < c.Response.MaxActionsPerHour) {
		c.Response.MaxActionsPerHour = n
	}
}

// TuningValues reports the value of each hub-settable setting in effect.
func (c Config) TuningValues() map[string]string {
	out := map[string]string{}
	for k, fd := range c.tuningFields() {
		switch {
		case k == "schedule.retention_days" && *fd.i <= 0:
			// 0 is the default, 90 days; negative keeps everything.
			out[k] = "forever"
			if *fd.i == 0 {
				out[k] = "90"
			}
		case fd.i != nil:
			out[k] = strconv.Itoa(*fd.i)
		case fd.f != nil:
			out[k] = strconv.FormatFloat(*fd.f, 'f', -1, 64)
		case fd.b != nil:
			out[k] = strconv.FormatBool(*fd.b)
		case fd.s != nil:
			out[k] = *fd.s
		}
	}
	return out
}
