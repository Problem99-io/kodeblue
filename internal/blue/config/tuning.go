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
		"cve_feed.enabled":                {b: &c.CVEFeed.Enabled},
		"cve_feed.nvd":                    {b: &c.CVEFeed.NVD},
		"cve_feed.cisa_kev":               {b: &c.CVEFeed.KEV},
	}
}

// applyTuning sets the hub's tuning values that pass their checks. A value
// whose setting only tightens (Tuning.Only) applies only when it is stricter
// than the server's own. The daily budget is capped at the root-owned
// hub_max_daily_usd; with none (0 or less) the hub may only lower it. The
// CVE feed and its sources stay off where the root config turns them off.
func (c *Config) applyTuning(m map[string]string) {
	fields := c.tuningFields()
	rootDaily := c.Budget.DailyUSD
	rootFeed := c.CVEFeed
	defer func() {
		c.CVEFeed.Enabled = c.CVEFeed.Enabled && rootFeed.Enabled
		c.CVEFeed.NVD = c.CVEFeed.NVD && rootFeed.NVD
		c.CVEFeed.KEV = c.CVEFeed.KEV && rootFeed.KEV
	}()
	for k, v := range m {
		t, ok := hubproto.TuningFor(k)
		fd, known := fields[k]
		if !ok || !known || t.Check(v) != nil {
			continue
		}
		v = strings.TrimSpace(v)
		switch {
		case fd.i != nil:
			n, _ := strconv.Atoi(v)
			own := *fd.i
			if k == "schedule.retention_days" {
				if own < 0 {
					continue // the server keeps everything
				}
				if own == 0 {
					own = 90
				}
			}
			if tightens(t.Only, float64(own), float64(n)) {
				*fd.i = n
			}
		case fd.f != nil:
			f, _ := strconv.ParseFloat(v, 64)
			if tightens(t.Only, *fd.f, f) {
				*fd.f = f
			}
		case fd.b != nil:
			b := v == "true"
			if tightens(t.Only, boolNum(*fd.b), boolNum(b)) {
				*fd.b = b
			}
		case fd.s != nil:
			if t.Kind == "severity" && !tightens(t.Only, float64(hubproto.SeverityRank(*fd.s)), float64(hubproto.SeverityRank(v))) {
				continue
			}
			*fd.s = v
		}
	}
	if _, set := m["budget.daily_usd"]; set {
		limit := c.Budget.HubMaxDailyUSD
		if limit <= 0 {
			limit = rootDaily // 0 or less in the root config: unlimited
		}
		if limit > 0 {
			c.Budget.DailyUSD = math.Min(c.Budget.DailyUSD, limit)
		}
	}
}

// tightens reports whether a setting may move from own to v.
func tightens(only string, own, v float64) bool {
	switch only {
	case "lower":
		return v <= own
	case "raise":
		return v >= own
	}
	return true
}

func boolNum(b bool) float64 {
	if b {
		return 1
	}
	return 0
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
