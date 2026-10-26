package hubproto

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// Tuning is a server setting hub operators may set: what a server spends,
// how often it does things and how noisy it is, never what its agents may
// do. Settings carry values as strings by key; the hub checks them against
// Kind and the bounds here, and the server checks them again before use.
// The bounds keep a hub from blinding a server (a brute-force threshold of
// a million, retention of an hour) through settings meant for tuning.
type Tuning struct {
	Key   string  `json:"key"` // the server's config key, e.g. budget.daily_usd
	Group string  `json:"group"`
	Label string  `json:"label"`
	Help  string  `json:"help"`
	Kind  string  `json:"kind"` // int | usd | bool | severity
	Min   float64 `json:"min,omitempty"`
	Max   float64 `json:"max,omitempty"`
}

// Tunings lists every setting the hub may set, in display order.
var Tunings = []Tuning{
	{Key: "budget.daily_usd", Group: "Budget", Label: "Daily model budget (USD)", Kind: "usd", Min: 0.1, Max: 1000,
		Help: "Model spend per UTC day. Past it only critical findings reach a model (hard stop at twice the budget). The server caps it at its own [budget] hub_max_daily_usd."},
	{Key: "budget.input_usd_per_mtok", Group: "Budget", Label: "Input price (USD per million tokens)", Kind: "usd", Min: 0, Max: 1000,
		Help: "Only for endpoints that report no cost per call: without prices such calls count as $0 and the budget is not enforced."},
	{Key: "budget.output_usd_per_mtok", Group: "Budget", Label: "Output price (USD per million tokens)", Kind: "usd", Min: 0, Max: 1000,
		Help: "Only for endpoints that report no cost per call."},
	{Key: "budget.max_concurrent_incidents", Group: "Budget", Label: "Incidents investigated at once", Kind: "int", Min: 1, Max: 20},
	{Key: "budget.max_incidents_per_hour", Group: "Budget", Label: "New investigations per hour", Kind: "int", Min: 1, Max: 100},
	{Key: "budget.incident_max_iterations", Group: "Budget", Label: "Steps per investigation", Kind: "int", Min: 5, Max: 200,
		Help: "How many tool calls an incident agent may make before it must report."},
	{Key: "schedule.review_hours", Group: "Schedule", Label: "Reviewer runs every (hours)", Kind: "int", Min: 1, Max: 168},
	{Key: "schedule.learning_minutes", Group: "Schedule", Label: "Baseline length (minutes)", Kind: "int", Min: 5, Max: 1440,
		Help: "How long learning collects the baseline. Applies to the next learning run."},
	{Key: "schedule.learning_sweeps", Group: "Schedule", Label: "Baseline snapshots", Kind: "int", Min: 2, Max: 100,
		Help: "Snapshots taken over the baseline. Applies to the next learning run."},
	{Key: "schedule.retention_days", Group: "Schedule", Label: "Keep settled findings and the journal (days)", Kind: "int", Min: 7, Max: 3650},
	{Key: "detect.realert_hours", Group: "Detection", Label: "Re-alert an unchanged finding after (hours)", Kind: "int", Min: 1, Max: 168},
	{Key: "detect.bruteforce_threshold", Group: "Detection", Label: "Failed logins from one address that count as brute force", Kind: "int", Min: 3, Max: 50},
	{Key: "detect.debounce_sweeps", Group: "Detection", Label: "Sweeps a change must persist before it is a finding", Kind: "int", Min: 1, Max: 5},
	{Key: "notify.min_severity", Group: "Notifications", Label: "Lowest severity that notifies about an incident", Kind: "severity"},
	{Key: "notify.agent_messages_per_hour", Group: "Notifications", Label: "Agent messages per hour", Kind: "int", Min: 1, Max: 120,
		Help: "Messages agents may post (progress, questions) per hour."},
	{Key: "hub.sync_seconds", Group: "Hub link", Label: "Sync with the hub every (seconds)", Kind: "int", Min: 5, Max: 300},
	{Key: "hub.messages_per_hour", Group: "Hub link", Label: "Operator chat messages per hour", Kind: "int", Min: 1, Max: 240},
	{Key: "hub.share_transcripts", Group: "Hub link", Label: "Share agent transcripts with the hub", Kind: "bool"},
	{Key: "requests.disabled", Group: "Web requests", Label: "Turn off the web request recorder", Kind: "bool",
		Help: "The recorder notes the request lines of web services so agents can see attacks against them."},
}

// TuningFor returns the tuning setting for key.
func TuningFor(key string) (Tuning, bool) {
	for _, t := range Tunings {
		if t.Key == key {
			return t, true
		}
	}
	return Tuning{}, false
}

var severities = []string{"info", "low", "medium", "high", "critical"}

// Check validates a value for the setting.
func (t Tuning) Check(v string) error {
	v = strings.TrimSpace(v)
	switch t.Kind {
	case "int", "usd":
		f, err := strconv.ParseFloat(v, 64)
		if t.Kind == "int" {
			var n int
			n, err = strconv.Atoi(v)
			f = float64(n)
		}
		if err != nil {
			return fmt.Errorf("%s: %q is not a number", t.Label, v)
		}
		if f < t.Min || f > t.Max {
			return fmt.Errorf("%s: must be between %v and %v", t.Label, t.Min, t.Max)
		}
	case "bool":
		if v != "true" && v != "false" {
			return fmt.Errorf("%s: must be true or false", t.Label)
		}
	case "severity":
		if !containsStr(severities, v) {
			return fmt.Errorf("%s: must be one of %s", t.Label, strings.Join(severities, ", "))
		}
	default:
		return fmt.Errorf("%s: unknown kind %q", t.Label, t.Kind)
	}
	return nil
}

// CheckTuning validates a set of tuning values by key.
func CheckTuning(m map[string]string) error {
	for k, v := range m {
		t, ok := TuningFor(k)
		if !ok {
			return fmt.Errorf("unknown setting %q", k)
		}
		if err := t.Check(v); err != nil {
			return err
		}
	}
	return nil
}

// MaxProtected bounds each protected list the hub adds.
const MaxProtected = 200

var (
	userRe = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}\$?$`)
	unitRe = regexp.MustCompile(`^[A-Za-z0-9@_.:*-]{1,128}$`)
)

// CheckProtected validates the users, IPs (or CIDRs) and systemd units the
// hub adds to a server's protected lists.
func CheckProtected(users, ips, units []string) error {
	if len(users) > MaxProtected || len(ips) > MaxProtected || len(units) > MaxProtected {
		return fmt.Errorf("at most %d entries per protected list", MaxProtected)
	}
	for _, u := range users {
		if !userRe.MatchString(u) {
			return fmt.Errorf("protected user %q is not a user name", u)
		}
	}
	for _, ip := range ips {
		if net.ParseIP(ip) == nil {
			if _, _, err := net.ParseCIDR(ip); err != nil {
				return fmt.Errorf("protected IP %q is not an address or CIDR", ip)
			}
		}
	}
	for _, u := range units {
		if !unitRe.MatchString(u) {
			return fmt.Errorf("protected service %q is not a unit name", u)
		}
	}
	return nil
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
