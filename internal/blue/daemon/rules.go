package daemon

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/containment"
	"github.com/Problem99-io/kodeblue/internal/blue/detect"
	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
	"github.com/Problem99-io/kodeblue/internal/blue/mcpserver"
	"github.com/Problem99-io/kodeblue/internal/blue/notify"
	"github.com/Problem99-io/kodeblue/internal/blue/respond"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

// ruleWorkers is how many findings' rule actions run at once.
const ruleWorkers = 4

// applyRules answers findings that an approved containment rule covers,
// before triage reads them: the attack was seen before, a person approved
// the answer, and waiting for a model only gives it time. A finding every
// target of which was contained is closed; one where a rule could not act
// (refused, over its limit, a protected address) goes on to triage as usual,
// and criticals always do.
func (d *Daemon) applyRules(ctx context.Context, all []*store.Finding) []*store.Finding {
	rules := containment.Active(d.cfg, time.Now())
	if len(rules) == 0 || d.cfg.Response.Mode == "off" {
		return all
	}
	// A flood brings many findings at once, and each action is a helper run
	// (with DNS lookups for block_ip): run a few side by side so the sweep
	// does not wait for them one by one. The helper serializes what must be.
	results := make([][]containment.Fired, len(all))
	sem := make(chan struct{}, ruleWorkers)
	var wg sync.WaitGroup
	for i, f := range all {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			results[i] = containment.Fire(ctx, rules, f, d.ruleCheck, d.ruleRun)
		}()
	}
	wg.Wait()
	out := all[:0:0]
	for i, f := range all {
		fired := results[i]
		if len(fired) == 0 {
			out = append(out, f)
			continue
		}
		var lines []string
		done, acted := true, false
		for _, x := range fired {
			lines = append(lines, fmt.Sprintf("%s on %s: %s", x.Rule, x.Target, x.Message))
			done = done && x.Done
			acted = acted || x.Done
			d.log.Info("containment rule", "rule", x.Rule, "finding", f.ID, "target", x.Target, "done", x.Done, "result", x.Message)
		}
		summary := clipText(strings.Join(lines, "\n"), 1500)
		d.st.Journal("rule:"+fired[0].Rule, "rule.fired", fmt.Sprintf("finding #%d: %s", f.ID, summary))
		// Slack hears about what was done. What a rule could not do (over
		// its limit, refused) goes on to triage like any finding, which
		// notifies as usual: one alert per finding of a flood is the noise
		// the rule exists to remove.
		if acted {
			d.slack.Async(notify.Message{Server: d.cfg.Server.Name, Kind: "action", Severity: "medium", IncidentID: f.IncidentID,
				Title: fmt.Sprintf("Containment rule %s answered: %s", fired[0].Rule, f.Title), Body: summary}, nil)
		}
		if done && f.Severity != detect.SevCritical {
			_ = d.st.SetFindingStatus(f.ID, "closed", "contained", "contained by an approved containment rule: "+summary, 0)
			continue
		}
		out = append(out, f)
	}
	return out
}

// ruleCheck refuses a rule's request on what only this side knows, as
// mcpserver.Submit does for an agent's: an action the hub turned off,
// protected targets the hub added, and the hub's lower rate limit.
func (d *Daemon) ruleCheck(req respond.Request) error {
	if d.cfg.ActionRule(req.Action) == hubproto.ActionOff {
		return fmt.Errorf("the operators turned %s off for this server on the hub", req.Action)
	}
	if err := respond.Check(d.cfg.Response, req); err != nil {
		return err
	}
	return mcpserver.RateLimited(d.cfg)
}

// recurringDigest is the reviewer's view of attacks that keep coming back:
// finding rules seen at least three times in two weeks, with the targets
// they named, and the containment rules that exist already. It is where a
// proposal for a containment rule starts.
func (d *Daemon) recurringDigest(now time.Time) string {
	type agg struct {
		findings, occurrences int
		targets               map[string]int
		ids                   []int64
		incidents             map[int64]bool
	}
	by := map[string]*agg{}
	for _, f := range d.st.FindingsSince(now.Add(-14*24*time.Hour), 2000) {
		a := by[f.Rule]
		if a == nil {
			a = &agg{targets: map[string]int{}, incidents: map[int64]bool{}}
			by[f.Rule] = a
		}
		a.findings++
		a.occurrences += max(f.Occurrences, 1)
		if ip := f.Evidence["ip"]; ip != "" {
			a.targets[ip]++
		}
		if len(a.ids) < 6 {
			a.ids = append(a.ids, f.ID)
		}
		if f.IncidentID > 0 {
			a.incidents[f.IncidentID] = true
		}
	}
	var b strings.Builder
	b.WriteString("Recurring findings, last 14 days (rules seen at least 3 times; untrusted host data):\n")
	rules := make([]string, 0, len(by))
	for rule, a := range by {
		if a.findings >= 3 {
			rules = append(rules, rule)
		}
	}
	slices.SortFunc(rules, func(x, y string) int {
		if c := by[y].findings - by[x].findings; c != 0 {
			return c
		}
		return strings.Compare(x, y)
	})
	n := 0
	for _, rule := range rules {
		a := by[rule]
		n++
		fmt.Fprintf(&b, "- %s: %d findings (%d occurrences), %d incidents; e.g. findings %v", rule, a.findings, a.occurrences, len(a.incidents), a.ids)
		if len(a.targets) > 0 {
			fmt.Fprintf(&b, "; %d distinct addresses", len(a.targets))
		}
		b.WriteString("\n")
	}
	if n == 0 {
		b.WriteString("- none\n")
	}
	views := containment.List(d.cfg, d.st)
	b.WriteString("Containment rules:\n")
	if len(views) == 0 {
		b.WriteString("- none\n")
	}
	for _, v := range views {
		fmt.Fprintf(&b, "- %s [%s] answers %s with %s; fired %d times\n", v.ID, v.Status, v.When.Rule, v.Action, v.Fired)
	}
	return b.String()
}
