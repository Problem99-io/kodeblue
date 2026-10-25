package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/detect"
	"github.com/Problem99-io/kodeblue/internal/blue/services"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

// checkServiceCoverage is the floor under the learner's monitors: every
// service the server runs or can start must have its checks covered, or a
// coverage case says it is not. The learner opens cases with its own
// explanation; this opens one for every gap it left without a word, and
// resolves the cases of services monitors cover now. It runs after learning
// and after each review, and returns a one-line summary.
func (d *Daemon) checkServiceCoverage(after string) string {
	inv := services.Take(d.env, d.st, d.cfg.RequestsDir())
	opened, resolved := services.Sync(d.st, inv)
	inv.Attach(d.st)
	d.saveInventory(inv)
	gaps := inv.Gaps()
	d.log.Info("service coverage", "after", after, "services", len(inv.Services), "gaps", len(gaps), "cases_opened", len(opened), "cases_resolved", len(resolved))
	if len(opened) > 0 || len(resolved) > 0 {
		d.nudgeHub()
	}
	if len(opened) > 0 {
		sev := detect.SevLow
		for _, in := range opened {
			if detect.Rank(in.Severity) > detect.Rank(sev) {
				sev = in.Severity
			}
		}
		d.notify("coverage", sev, fmt.Sprintf("kodeblue cannot fully monitor %d service(s)", len(opened)),
			"Opened a coverage case for each: "+caseList(opened)+". They wait for a human and resolve by themselves once monitors cover the service.", opened[0].ID)
	}
	line := fmt.Sprintf("%d services found, %d fully covered", len(inv.Services), len(inv.Services)-len(gaps))
	if n := len(d.st.Incidents(`WHERE kind=? AND status<>'resolved'`, services.Kind)); n > 0 {
		line += fmt.Sprintf(", %d coverage case(s) open", n)
	}
	if v := vulnSummary(d.st.Vulnerabilities(`WHERE status=?`, store.VulnOpen)); v != "" {
		line += ", " + v
	}
	return line
}

func (d *Daemon) saveInventory(inv services.Inventory) {
	b, _ := json.Marshal(inv)
	_ = d.st.Set(services.InventoryKey, string(b))
}

// assess runs the vulnerability assessment after the learner: a separate,
// short session that only records the weaknesses of each service, so a
// learner that runs out of turns or skips a step cannot leave them out.
func (d *Daemon) assess(ctx context.Context) {
	inv := services.Take(d.env, d.st, d.cfg.RequestsDir())
	var l []string
	for _, r := range inv.Services {
		var ports []string
		for _, p := range r.Listen {
			ports = append(ports, fmt.Sprintf("%s/%d on %s", p.Proto, p.Port, p.Address))
		}
		l = append(l, fmt.Sprintf("- %s (%s, %s) %s", r.Name, r.Role, r.State, strings.Join(ports, ", ")))
	}
	brief := fmt.Sprintf("Vulnerability assessment for server %q. kodeblue found these services:\n%s\nFollow your procedure: record every vulnerability you can show with vulnerability_report.", d.cfg.Server.Name, strings.Join(l, "\n"))
	in, sess, err := d.startLearning(ctx, "blue-assessor", "Vulnerability assessment", brief)
	if err != nil {
		return
	}
	out := d.finishLearning(ctx, in, sess, "vulnerabilities.md")
	d.log.Info("assessment finished", "status", out.Status, "cost_usd", fmt.Sprintf("%.4f", in.CostUSD),
		"open_vulnerabilities", len(d.st.Vulnerabilities(`WHERE status=?`, store.VulnOpen)))
}

// serviceLoop keeps the inventory the hub shows current and reruns the
// vulnerability checks, without a model: a vulnerability whose check passes
// is resolved, and one that was fixed and fails again is reopened.
func (d *Daemon) serviceLoop(ctx context.Context) {
	t := time.NewTimer(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		before := d.st.Get(services.InventoryKey)
		vc := services.VulnContext{Store: d.st, StateDir: d.cfg.Server.StateDir, Env: d.env}
		resolved, reopened := vc.Recheck(ctx)
		d.saveInventory(services.Take(d.env, d.st, d.cfg.RequestsDir()))
		if len(resolved) > 0 || len(reopened) > 0 || d.st.Get(services.InventoryKey) != before {
			d.nudgeHub()
		}
		if len(resolved) > 0 {
			d.log.Info("vulnerabilities fixed", "ids", vulnIDs(resolved))
		}
		if len(reopened) > 0 {
			sev := "low"
			for _, v := range reopened {
				if detect.Rank(v.Severity) > detect.Rank(sev) {
					sev = v.Severity
				}
			}
			d.notify("vulnerability", sev, fmt.Sprintf("%d fixed vulnerability(ies) came back", len(reopened)),
				"Their checks fail again: "+vulnIDs(reopened)+". A rollback or redeploy may have undone the fix.", 0)
		}
		t.Reset(10 * time.Minute)
	}
}

// vulnSummary says how many vulnerabilities are open, by severity.
func vulnSummary(open []store.Vulnerability) string {
	if len(open) == 0 {
		return ""
	}
	by := map[string]int{}
	for _, v := range open {
		by[v.Severity]++
	}
	var parts []string
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		if by[sev] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", by[sev], sev))
		}
	}
	return fmt.Sprintf("%d open vulnerabilities (%s)", len(open), strings.Join(parts, ", "))
}

func vulnIDs(l []store.Vulnerability) string {
	var ids []string
	for _, v := range l {
		ids = append(ids, v.ID)
	}
	return strings.Join(ids, ", ")
}

func caseList(cases []store.Incident) string {
	var l []string
	for i, in := range cases {
		if i == 8 {
			l = append(l, fmt.Sprintf("… %d more", len(cases)-8))
			break
		}
		l = append(l, fmt.Sprintf("#%d %s", in.ID, strings.TrimPrefix(in.Title, "Coverage gap: ")))
	}
	return strings.Join(l, ", ")
}
