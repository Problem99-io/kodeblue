package services

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/Problem99-io/kodeblue/internal/blue/detect"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

// Kind is the incident kind of a coverage case: a service kodeblue cannot
// watch well enough. Nobody investigates it; it waits for a human (status
// needs_human) until monitors cover the service, then kodeblue resolves it.
const Kind = "coverage"

const titlePrefix = "Coverage gap: "

// CaseTitle is the title of the coverage case about a service.
func CaseTitle(service string) string { return titlePrefix + service }

// caseMeta is kept beside a coverage case (kv coverage_case:<id>): which
// checks it is about, so kodeblue can tell when monitors cover them, and
// what the agent that opened it said.
type caseMeta struct {
	Service string   `json:"service"`
	Checks  []string `json:"checks,omitempty"`
	Notes   string   `json:"notes,omitempty"`
	By      string   `json:"by"`
}

func metaKey(id int64) string { return fmt.Sprintf("coverage_case:%d", id) }

func openCases(st *store.Store) map[string]store.Incident {
	out := map[string]store.Incident{}
	for _, in := range st.Incidents(`WHERE kind=? AND status<>'resolved' ORDER BY id`, Kind) {
		out[strings.TrimPrefix(in.Title, titlePrefix)] = in
	}
	return out
}

// Gap is what a coverage case is opened with.
type Gap struct {
	Service  string
	Severity string
	// Summary is the one-paragraph reason a human reads first.
	Summary string
	// Notes is the opener's explanation: what it tried and why it could not
	// cover the service.
	Notes string
	// Checks are the checks the case is about. Only known checks (health,
	// exec, …) can be resolved by kodeblue; a case naming another one stays
	// open until a human closes it.
	Checks []string
	// Result is the service as the inventory saw it, when it is in it.
	Result *Result
	By     string
}

// OpenCase opens a coverage case for a service, or updates the one already
// open: one case per service.
func OpenCase(st *store.Store, g Gap) (*store.Incident, bool, error) {
	if g.Severity == "" {
		g.Severity = detect.SevMedium
	}
	in, created := (*store.Incident)(nil), false
	if cur, ok := openCases(st)[g.Service]; ok {
		in = &cur
		if detect.Rank(g.Severity) > detect.Rank(in.Severity) {
			in.Severity = g.Severity
		}
		var old caseMeta
		_ = json.Unmarshal([]byte(st.Get(metaKey(in.ID))), &old)
		if g.Notes == "" {
			g.Notes = old.Notes
		}
		if g.By == "kodeblue" && old.By != "" && old.By != "kodeblue" {
			// The agent's explanation stays the summary, and the checks it
			// named stay part of the case.
			g.Summary, g.By = in.Summary, old.By
			for _, c := range old.Checks {
				if !slices.Contains(g.Checks, c) {
					g.Checks = append(g.Checks, c)
				}
			}
		}
	} else {
		in = &store.Incident{Title: CaseTitle(g.Service), Severity: g.Severity, Kind: Kind, Status: "needs_human"}
		if err := st.CreateIncident(in); err != nil {
			return nil, false, err
		}
		created = true
	}
	in.Status = "needs_human"
	in.Summary = g.Summary
	in.Report = report(g)
	if err := st.UpdateIncident(in); err != nil {
		return nil, false, err
	}
	m, _ := json.Marshal(caseMeta{Service: g.Service, Checks: g.Checks, Notes: g.Notes, By: g.By})
	_ = st.Set(metaKey(in.ID), string(m))
	verb := "case.update"
	if created {
		verb = "case.open"
	}
	st.Journal(g.By, verb, fmt.Sprintf("#%d %s: %s", in.ID, in.Title, strings.Join(g.Checks, ",")))
	return in, created, nil
}

func report(g Gap) string {
	var b strings.Builder
	b.WriteString("kodeblue cannot watch this service well enough. Until the missing checks below have monitors, an attack through it may go unnoticed.\n\n")
	if r := g.Result; r != nil {
		fmt.Fprintf(&b, "## Service\n\n- name: %s\n- state: %s\n- role: %s\n", r.Name, r.State, r.Role)
		if r.Unit != "" {
			fmt.Fprintf(&b, "- unit: %s\n", r.Unit)
		}
		if r.Container != "" {
			fmt.Fprintf(&b, "- container: %s\n", r.Container)
		}
		if len(r.Exes) > 0 {
			fmt.Fprintf(&b, "- programs: %s\n", strings.Join(r.Exes, ", "))
		}
		if len(r.Listen) > 0 {
			var ps []string
			for _, p := range r.Listen {
				ps = append(ps, fmt.Sprintf("%s/%d on %s", p.Proto, p.Port, p.Address))
			}
			fmt.Fprintf(&b, "- listens: %s\n", strings.Join(ps, ", "))
		}
		if r.Root != "" || r.Net != "" {
			fmt.Fprintf(&b, "- outside kodeblue's view: reach it through %s\n", strings.Trim(r.Root+" "+r.Net, " "))
		}
		if r.Note != "" {
			fmt.Fprintf(&b, "- note: %s\n", r.Note)
		}
		b.WriteString("\n## Checks\n\n")
		for _, c := range r.Checks {
			if len(c.By) > 0 {
				fmt.Fprintf(&b, "- %s: covered by %s\n", c.Check, strings.Join(c.By, ", "))
			} else {
				fmt.Fprintf(&b, "- **%s: missing**. Needs %s\n", c.Check, c.Need)
			}
		}
	}
	if extra := unknownChecks(g.Checks); len(extra) > 0 {
		fmt.Fprintf(&b, "\nAlso missing (kodeblue cannot verify these itself; close the case once they are covered): %s\n", strings.Join(extra, ", "))
	}
	if g.Notes != "" {
		fmt.Fprintf(&b, "\n## Why it is not covered (%s)\n\n%s\n", g.By, g.Notes)
	}
	b.WriteString("\n## What to do\n\nCreate the missing monitors (relearn, or an operator session), or change how kodeblue runs so it can see the service. kodeblue resolves this case by itself once monitors cover every missing check.\n")
	return b.String()
}

var known = []string{Health, Exec, Network, Files, Requests, Start}

func unknownChecks(checks []string) []string {
	var out []string
	for _, c := range checks {
		if !slices.Contains(known, c) {
			out = append(out, c)
		}
	}
	return out
}

// Sync brings the coverage cases in line with inv: a case for every service
// that still misses a check (one already open is refreshed, keeping what the
// agent wrote), and resolved cases for services whose checks are all covered
// now. It returns the cases it opened and resolved.
func Sync(st *store.Store, inv Inventory) (opened, resolved []store.Incident) {
	open := openCases(st)
	byName := map[string]Result{}
	for _, r := range inv.Services {
		byName[r.Name] = r
		if r.Covered() {
			continue
		}
		sev := detect.SevLow
		if r.State == "running" && r.Public() {
			sev = detect.SevMedium
		}
		rr := r
		in, created, err := OpenCase(st, Gap{
			Service: r.Name, Severity: sev, Checks: r.Missing, Result: &rr, By: "kodeblue",
			Summary: fmt.Sprintf("%s (%s) has no monitor for: %s. Nobody created one or said why it cannot be done.", r.Name, describe(r), strings.Join(r.Missing, ", ")),
		})
		if err == nil && created {
			opened = append(opened, *in)
		}
	}
	if inv.Blind != "" {
		in, created, err := OpenCase(st, Gap{Service: "this server's processes", Severity: detect.SevHigh, By: "kodeblue", Checks: []string{"visibility"},
			Summary: "kodeblue sees no processes but its own, so it cannot list or monitor the services on this server. " + inv.Blind})
		if err == nil && created {
			opened = append(opened, *in)
		}
	}
	for name, in := range open {
		r, ok := byName[name]
		if !ok || !r.Covered() {
			continue
		}
		var m caseMeta
		_ = json.Unmarshal([]byte(st.Get(metaKey(in.ID))), &m)
		if len(m.Checks) == 0 || len(unknownChecks(m.Checks)) > 0 {
			continue // about something kodeblue cannot verify: a human closes it
		}
		var by []string
		for _, c := range r.Checks {
			if slices.Contains(m.Checks, c.Check) {
				by = append(by, c.Check+": "+strings.Join(c.By, ", "))
			}
		}
		in.Status, in.Verdict = "resolved", "covered"
		in.Summary = "Covered now. " + strings.Join(by, "; ")
		if st.UpdateIncident(&in) == nil {
			st.Journal("kodeblue", "case.resolve", fmt.Sprintf("#%d %s", in.ID, in.Title))
			resolved = append(resolved, in)
		}
	}
	return opened, resolved
}

func describe(r Result) string {
	parts := []string{r.State}
	if r.Public() {
		parts = append(parts, "listens publicly")
	}
	if r.Root != "" || r.Container != "" {
		parts = append(parts, "outside kodeblue's filesystem")
	}
	return strings.Join(parts, ", ")
}
