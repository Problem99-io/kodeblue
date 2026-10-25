package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/Problem99-io/kodeblue/internal/blue/notify"
	"github.com/Problem99-io/kodeblue/internal/blue/services"
)

// serviceInventory lists every service the server runs or can start, the
// checks each needs and the monitors or sensors that cover them, so the
// learner works from a complete list rather than from what it happened to
// notice.
func (s *Server) serviceInventory(ctx context.Context, args json.RawMessage) (string, error) {
	var a struct {
		Gaps bool `json:"gaps_only"`
	}
	if err := decode(args, &a); err != nil {
		return "", err
	}
	inv := services.Take(s.env, s.st, s.cfg.RequestsDir())
	gaps := inv.Gaps()
	if a.Gaps {
		inv.Services = gaps
	}
	head := fmt.Sprintf("%d services, %d missing a check.", len(inv.Services), len(gaps))
	if a.Gaps {
		head = fmt.Sprintf("%d services missing a check.", len(gaps))
	}
	if inv.Blind != "" {
		head += " kodeblue cannot see this server's processes, so the list is incomplete: " + inv.Blind
	}
	return head + " For each missing check create the monitor `need` describes (monitor_test first); where none can work, call coverage_case.\n" +
		jsonOut(inv) + untrusted, nil
}

// coverageCase opens a case for a service kodeblue cannot monitor well
// enough. It waits for a human; no responder is started, since nothing on
// the host is under attack.
func (s *Server) coverageCase(ctx context.Context, args json.RawMessage) (string, error) {
	var a struct {
		Service  string          `json:"service"`
		Severity string          `json:"severity"`
		Summary  string          `json:"summary"`
		Tried    string          `json:"tried"`
		Checks   json.RawMessage `json:"checks"`
	}
	if err := decode(args, &a); err != nil {
		return "", err
	}
	a.Service, a.Summary, a.Tried = strings.TrimSpace(a.Service), strings.TrimSpace(a.Summary), strings.TrimSpace(a.Tried)
	switch a.Severity {
	case "":
		a.Severity = "medium"
	case "low", "medium", "high":
	default:
		return "", errors.New("severity must be low, medium or high; an intrusion goes to finding_report instead")
	}
	if a.Service == "" || len(a.Summary) < 20 {
		return "", errors.New("service (its name in service_inventory) and summary (what cannot be watched and why) are required")
	}
	checks, err := idList(a.Checks)
	if err != nil {
		return "", errors.New("checks must be a list of check names, e.g. [\"exec\",\"files\"]")
	}
	inv := services.Take(s.env, s.st, s.cfg.RequestsDir())
	var res *services.Result
	for i := range inv.Services {
		if inv.Services[i].Name == a.Service {
			res = &inv.Services[i]
		}
	}
	if res != nil && len(checks) == 0 {
		checks = res.Missing
	}
	in, created, err := services.OpenCase(s.st, services.Gap{
		Service: a.Service, Severity: a.Severity, Summary: truncate(a.Summary, 1000), Notes: truncate(a.Tried, 4000),
		Checks: checks, Result: res, By: "agent",
	})
	if err != nil {
		return "", err
	}
	if !created {
		return fmt.Sprintf("coverage case %d for %s was already open; updated it with your explanation", in.ID, a.Service), nil
	}
	s.slack.Async(notify.Message{Server: s.cfg.Server.Name, Kind: "coverage", Severity: a.Severity, IncidentID: in.ID,
		Title: fmt.Sprintf("#%d %s", in.ID, in.Title),
		Body:  a.Summary + "\nkodeblue resolves the case by itself once monitors cover the service."}, nil)
	msg := fmt.Sprintf("opened coverage case %d for %s; it waits for a human", in.ID, a.Service)
	if res == nil {
		msg += ". Note: service_inventory has no service by that name, so kodeblue cannot resolve this case by itself"
	}
	return msg, nil
}
