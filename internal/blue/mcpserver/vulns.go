package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Problem99-io/kodeblue/internal/blue/services"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

func (s *Server) vulnContext() services.VulnContext {
	return services.VulnContext{Store: s.st, StateDir: s.cfg.Server.StateDir, Env: s.env}
}

// vulnerabilityReport records a weakness an agent found in a service, with
// how to fix it and, where it can be checked, a check that tells kodeblue
// when it is fixed.
func (s *Server) vulnerabilityReport(ctx context.Context, args json.RawMessage) (string, error) {
	var a struct {
		ID          string          `json:"id"`
		Service     string          `json:"service"`
		Title       string          `json:"title"`
		Severity    string          `json:"severity"`
		Category    string          `json:"category"`
		CVEs        json.RawMessage `json:"cves"`
		Evidence    string          `json:"evidence"`
		Remediation string          `json:"remediation"`
		Check       json.RawMessage `json:"check"`
	}
	if err := decode(args, &a); err != nil {
		return "", err
	}
	cves, err := idList(a.CVEs)
	if err != nil {
		return "", fmt.Errorf("cves must be a list of ids, e.g. [\"CVE-2024-6387\"]")
	}
	v := store.Vulnerability{ID: a.ID, Service: a.Service, Title: truncate(a.Title, 200), Severity: a.Severity, Category: a.Category, CVEs: cves,
		Evidence: truncate(a.Evidence, 4000), Remediation: truncate(a.Remediation, 4000), Check: a.Check}
	created, note, err := s.vulnContext().Report(ctx, v, "agent")
	if err != nil {
		return "", err
	}
	verb := "recorded"
	if !created {
		verb = "updated"
	}
	msg := fmt.Sprintf("%s vulnerability %s for %s.%s", verb, a.ID, a.Service, note)
	if a.Service != services.Host && !s.knownService(a.Service) {
		msg += " Note: service_inventory has no service by that name; use its exact name, or \"host\" for the server as a whole."
	}
	return msg, nil
}

func (s *Server) knownService(name string) bool {
	for _, r := range services.Take(s.env, s.st, s.cfg.RequestsDir()).Services {
		if r.Name == name {
			return true
		}
	}
	return false
}

func (s *Server) vulnerabilityList(ctx context.Context, args json.RawMessage) (string, error) {
	var a struct {
		Service string `json:"service"`
		Status  string `json:"status"`
	}
	if err := decode(args, &a); err != nil {
		return "", err
	}
	where, q := "WHERE 1=1", []any{}
	if a.Service != "" {
		where += " AND service=?"
		q = append(q, a.Service)
	}
	if a.Status != "" {
		where += " AND status=?"
		q = append(q, a.Status)
	}
	l := s.st.Vulnerabilities(where+" ORDER BY service, id", q...)
	return fmt.Sprintf("%d vulnerabilities.\n", len(l)) + jsonOut(l) + untrusted, nil
}

func (s *Server) vulnerabilityResolve(ctx context.Context, args json.RawMessage) (string, error) {
	var a struct {
		ID   string `json:"id"`
		Note string `json:"note"`
	}
	if err := decode(args, &a); err != nil {
		return "", err
	}
	return s.vulnContext().Resolve(ctx, a.ID, "agent", truncate(a.Note, 1000))
}
