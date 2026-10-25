package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/Problem99-io/kodeblue/internal/blue/monitor"
	"github.com/Problem99-io/kodeblue/internal/blue/sensors"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

// Host is the service a vulnerability of the server as a whole belongs to
// (the kernel, sudoers, an SSH setting shared by every login).
const Host = "host"

// VulnCategories are the kinds of vulnerability an agent can report.
var VulnCategories = []string{"outdated-software", "misconfiguration", "exposure", "weak-auth", "secret", "permissions", "other"}

// checkKinds are the monitor kinds a vulnerability check may use: the ones
// that judge the present state. A file or log monitor compares against what
// it saw before, which says nothing about whether a weakness is fixed.
var checkKinds = []string{"command", "http", "sockets"}

var (
	vulnIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)
	cveRe    = regexp.MustCompile(`^(CVE-\d{4}-\d{4,}|GHSA(-[23456789cfghjmpqrvwx]{4}){3})$`)
)

// VulnContext is what checking a vulnerability needs.
type VulnContext struct {
	Store    *store.Store
	StateDir string
	Env      *sensors.Env
}

// ParseCheck decodes a vulnerability's check: a monitor spec that fails while
// the vulnerability exists and passes once it is fixed.
func ParseCheck(id string, raw json.RawMessage) (*monitor.Spec, error) {
	var s monitor.Spec
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("check: %w", err)
	}
	if s.ID == "" {
		s.ID = "vuln-" + id
	}
	if s.Description == "" {
		s.Description = "check for vulnerability " + id
	}
	if s.Rationale == "" {
		s.Rationale = "passes once the vulnerability is fixed"
	}
	if s.Severity == "" {
		s.Severity = "low"
	}
	if !slices.Contains(checkKinds, s.Kind) {
		return nil, fmt.Errorf("check kind must be one of %s (a check judges the present state)", strings.Join(checkKinds, ", "))
	}
	s.Contain = false
	if err := s.Validate(); err != nil {
		return nil, fmt.Errorf("check: %w", err)
	}
	return &s, nil
}

// probe runs a vulnerability's check once.
func (c VulnContext) probe(ctx context.Context, v store.Vulnerability) (bool, string, error) {
	spec, err := ParseCheck(v.ID, v.Check)
	if err != nil {
		return false, "", err
	}
	ok, out, err := monitor.Probe(ctx, c.StateDir, c.Env, *spec)
	if len(out) > 2000 {
		out = out[:2000] + "…"
	}
	return ok, out, err
}

// Report records a vulnerability an agent found, or updates the one with its
// id. A check must fail now: one that passes does not show the weakness, and
// could never tell that it was fixed.
func (c VulnContext) Report(ctx context.Context, v store.Vulnerability, by string) (created bool, note string, err error) {
	v.ID, v.Service, v.Title = strings.TrimSpace(v.ID), strings.TrimSpace(v.Service), strings.TrimSpace(v.Title)
	v.Evidence, v.Remediation = strings.TrimSpace(v.Evidence), strings.TrimSpace(v.Remediation)
	switch {
	case !vulnIDRe.MatchString(v.ID):
		return false, "", errors.New("id must be 2-63 lowercase letters, digits and dashes, stable for this weakness (e.g. juice-shop-ctf-key-readable)")
	case v.Service == "":
		return false, "", errors.New(`service is required: a name from service_inventory, or "host" for the server as a whole`)
	case len(v.Title) < 10:
		return false, "", errors.New("title must say what is wrong")
	case !slices.Contains([]string{"low", "medium", "high", "critical"}, v.Severity):
		return false, "", errors.New("severity must be low, medium, high or critical")
	case len(v.Evidence) < 20:
		return false, "", errors.New("evidence must show what you observed (the command and its output, the file and the line)")
	case len(v.Remediation) < 20:
		return false, "", errors.New("remediation must say how to fix it: the command, the setting, the version to move to")
	}
	if v.Category == "" {
		v.Category = "other"
	}
	if !slices.Contains(VulnCategories, v.Category) {
		return false, "", fmt.Errorf("category must be one of %s", strings.Join(VulnCategories, ", "))
	}
	for i, id := range v.CVEs {
		v.CVEs[i] = strings.ToUpper(strings.TrimSpace(id))
		if !cveRe.MatchString(v.CVEs[i]) {
			return false, "", fmt.Errorf("%q is not a CVE or GHSA id", id)
		}
	}
	var ok bool
	var out string
	if len(v.Check) > 0 && string(v.Check) != "null" {
		if ok, out, err = c.probe(ctx, v); err != nil {
			return false, "", err
		}
		if ok {
			return false, "", fmt.Errorf("the check passes now (%s), so it does not show the vulnerability: write one that fails while the weakness exists and passes once it is fixed, or report without a check", out)
		}
	} else {
		v.Check = nil
	}
	if created, err = c.Store.PutVulnerability(&v, by); err != nil {
		return false, "", err
	}
	if v.Check != nil {
		c.Store.RecordVulnerabilityCheck(v.ID, false, out)
		note = " Its check fails now as it should (" + out + "); kodeblue reruns it and resolves the vulnerability once it passes."
	} else {
		note = " It has no check: it stays open until an agent confirms the fix with vulnerability_resolve or a human accepts the risk on the hub."
	}
	return created, note, nil
}

// Resolve marks a vulnerability fixed. One with a check is resolved only when
// the check passes; one without needs a note saying how the fix was
// confirmed.
func (c VulnContext) Resolve(ctx context.Context, id, by, note string) (string, error) {
	v := c.Store.GetVulnerability(id)
	if v == nil {
		return "", fmt.Errorf("no vulnerability %q", id)
	}
	if v.Status == store.VulnResolved {
		return "already resolved", nil
	}
	note = strings.TrimSpace(note)
	if v.Check != nil {
		ok, out, err := c.probe(ctx, *v)
		if err != nil {
			return "", err
		}
		c.Store.RecordVulnerabilityCheck(id, ok, out)
		if !ok {
			return "", fmt.Errorf("its check still fails (%s): the vulnerability is not fixed", out)
		}
		if note == "" {
			note = "its check passes: " + out
		}
	} else if len(note) < 20 {
		return "", errors.New("note must say how you confirmed the fix (the command and what it showed)")
	}
	if err := c.Store.SetVulnerabilityStatus(id, store.VulnResolved, by, note); err != nil {
		return "", err
	}
	return "resolved " + id, nil
}

// Recheck reruns every vulnerability's check, without a model. An open one
// whose check passes is resolved; a resolved one whose check fails again is
// reopened. An accepted risk only records the outcome: a human owns it.
func (c VulnContext) Recheck(ctx context.Context) (resolved, reopened []store.Vulnerability) {
	for _, v := range c.Store.Vulnerabilities(`WHERE check_spec<>'' ORDER BY id`) {
		if ctx.Err() != nil {
			return
		}
		switch got, _ := c.recheck(ctx, v); got {
		case store.VulnResolved:
			resolved = append(resolved, v)
		case store.VulnOpen:
			reopened = append(reopened, v)
		}
	}
	return
}

// RecheckOne reruns one vulnerability's check and says what it found.
func (c VulnContext) RecheckOne(ctx context.Context, id string) (string, error) {
	v := c.Store.GetVulnerability(id)
	switch {
	case v == nil:
		return "", fmt.Errorf("no vulnerability %q", id)
	case v.Check == nil:
		return "", fmt.Errorf("%s has no check kodeblue can run; an agent has to confirm the fix", id)
	}
	changed, out := c.recheck(ctx, *v)
	switch {
	case changed == store.VulnResolved:
		return "fixed: its check passes now (" + out + "), so it is resolved", nil
	case changed == store.VulnOpen:
		return "vulnerable again: its check fails (" + out + "), so it was reopened", nil
	case c.Store.GetVulnerability(id).CheckOK:
		return "its check passes (" + out + ")", nil
	}
	return "still vulnerable: its check fails (" + out + ")", nil
}

// recheck runs v's check, records the outcome and moves v to the status it
// calls for. It returns the new status when it changed.
func (c VulnContext) recheck(ctx context.Context, v store.Vulnerability) (changed, output string) {
	ok, out, err := c.probe(ctx, v)
	if err != nil {
		c.Store.RecordVulnerabilityCheck(v.ID, false, "check could not run: "+err.Error())
		return "", "check could not run: " + err.Error()
	}
	c.Store.RecordVulnerabilityCheck(v.ID, ok, out)
	switch {
	case ok && v.Status == store.VulnOpen:
		if c.Store.SetVulnerabilityStatus(v.ID, store.VulnResolved, "kodeblue", "its check passes now: "+out) == nil {
			return store.VulnResolved, out
		}
	case !ok && v.Status == store.VulnResolved:
		if c.Store.SetVulnerabilityStatus(v.ID, store.VulnOpen, "kodeblue", "its check fails again: "+out) == nil {
			return store.VulnOpen, out
		}
	}
	return "", out
}
