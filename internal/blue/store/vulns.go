package store

import (
	"encoding/json"
	"fmt"
	"time"
)

// Vulnerability states. Open needs fixing; Resolved was fixed (its check
// passes, or someone confirmed the fix); Accepted is a risk a human decided
// to live with.
const (
	VulnOpen     = "open"
	VulnResolved = "resolved"
	VulnAccepted = "accepted"
)

const vulnSchema = `CREATE TABLE IF NOT EXISTS vulnerabilities (
  id TEXT PRIMARY KEY, service TEXT NOT NULL, title TEXT NOT NULL, severity TEXT NOT NULL, category TEXT NOT NULL DEFAULT '',
  cves TEXT NOT NULL DEFAULT '[]', evidence TEXT NOT NULL DEFAULT '', remediation TEXT NOT NULL DEFAULT '', check_spec TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'open', status_by TEXT NOT NULL DEFAULT '', status_note TEXT NOT NULL DEFAULT '', found_by TEXT NOT NULL,
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, resolved_at INTEGER NOT NULL DEFAULT 0,
  checked_at INTEGER NOT NULL DEFAULT 0, check_ok INTEGER NOT NULL DEFAULT 0, check_output TEXT NOT NULL DEFAULT '')`

// Vulnerability is a weakness found on the server that someone can fix: an
// outdated package with known CVEs, a misconfiguration, an exposed secret.
// Service names the service from the inventory it belongs to ("host" for
// the server as a whole). Check, when set, is a monitor spec that passes
// once the vulnerability is fixed, so kodeblue can tell by itself.
type Vulnerability struct {
	ID          string          `json:"id"`
	Service     string          `json:"service"`
	Title       string          `json:"title"`
	Severity    string          `json:"severity"`
	Category    string          `json:"category,omitempty"`
	CVEs        []string        `json:"cves,omitempty"`
	Evidence    string          `json:"evidence,omitempty"`
	Remediation string          `json:"remediation,omitempty"`
	Check       json.RawMessage `json:"check,omitempty"`
	Status      string          `json:"status"`
	StatusBy    string          `json:"status_by,omitempty"`
	StatusNote  string          `json:"status_note,omitempty"`
	FoundBy     string          `json:"found_by"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
	ResolvedAt  time.Time       `json:"resolved_at,omitzero"`
	CheckedAt   time.Time       `json:"checked_at,omitzero"`
	CheckOK     bool            `json:"check_ok"`
	CheckOutput string          `json:"check_output,omitempty"`
}

// PutVulnerability records v, or updates the one with its id. An update
// keeps the status, unless the vulnerability was resolved: reported again,
// it is open again.
func (s *Store) PutVulnerability(v *Vulnerability, by string) (created bool, err error) {
	cves, _ := json.Marshal(v.CVEs)
	if v.CVEs == nil {
		cves = []byte("[]")
	}
	now := time.Now().Unix()
	old := s.GetVulnerability(v.ID)
	if old == nil {
		_, err = s.db.Exec(`INSERT INTO vulnerabilities(id,service,title,severity,category,cves,evidence,remediation,check_spec,status,found_by,created_at,updated_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, v.ID, v.Service, v.Title, v.Severity, v.Category, string(cves), v.Evidence, v.Remediation, string(v.Check), VulnOpen, by, now, now)
		if err == nil {
			s.Journal(by, "vulnerability.add", fmt.Sprintf("%s [%s] %s: %s", v.ID, v.Severity, v.Service, v.Title))
		}
		return err == nil, err
	}
	status, resolvedAt := old.Status, int64(0)
	if !old.ResolvedAt.IsZero() {
		resolvedAt = old.ResolvedAt.Unix()
	}
	if status == VulnResolved {
		status, resolvedAt = VulnOpen, 0
	}
	_, err = s.db.Exec(`UPDATE vulnerabilities SET service=?,title=?,severity=?,category=?,cves=?,evidence=?,remediation=?,check_spec=?,status=?,resolved_at=?,updated_at=? WHERE id=?`,
		v.Service, v.Title, v.Severity, v.Category, string(cves), v.Evidence, v.Remediation, string(v.Check), status, resolvedAt, now, v.ID)
	if err == nil {
		s.Journal(by, "vulnerability.update", fmt.Sprintf("%s [%s] %s", v.ID, v.Severity, status))
	}
	return false, err
}

// SetVulnerabilityStatus moves a vulnerability to status, saying who did
// and why.
func (s *Store) SetVulnerabilityStatus(id, status, by, note string) error {
	var resolved int64
	if status == VulnResolved {
		resolved = time.Now().Unix()
	}
	res, err := s.db.Exec(`UPDATE vulnerabilities SET status=?,status_by=?,status_note=?,resolved_at=?,updated_at=? WHERE id=?`,
		status, by, note, resolved, time.Now().Unix(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("no vulnerability %q", id)
	}
	s.Journal(by, "vulnerability."+status, fmt.Sprintf("%s: %s", id, note))
	return nil
}

// RecordVulnerabilityCheck stores the outcome of a vulnerability's check.
// It touches updated_at only when the outcome changed, so an unchanged
// recheck does not make the hub sync the row again.
func (s *Store) RecordVulnerabilityCheck(id string, ok bool, output string) {
	okI := 0
	if ok {
		okI = 1
	}
	now := time.Now().Unix()
	_, _ = s.db.Exec(`UPDATE vulnerabilities SET checked_at=?, updated_at=CASE WHEN check_ok<>? OR check_output<>? THEN ? ELSE updated_at END,
check_ok=?, check_output=? WHERE id=?`, now, okI, output, now, okI, output, id)
}

func (s *Store) GetVulnerability(id string) *Vulnerability {
	l := s.Vulnerabilities(`WHERE id=?`, id)
	if len(l) == 0 {
		return nil
	}
	return &l[0]
}

// Vulnerabilities lists vulnerabilities matching where (e.g. `WHERE status=?`).
func (s *Store) Vulnerabilities(where string, args ...any) []Vulnerability {
	rows, err := s.db.Query(`SELECT id,service,title,severity,category,cves,evidence,remediation,check_spec,status,status_by,status_note,found_by,
created_at,updated_at,resolved_at,checked_at,check_ok,check_output FROM vulnerabilities `+where, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Vulnerability
	for rows.Next() {
		var v Vulnerability
		var cves, check string
		var c, u, r, ch int64
		var ok int
		if err := rows.Scan(&v.ID, &v.Service, &v.Title, &v.Severity, &v.Category, &cves, &v.Evidence, &v.Remediation, &check, &v.Status, &v.StatusBy,
			&v.StatusNote, &v.FoundBy, &c, &u, &r, &ch, &ok, &v.CheckOutput); err != nil {
			continue
		}
		_ = json.Unmarshal([]byte(cves), &v.CVEs)
		if check != "" {
			v.Check = json.RawMessage(check)
		}
		v.CreatedAt, v.UpdatedAt = time.Unix(c, 0), time.Unix(u, 0)
		if r > 0 {
			v.ResolvedAt = time.Unix(r, 0)
		}
		if ch > 0 {
			v.CheckedAt = time.Unix(ch, 0)
		}
		v.CheckOK = ok == 1
		out = append(out, v)
	}
	return out
}

// VulnerabilityCounts is open vulnerabilities per service and severity.
func (s *Store) VulnerabilityCounts() map[string]map[string]int {
	out := map[string]map[string]int{}
	rows, err := s.db.Query(`SELECT service, severity, COUNT(*) FROM vulnerabilities WHERE status=? GROUP BY service, severity`, VulnOpen)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var svc, sev string
		var n int
		if rows.Scan(&svc, &sev, &n) == nil {
			if out[svc] == nil {
				out[svc] = map[string]int{}
			}
			out[svc][sev] = n
		}
	}
	return out
}
