package daemon

import (
	"encoding/json"

	"github.com/Problem99-io/kodeblue/internal/blue/monitor"
	"github.com/Problem99-io/kodeblue/internal/blue/reqtap"
)

// seedRequestMonitors guarantees a floor of request-log detection on the tap
// log, whatever the learner model happened to create. The learner is asked
// to tune per-app monitors (logins, admin endpoints) on top; these three are
// the universal ones, so an attack is caught even when a small learner model
// builds a thin set. They use fixed ids, so a relearn refreshes them in
// place rather than piling up.
func (d *Daemon) seedRequestMonitors() {
	var st TapStatus
	if json.Unmarshal([]byte(d.st.Get(TapStatusKey)), &st); st.Status != "ok" {
		return // no tap here: request monitors rely on the app's own log, which the learner wires up
	}
	dir := d.cfg.RequestsDir()
	client := `^(\S+)`
	known := []string{} // nothing pre-trusted: the first login from any client alerts once (the learner tunes this per app)
	specs := []monitor.Spec{
		{
			ID: "kb-requests-error-bursts", Kind: "log", Severity: "high",
			Description: "A burst of 4xx/5xx responses to one client in kodeblue's request log.",
			Rationale:   "Credential guessing, authz probing and endpoint enumeration show as many error responses from one client even when each request looks ordinary.",
			Path:        dir, FilePattern: `^` + reqtap.LogName + `$`, GroupBy: client,
			Pattern: `"[A-Z]+ [^"]*" [45][0-9][0-9] `, Threshold: 15, WindowSeconds: 600,
			IntervalSeconds: 30, ConsecutiveFailures: 1,
		},
		{
			ID: "kb-requests-attack-text", Kind: "log", Severity: "high",
			Description: "A request in kodeblue's request log carrying attack text.",
			Rationale:   "Injection, traversal and attempts to read secrets through the app run inside the service and show only in the request line.",
			Path:        dir, FilePattern: `^` + reqtap.LogName + `$`, GroupBy: client,
			Pattern:         `(?i)"[A-Z]+ [^"]*(\.\./|%2e%2e|union[\s+]+select|' or |sleep\(|\{\{|\$\{|<%|\$\(|` + "`" + `|/bin/|eval\(|require\(|\.env\b|\.git/|/etc/passwd|%00)`,
			Threshold:       1,
			IntervalSeconds: 30, ConsecutiveFailures: 1,
		},
		{
			ID: "kb-requests-new-login", Kind: "log", Severity: "high",
			Description: "A successful authentication from a client the request log has not shown before.",
			Rationale:   "A valid login, token issue or account creation from a new client is the clearest sign an attacker got in with stolen or guessed credentials; it is the one app-layer signal that does not depend on where the payload sits.",
			Path:        dir, FilePattern: `^` + reqtap.LogName + `$`, GroupBy: client,
			Pattern:   `(?i)"(POST|PUT) [^"]*(login|signin|session|token|oauth|auth|register|signup|/users?)[^"]*" (200|201) `,
			NewValues: true, KnownValues: &known,
			IntervalSeconds: 30, ConsecutiveFailures: 1,
		},
		{
			ID: "kb-requests-scanner-ua", Kind: "log", Severity: "high",
			Description: "A request in kodeblue's request log from a known attack tool's user agent.",
			Rationale:   "Automated scanners and exploitation tools identify themselves in the user agent; a hit means active scanning.",
			Path:        dir, FilePattern: `^` + reqtap.LogName + `$`, GroupBy: client,
			Pattern:         `(?i)"(sqlmap|nikto|nmap|masscan|zgrab|dirbuster|gobuster|dirb|feroxbuster|ffuf|wfuzz|nuclei|acunetix|nessus|openvas|burp|zaproxy|wpscan|hydra|metasploit)`,
			Threshold:       1,
			IntervalSeconds: 30, ConsecutiveFailures: 1,
		},
	}
	for _, s := range specs {
		if err := s.Validate(); err != nil {
			d.log.Error("seed request monitor invalid", "id", s.ID, "error", err)
			continue
		}
		b, _ := json.Marshal(s)
		if err := d.st.PutMonitor(s.ID, b, "kodeblue"); err != nil {
			d.log.Error("seed request monitor failed", "id", s.ID, "error", err)
		}
	}
	d.log.Info("seeded baseline request monitors on the tap log", "dir", dir)
}
