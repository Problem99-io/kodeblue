package mcpserver

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/config"
	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
	"github.com/Problem99-io/kodeblue/internal/blue/notify"
	"github.com/Problem99-io/kodeblue/internal/blue/respond"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

func (s *Server) respond(ctx context.Context, args json.RawMessage) (string, error) {
	var a struct {
		IncidentID    int64             `json:"incident_id"`
		Action        string            `json:"action"`
		Params        map[string]string `json:"params"`
		Justification string            `json:"justification"`
	}
	if err := decode(args, &a); err != nil {
		return "", err
	}
	in := s.st.GetIncident(a.IncidentID)
	if in == nil || in.Kind != "incident" {
		return "", fmt.Errorf("incident %d not found", a.IncidentID)
	}
	if a.Params == nil {
		a.Params = map[string]string{}
	}
	delete(a.Params, "incident_linked") // computed here, never taken from the model
	findings := s.st.FindingsForIncident(a.IncidentID)
	switch a.Action {
	case "kill_process":
		for _, f := range findings {
			if (a.Params["pid"] != "" && f.Evidence["pid"] == a.Params["pid"]) || (a.Params["expect_exe"] != "" && strings.HasPrefix(f.ItemID, "process|"+a.Params["expect_exe"]+"@")) {
				a.Params["incident_linked"] = "true"
			}
		}
	case "quarantine_file":
		path := a.Params["path"]
		// An authorized_keys file of a protected or baseline administrator is
		// never quarantined, however suspicious the path looks: removing it
		// locks the real admins out. The root helper's Check enforces the
		// same rule; this one explains it to the agent.
		if user, why := respond.AdminKeyFile(s.cfg.Response, path); why != "" {
			return "", fmt.Errorf("%s is %s's authorized_keys; %s — an agent may not quarantine it (disable the specific planted key instead, or recommend it to a human)", path, user, why)
		}
		suspicious := strings.HasPrefix(path, "/tmp/") || strings.HasPrefix(path, "/var/tmp/") || strings.HasPrefix(path, "/dev/shm/") || strings.Contains(path, "/.")
		linked := false
		for _, f := range findings {
			if strings.HasSuffix(f.ItemID, "|"+path) || strings.Contains(f.ItemID, "|"+path+"@") || strings.Contains(f.Title, path) {
				linked = true
			}
		}
		if !suspicious && !linked {
			for _, b := range s.st.QueryBaseline("", path, 5) {
				if b.Key == path {
					return "", errors.New(path + " is part of the learned baseline (known-good); an agent may not quarantine it. Recommend it to a human if you have evidence it was tampered with")
				}
			}
			for _, f := range s.st.FindingsByStatus("needs_ack", 100) {
				if strings.Contains(f.ItemID, "|"+path) {
					return "", errors.New(path + " was judged benign by triage and is awaiting an operator's decision; an agent may not quarantine it. Mention it in your report instead")
				}
			}
		}
	case "disable_ssh_key":
		id := "ssh_key|" + a.Params["user"] + "/" + a.Params["key_id"]
		if items := s.st.QueryBaseline("ssh_key", a.Params["user"]+"/"+a.Params["key_id"], 1); len(items) > 0 && items[0].ID == id && (items[0].Source == "learned" || items[0].Source == "operator") {
			return "", errors.New("this key was part of the learned baseline (a legitimate admin key); an agent may not disable it — recommend it to a human")
		}
	}
	req := respond.Request{ID: respond.NewID(), IncidentID: a.IncidentID, Action: a.Action, Params: a.Params, Justification: a.Justification, RequestedBy: "agent", RequestedAt: time.Now()}
	return Submit(ctx, s.cfg, s.st, s.slack, req)
}

// RateLimited enforces the containment rate limit in effect before an
// action runs. The root helper enforces its own max_actions_per_hour; a
// lower one the hub set exists only here, so every path to the helper (an
// automatic action, an operator's approval) checks it.
func RateLimited(cfg config.Config) error {
	limit := cfg.Response.MaxActionsPerHour
	if n := respond.ActionsLastHour(cfg.Response.StateDir); limit > 0 && n >= limit {
		return fmt.Errorf("rate limit: %d containment actions in the last hour (the limit is %d)", n, limit)
	}
	return nil
}

// Submit puts a containment request through policy: refused when response is
// off or the action is turned off, recorded for an operator's approval when
// the action needs one, otherwise run by the root helper. The responder's
// respond tool and the daemon's monitor reflexes both go through here, so
// they obey the same rules.
func Submit(ctx context.Context, cfg config.Config, st *store.Store, slack notify.Sender, req respond.Request) (string, error) {
	pol := cfg.Response
	if pol.Mode == "off" {
		return "", errors.New("response is disabled by policy (mode=off); put the action in your report as a recommendation")
	}
	if err := respond.Check(pol, req); err != nil {
		return "", err
	}
	rule := cfg.ActionRule(req.Action)
	if rule == hubproto.ActionOff {
		return "", fmt.Errorf("the operators turned %s off for this server; put it in your report as a recommendation", req.Action)
	}
	actor := "agent"
	if strings.HasPrefix(req.RequestedBy, "monitor:") {
		actor = req.RequestedBy
	}
	if rule != hubproto.ActionAuto {
		// Concurrent incidents often ask for the same thing; one request (or
		// one completed action) per target is enough for the operator.
		for _, r := range respond.Load(pol.StateDir) {
			if r.Action == req.Action && r.Status == "done" && respond.SameTarget(r.Params, req.Params) {
				return fmt.Sprintf("Already done as %s (%s). No new request needed.", r.ID, r.Result), nil
			}
		}
		for _, r := range LoadRequests(cfg) {
			if r.Action == req.Action && respond.SameTarget(r.Params, req.Params) {
				return fmt.Sprintf("Already requested as %s (incident #%d) and waiting for operator approval: kodeblue respond approve %s. Mention it in your report.", r.ID, r.IncidentID, r.ID), nil
			}
		}
		if err := AppendRequest(cfg, req); err != nil {
			return "", err
		}
		st.Journal(actor, "respond.request", fmt.Sprintf("%s %s %v (incident #%d)", req.ID, req.Action, req.Params, req.IncidentID))
		announceAction(cfg, slack, req, "awaiting approval", "Run on the server: kodeblue respond approve "+req.ID, nil)
		return fmt.Sprintf("Recorded as %s, awaiting operator approval (%s needs approval on this server). An operator approves it in the hub or runs: kodeblue respond approve %s. Mention it in your report.", req.ID, req.Action, req.ID), nil
	}
	if err := RateLimited(cfg); err != nil {
		return "", fmt.Errorf("%w; put it in your report as a recommendation", err)
	}
	rec, err := runHelper(ctx, cfg, req)
	if err != nil {
		return "", err
	}
	st.Journal(actor, "respond."+rec.Status, fmt.Sprintf("%s %s: %s", req.ID, req.Action, rec.Result))
	announceAction(cfg, slack, req, rec.Status, rec.Result, rec.Undo)
	return fmt.Sprintf("%s: %s — %s", req.ID, rec.Status, rec.Result), nil
}

func (s *Server) responseList(ctx context.Context, args json.RawMessage) (string, error) {
	return jsonOut(map[string]any{"executed": respond.Load(s.cfg.Response.StateDir), "pending": LoadRequests(s.cfg)}), nil
}

func (s *Server) notifySlack(ctx context.Context, args json.RawMessage) (string, error) {
	var a struct {
		Severity   string `json:"severity"`
		Title      string `json:"title"`
		Message    string `json:"message"`
		IncidentID int64  `json:"incident_id"`
	}
	if err := decode(args, &a); err != nil {
		return "", err
	}
	if !notify.Enabled(s.slack) {
		return "", errors.New("Slack is not configured for this server (no kodeblue hub and no notify.slack_webhook_file); put the update in your report instead")
	}
	switch a.Severity {
	case "info", "low", "medium", "high", "critical":
	default:
		return "", errors.New("severity must be info|low|medium|high|critical")
	}
	if strings.TrimSpace(a.Title) == "" || len(strings.TrimSpace(a.Message)) < 10 {
		return "", errors.New("title and a real message are required")
	}
	limit := s.cfg.Notify.AgentMessagesPerHour
	if limit <= 0 {
		limit = 20
	}
	sent := 0
	for _, j := range s.st.JournalSince(time.Now().Add(-time.Hour), 500) {
		if j.Action == "slack.agent" {
			sent++
		}
	}
	if sent >= limit {
		return "", fmt.Errorf("Slack rate limit reached (%d agent messages/hour); include this in your report instead", limit)
	}
	fields := map[string]string{}
	if a.IncidentID > 0 {
		fields["Incident"] = fmt.Sprintf("#%d (kodeblue incident %d)", a.IncidentID, a.IncidentID)
	}
	if err := s.slack.Send(ctx, notify.Message{Server: s.cfg.Server.Name, Kind: "agent", Severity: a.Severity, Title: a.Title, Body: a.Message, Fields: fields, IncidentID: a.IncidentID}); err != nil {
		return "", err
	}
	s.st.Journal("agent", "slack.agent", fmt.Sprintf("incident=%d %s: %s", a.IncidentID, a.Severity, a.Title))
	if notify.ViaHub(s.slack) {
		return "sent: the kodeblue hub posts it to the team's Slack channel", nil
	}
	return "posted to Slack", nil
}

// announceAction posts every containment action to Slack, whatever the agent
// remembers to say: humans must always know when kodeblue touched the host.
func announceAction(cfg config.Config, slack notify.Sender, req respond.Request, status, result string, undo map[string]string) {
	sev := "high"
	if status == "refused" || status == "failed" {
		sev = "medium"
	}
	params, _ := json.Marshal(req.Params)
	slack.Async(notify.Message{
		Server: cfg.Server.Name, Kind: "action", Severity: sev, IncidentID: req.IncidentID,
		Title:  fmt.Sprintf("Containment %s: %s", status, req.Action),
		Body:   fmt.Sprintf("%s\nJustification: %s", result, req.Justification),
		Fields: actionFields(req, status, string(params), undo),
	}, nil)
}

// actionFields are an action notice's fields. Only a completed action that
// can be undone gets an undo command: a pending, refused or failed one has
// nothing to undo, a request answered by an earlier action ("already done",
// no recipe of its own) is undone by that action's id, and a killed process
// cannot be revived, so its notice says where the binary was kept instead.
func actionFields(req respond.Request, status, params string, undo map[string]string) map[string]string {
	fields := map[string]string{"Incident": fmt.Sprintf("#%d", req.IncidentID), "Action id": req.ID, "Params": params}
	if status != "done" || len(undo) == 0 {
		return fields
	}
	if !respond.Undoable(req.Action) {
		fields["Undo"] = "not possible: a killed process cannot be revived"
		if dir := undo["evidence"]; dir != "" {
			fields["Binary"] = "preserved for forensics in " + dir
		} else {
			fields["Binary"] = "could not be preserved"
		}
		return fields
	}
	fields["Undo"] = "kodeblue respond undo " + req.ID
	return fields
}

func requestsPath(cfg config.Config) string {
	return filepath.Join(cfg.Server.StateDir, "response-requests.jsonl")
}

// AppendRequest records r as waiting for an operator's approval.
func AppendRequest(cfg config.Config, r respond.Request) error {
	f, err := os.OpenFile(requestsPath(cfg), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	defer f.Close()
	b, _ := json.Marshal(r)
	_, err = f.Write(append(b, '\n'))
	return err
}

func deniedPath(cfg config.Config) string {
	return filepath.Join(cfg.Server.StateDir, "response-denied.jsonl")
}

// Denial is an operator's "no" to a pending containment request.
type Denial struct {
	ID       string    `json:"id"`
	DeniedBy string    `json:"denied_by"`
	DeniedAt time.Time `json:"denied_at"`
}

// DenyRequest settles a pending request without running it.
func DenyRequest(cfg config.Config, id, by string) error {
	f, err := os.OpenFile(deniedPath(cfg), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	defer f.Close()
	b, _ := json.Marshal(Denial{ID: id, DeniedBy: by, DeniedAt: time.Now().UTC()})
	_, err = f.Write(append(b, '\n'))
	return err
}

func deniedIDs(cfg config.Config) map[string]bool {
	out := map[string]bool{}
	f, err := os.Open(deniedPath(cfg))
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var d Denial
		if json.Unmarshal(sc.Bytes(), &d) == nil && d.ID != "" {
			out[d.ID] = true
		}
	}
	return out
}

// FindRequest returns the pending request with this id, or nil.
func FindRequest(cfg config.Config, id string) *respond.Request {
	for _, r := range LoadRequests(cfg) {
		if r.ID == id {
			return &r
		}
	}
	return nil
}

// LoadRequests returns requests not yet executed or denied.
func LoadRequests(cfg config.Config) []respond.Request {
	f, err := os.Open(requestsPath(cfg))
	if err != nil {
		return nil
	}
	defer f.Close()
	done := deniedIDs(cfg)
	executed := respond.Load(cfg.Response.StateDir)
	for _, r := range executed {
		done[r.ID] = true
	}
	// A request is settled when it ran, or when the same action on the same
	// target already ran (an approved twin from a concurrent incident) or is
	// already listed.
	settled := func(r respond.Request, listed []respond.Request) bool {
		if done[r.ID] {
			return true
		}
		for _, e := range executed {
			if e.Action == r.Action && e.Status == "done" && respond.SameTarget(e.Params, r.Params) {
				return true
			}
		}
		for _, l := range listed {
			if l.Action == r.Action && respond.SameTarget(l.Params, r.Params) {
				return true
			}
		}
		return false
	}
	var out []respond.Request
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var r respond.Request
		if json.Unmarshal(sc.Bytes(), &r) == nil && !settled(r, out) {
			out = append(out, r)
		}
	}
	return out
}

// runHelper hands the request to the root helper (systemd socket, or sudo).
// The helper re-reads policy from the root-owned config, so nothing here can
// widen it.
func runHelper(ctx context.Context, cfg config.Config, req respond.Request) (*respond.Record, error) {
	payload, _ := json.Marshal(map[string]any{"op": "execute", "request": req})
	out, err := respond.Invoke(ctx, cfg.Path(), payload)
	if err != nil {
		return nil, err
	}
	var rec respond.Record
	if err := json.Unmarshal(out, &rec); err != nil {
		return nil, fmt.Errorf("helper output: %s", strings.TrimSpace(string(out)))
	}
	return &rec, nil
}

// RunHelper is exported for the CLI's approve path.
func RunHelper(ctx context.Context, cfg config.Config, req respond.Request) (*respond.Record, error) {
	return runHelper(ctx, cfg, req)
}

// IncidentDecisions sums up the containment an incident's agent asked for:
// how many requests still wait for an operator, and one line per settled
// one (ran, failed, denied), oldest first. Targets, results and names come
// from the host and the hub: they are quoted, never trusted.
type IncidentDecisions struct {
	Pending int
	Settled []string
}

// Decisions returns IncidentDecisions for every incident with containment
// requests, reading the request, denial and action files once. The daemon
// hands the settled lines back to an agent once nothing of its waits.
func Decisions(cfg config.Config) map[int64]*IncidentDecisions {
	out := map[int64]*IncidentDecisions{}
	get := func(id int64) *IncidentDecisions {
		if out[id] == nil {
			out[id] = &IncidentDecisions{}
		}
		return out[id]
	}
	open := map[string]bool{}
	for _, r := range LoadRequests(cfg) {
		get(r.IncidentID).Pending++
		open[r.ID] = true
	}
	denied := map[string]Denial{}
	if f, err := os.Open(deniedPath(cfg)); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			var d Denial
			if json.Unmarshal(sc.Bytes(), &d) == nil && d.ID != "" {
				denied[d.ID] = d
			}
		}
		f.Close()
	}
	target := func(p map[string]string) string {
		var parts []string
		for _, k := range []string{"ip", "user", "unit", "pid", "path", "key_id"} {
			if v := p[k]; v != "" {
				parts = append(parts, k+"="+strconv.Quote(v))
			}
		}
		return strings.Join(parts, " ")
	}
	ran := map[string]bool{}
	for _, e := range respond.Load(cfg.Response.StateDir) {
		ran[e.ID] = true
		// Only what an operator approved: the agent saw the result of
		// actions it ran itself.
		by, ok := strings.CutSuffix(e.RequestedBy, "+operator")
		if !ok || e.Status == "pending" || denied[e.ID].ID != "" {
			continue
		}
		who := "an operator on the server"
		if i := strings.Index(by, "+hub:"); i >= 0 {
			who = strconv.Quote(clipLine(by[i+len("+hub:"):], 80)) + " on the hub"
		}
		d := get(e.IncidentID)
		d.Settled = append(d.Settled, fmt.Sprintf("%s %s: approved by %s; helper status %s; result %s", e.Action, target(e.Params), who, e.Status, strconv.Quote(clipLine(e.Result, 240))))
	}
	if f, err := os.Open(requestsPath(cfg)); err == nil {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			var r respond.Request
			if json.Unmarshal(sc.Bytes(), &r) != nil || open[r.ID] {
				continue
			}
			if d, ok := denied[r.ID]; ok {
				get(r.IncidentID).Settled = append(get(r.IncidentID).Settled, fmt.Sprintf("%s %s: denied by %s", r.Action, target(r.Params), strconv.Quote(clipLine(d.DeniedBy, 80))))
			} else if !ran[r.ID] {
				get(r.IncidentID).Settled = append(get(r.IncidentID).Settled, fmt.Sprintf("%s %s: already in effect (the same action on the same target ran for another request)", r.Action, target(r.Params)))
			}
		}
		f.Close()
	}
	return out
}

func clipLine(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
