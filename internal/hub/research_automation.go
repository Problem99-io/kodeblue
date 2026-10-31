package hub

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
	"github.com/Problem99-io/kodeblue/internal/research"
)

type researchAutoConfig struct {
	Worker     string `json:"worker"`
	Suspicious bool   `json:"auto_suspicious"`
	Daily      bool   `json:"daily_report"`
	Hour       int    `json:"daily_hour"`
	Scope      string `json:"scope"`
	UpdatedBy  string `json:"updated_by"`
}

type researchAutoState struct {
	Day        string `json:"day"`
	Sensitive  int64  `json:"sensitive_baseline"`
	Runs       int    `json:"suspicious_runs"`
	LastSus    int64  `json:"last_investigation_at"`
	NextSus    int64  `json:"next_suspicious_check"`
	SusError   string `json:"suspicious_error,omitempty"`
	DailyDay   string `json:"last_daily_report"`
	NextDaily  int64  `json:"next_daily_attempt"`
	DailyError string `json:"daily_error,omitempty"`
}

type researchAutoRecord struct {
	Site    string
	Version int64
	Config  researchAutoConfig
	State   researchAutoState
}
type researchAutoClaim struct {
	Version int64
	Day     string
	Count   int64
	At      time.Time
}

func researchScope(site research.Site) string {
	sources := append([]string(nil), site.Servers...)
	slices.Sort(sources)
	origins := append([]string(nil), site.Origins...)
	slices.Sort(origins)
	paths := append([]string(nil), site.BrowserPaths...)
	slices.Sort(paths)
	b, _ := json.Marshal([]any{site.ID, site.Timezone, sources, origins, paths, site.BrowserEnabled})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func readResearchAuto(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, site string) (researchAutoRecord, error) {
	p := researchAutoRecord{Site: site, Config: researchAutoConfig{Hour: 8}}
	var config, state string
	err := q.QueryRowContext(ctx, "SELECT version,config,state FROM research_automation WHERE site=?", site).Scan(&p.Version, &config, &state)
	if err != nil {
		return p, err
	}
	if err = json.Unmarshal([]byte(config), &p.Config); err == nil {
		err = json.Unmarshal([]byte(state), &p.State)
	}
	return p, err
}

func (s *Server) researchAutoRoutes() {
	s.mux.HandleFunc("GET /api/research/sites/{site}/automation", s.op(s.handleResearchAutoGet))
	s.mux.HandleFunc("PUT /api/research/sites/{site}/automation", s.op(s.handleResearchAutoPut))
}

func (s *Server) handleResearchAutoGet(w http.ResponseWriter, r *http.Request, c *opCtx) {
	if !s.researchEnabled(w) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	site, err := s.opt.Research.Site(ctx, r.PathValue("site"))
	if err != nil {
		s.researchError(w, err)
		return
	}
	p, err := readResearchAuto(ctx, s.st.db, site.ID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		s.researchError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"settings": p.Config, "state": p.State, "timezone": site.Timezone, "scope_changed": p.Version > 0 && p.Config.Scope != researchScope(site)})
}

func (s *Server) handleResearchAutoPut(w http.ResponseWriter, r *http.Request, c *opCtx) {
	if !s.researchEnabled(w) {
		return
	}
	var req struct {
		Worker     string `json:"worker"`
		Suspicious bool   `json:"auto_suspicious"`
		Daily      bool   `json:"daily_report"`
		Hour       *int   `json:"daily_hour"`
	}
	if researchJSON(w, r, 2048, &req) != nil {
		writeErr(w, 400, "invalid investigator automation settings")
		return
	}
	hour := 8
	if req.Hour != nil {
		hour = *req.Hour
	}
	if hour < 0 || hour > 23 {
		writeErr(w, 400, "daily hour must be between 0 and 23")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	site, err := s.opt.Research.Site(ctx, r.PathValue("site"))
	if err != nil {
		s.researchError(w, err)
		return
	}
	req.Worker = strings.TrimSpace(req.Worker)
	if req.Suspicious || req.Daily {
		worker := s.st.GetServer(req.Worker)
		if worker == nil || worker.Revoked || !worker.Enrolled || !slices.Contains(site.Servers, worker.ID) {
			writeErr(w, 403, "select an enrolled source from this site")
			return
		}
		var status hubproto.Status
		_ = json.Unmarshal(worker.Status, &status)
		if req.Suspicious && (!status.SupportsInvestigator || !status.AcceptsMessages) {
			writeErr(w, 409, "automatic investigation needs an updated worker accepting hub messages")
			return
		}
	}
	now := time.Now()
	zone, err := time.LoadLocation(site.Timezone)
	if err != nil {
		s.researchError(w, research.ErrInvalid)
		return
	}
	day := now.In(zone).Format("2006-01-02")
	var baseline int64
	if req.Suspicious {
		report, e := s.opt.Research.Daily(ctx, site.ID, day)
		if e != nil {
			s.researchError(w, e)
			return
		}
		baseline = report.SensitiveRequests
	}
	tx, err := s.st.db.BeginTx(ctx, nil)
	if err != nil {
		s.researchError(w, err)
		return
	}
	defer tx.Rollback()
	old, err := readResearchAuto(ctx, tx, site.ID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		s.researchError(w, err)
		return
	}
	if old.Version == 0 {
		var count int
		if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM research_automation").Scan(&count); err != nil || count >= 64 {
			writeErr(w, 409, "research automation configuration capacity reached")
			return
		}
	}
	state := old.State
	if req.Suspicious && (!old.Config.Suspicious || old.Config.Worker != req.Worker || old.Config.Scope != researchScope(site)) {
		if state.Day != day {
			state.Day = day
			state.Runs = 0
			state.Sensitive = 0
		}
		state.Sensitive = max(state.Sensitive, baseline) // enabling does not replay historical traffic
	}
	state.NextSus = 0
	state.NextDaily = 0
	state.SusError = ""
	state.DailyError = ""
	// Withdraw queued automatic grants when this option is switched off. A
	// delivered/running session remains under the normal Stop control.
	if !req.Suspicious {
		_, err = tx.ExecContext(ctx, `UPDATE messages SET status='refused',reply='Automatic investigation was disabled before dispatch.',replied_at=? WHERE status='queued' AND id IN(SELECT message_id FROM research_jobs WHERE site=? AND auto_kind='suspicious')`, now.Unix(), site.ID)
		if err != nil {
			s.researchError(w, err)
			return
		}
	}
	cfg := researchAutoConfig{Worker: req.Worker, Suspicious: req.Suspicious, Daily: req.Daily, Hour: hour, Scope: researchScope(site), UpdatedBy: c.user.Name}
	b, _ := json.Marshal(cfg)
	st, _ := json.Marshal(state)
	_, err = tx.ExecContext(ctx, `INSERT INTO research_automation(site,version,config,state) VALUES(?,1,?,?) ON CONFLICT(site) DO UPDATE SET version=version+1,config=excluded.config,state=excluded.state`, site.ID, string(b), string(st))
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		s.researchError(w, err)
		return
	}
	s.st.Audit(c.user.Name, "research.automation", req.Worker, fmt.Sprintf("site=%s suspicious=%t daily=%t hour=%d zone=%s", site.ID, req.Suspicious, req.Daily, hour, site.Timezone), c.ip)
	select {
	case s.researchAutoWake <- struct{}{}:
	default:
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) reserveResearchAuto(ctx context.Context, tx *sql.Tx, site research.Site, worker string, claim *researchAutoClaim) error {
	p, err := readResearchAuto(ctx, tx, site.ID)
	if err != nil {
		return err
	}
	if p.Version != claim.Version || !p.Config.Suspicious || p.Config.Worker != worker || p.Config.Scope != researchScope(site) {
		return researchDispatchProblem(409, "automatic investigation policy changed; no job queued")
	}
	state := p.State
	if state.Day != claim.Day {
		state.Day = claim.Day
		state.Sensitive = 0
		state.Runs = 0
	}
	if state.Runs >= 4 || state.LastSus > claim.At.Add(-time.Hour).Unix() || claim.Count-state.Sensitive < 20 {
		return researchDispatchProblem(409, "automatic investigation cooldown, daily cap or evidence threshold reached")
	}
	state.Sensitive = claim.Count
	state.Runs++
	state.LastSus = claim.At.Unix()
	state.NextSus = claim.At.Add(5 * time.Minute).Unix()
	state.SusError = ""
	b, _ := json.Marshal(state)
	_, err = tx.ExecContext(ctx, "UPDATE research_automation SET state=? WHERE site=? AND version=?", string(b), site.ID, claim.Version)
	return err // same transaction as the native message: no lost/duplicate reservation
}

func (s *Server) researchAutomationTick(ctx context.Context, now time.Time) {
	if s.opt.Research == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	rows, err := s.st.db.QueryContext(ctx, "SELECT site FROM research_automation ORDER BY site LIMIT 64")
	if err != nil {
		return
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	for _, id := range ids {
		if ctx.Err() != nil {
			return
		}
		p, e := readResearchAuto(ctx, s.st.db, id)
		if e != nil || (!p.Config.Suspicious && !p.Config.Daily) {
			continue
		}
		site, e := s.opt.Research.Site(ctx, id)
		if errors.Is(e, sql.ErrNoRows) {
			_, _ = s.st.db.ExecContext(ctx, "DELETE FROM research_automation WHERE site=? AND version=?", id, p.Version)
			continue
		}
		if e != nil {
			continue
		}
		if p.Config.Scope != researchScope(site) {
			s.researchAutoFailure(ctx, p, "scope", "Site scope changed; save automation settings to approve the current sources/timezone.", now)
			continue
		}
		zone, e := time.LoadLocation(site.Timezone)
		if e != nil {
			continue
		}
		local := now.In(zone)
		if p.Config.Daily && local.Hour() >= p.Config.Hour && now.Unix() >= p.State.NextDaily {
			date := researchDailyDate(local)
			if p.State.DailyDay != date {
				if e = s.queueDailyResearchOverview(ctx, site, p.Version, date, now); e != nil {
					s.researchAutoFailure(ctx, p, "daily", "Daily overview could not be queued; check the selected source and retry status.", now)
				}
			}
		}
		if !p.Config.Suspicious || now.Unix() < p.State.NextSus {
			continue
		}
		day := local.Format("2006-01-02")
		if p.State.LastSus > now.Add(-time.Hour).Unix() || (p.State.Day == day && p.State.Runs >= 4) {
			continue
		}
		report, e := s.opt.Research.Daily(ctx, id, day)
		if e != nil {
			s.researchAutoFailure(ctx, p, "suspicious", "Traffic counters are temporarily unavailable.", now)
			continue
		}
		baseline := p.State.Sensitive
		if p.State.Day != day {
			baseline = 0
		}
		if p.State.Day == day && report.SensitiveRequests < baseline {
			s.updateResearchAutoState(ctx, p, func(state *researchAutoState) {
				if state.Day == day && state.Sensitive == baseline {
					state.Sensitive = report.SensitiveRequests
					state.NextSus = now.Add(5 * time.Minute).Unix()
					state.SusError = "Counter coverage changed; baseline reset without a model call."
				}
			})
			continue
		}
		if report.SensitiveRequests-baseline < 20 {
			s.researchAutoChecked(ctx, p, now)
			continue
		}
		claim := &researchAutoClaim{Version: p.Version, Day: day, Count: report.SensitiveRequests, At: now}
		question := "Investigate a deterministic potential-suspicious-traffic lead for this site's selected day. At least 20 additional producer-reported sensitive-route requests arrived since the previous baseline/investigation. This is not a maliciousness or actor-identity verdict. Check evidence, legitimate tests, contradictions and missing coverage; explain whether deeper action is warranted. Recommendations are advisory."
		_, e = s.queueResearchInvestigation(ctx, id, investigationRequest{Server: p.Config.Worker, Day: day, Question: question}, "research-scheduler", "", claim)
		if e != nil {
			reason := "Investigation admission unavailable; retrying later."
			if problem, ok := e.(*researchDispatchError); ok {
				reason = problem.message
			}
			s.researchAutoFailure(ctx, p, "suspicious", reason, now)
		}
	}
}

func (s *Server) researchAutoChecked(ctx context.Context, p researchAutoRecord, now time.Time) {
	s.updateResearchAutoState(ctx, p, func(st *researchAutoState) { st.NextSus = now.Add(5 * time.Minute).Unix(); st.SusError = "" })
}

func researchDailyDate(local time.Time) string {
	return time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, local.Location()).AddDate(0, 0, -1).Format("2006-01-02")
}

func (s *Server) researchAutoFailure(ctx context.Context, p researchAutoRecord, kind, reason string, now time.Time) {
	changed := false
	s.updateResearchAutoState(ctx, p, func(st *researchAutoState) {
		if kind == "daily" || (kind == "scope" && p.Config.Daily) {
			changed = changed || st.DailyError != reason
			st.DailyError = reason
			st.NextDaily = now.Add(5 * time.Minute).Unix()
		}
		if kind == "suspicious" || (kind == "scope" && p.Config.Suspicious) {
			changed = changed || st.SusError != reason
			st.SusError = reason
			st.NextSus = now.Add(5 * time.Minute).Unix()
		}
	})
	if changed {
		s.log.Warn("research automation deferred", "site", p.Site, "mode", kind, "reason", reason)
	}
}

func (s *Server) updateResearchAutoState(ctx context.Context, p researchAutoRecord, change func(*researchAutoState)) {
	tx, err := s.st.db.BeginTx(ctx, nil)
	if err != nil {
		return
	}
	defer tx.Rollback()
	current, err := readResearchAuto(ctx, tx, p.Site)
	if err != nil || current.Version != p.Version {
		return
	}
	change(&current.State)
	b, _ := json.Marshal(current.State)
	if _, err = tx.ExecContext(ctx, "UPDATE research_automation SET state=? WHERE site=? AND version=?", string(b), p.Site, p.Version); err == nil {
		_ = tx.Commit()
	}
}

func (s *Server) queueDailyResearchOverview(ctx context.Context, site research.Site, version int64, date string, now time.Time) error {
	report, err := s.opt.Research.Daily(ctx, site.ID, date)
	if err != nil {
		return err
	}
	tx, err := s.st.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	p, err := readResearchAuto(ctx, tx, site.ID)
	if err != nil {
		return err
	}
	if p.Version != version || !p.Config.Daily || p.Config.Scope != researchScope(site) {
		return researchDispatchProblem(409, "daily overview policy changed")
	}
	if p.State.DailyDay == date {
		return nil
	}
	var enrolled int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM servers WHERE id=? AND revoked=0 AND enrolled_at>0", p.Config.Worker).Scan(&enrolled); err != nil {
		return err
	}
	if enrolled != 1 || !slices.Contains(site.Servers, p.Config.Worker) {
		return researchDispatchProblem(409, "daily overview source unavailable")
	}
	body := fmt.Sprintf("%s (%s)\nReceived requests: %d\nPage views: %d\nInteractions: %d\nServer-error requests: %d\nSensitive-route requests: %d\nResearch leads: %d\nLifetime capacity losses: %d detailed rows; %d summary buckets.\nCounts describe received telemetry, not complete traffic or proof of safety. No model was called.", date, site.Timezone, report.Requests, report.Pageviews, report.Interactions, report.Errors, report.SensitiveRequests, len(report.Findings), report.Coverage.DetailEvicted, report.Coverage.SummaryEvicted)
	for _, finding := range report.Findings {
		body += "\nPotential suspicious activity: " + finding.Rule + " (needs_review; identity not established)."
	}
	data, _ := json.Marshal(map[string]any{"kind": "research", "severity": "info", "title": "Daily traffic overview: " + trimRunes(site.Name, 60), "body": body, "fields": map[string]string{"site": site.ID, "date": date}})
	key := Hash(site.ID)[:16]
	_, err = addNotification(tx, p.Config.Worker, hubproto.Record{Kind: "notification", ID: "research-daily-" + key + "-" + date, UpdatedAt: now, Data: data})
	if err != nil {
		return err
	}
	p.State.DailyDay = date
	p.State.DailyError = ""
	p.State.NextDaily = 0
	b, _ := json.Marshal(p.State)
	if _, err = tx.ExecContext(ctx, "UPDATE research_automation SET state=? WHERE site=? AND version=?", string(b), site.ID, version); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	s.wakeSlack()
	return nil
}
