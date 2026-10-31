package hub

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
	"github.com/Problem99-io/kodeblue/internal/research"
)

func (s *Server) researchAgentRoutes() {
	s.mux.HandleFunc("POST /api/research/sites/{site}/investigate", s.op(s.handleInvestigate))
	s.mux.HandleFunc("GET /api/research/sites/{site}/investigations", s.op(s.handleInvestigations))
	s.mux.HandleFunc("POST "+hubproto.PathPrefix+"research-job/{job}", s.agent(s.handleResearchEvidence))
}

func (s *Server) handleInvestigate(w http.ResponseWriter, r *http.Request, c *opCtx) {
	if !s.researchEnabled(w) {
		return
	}
	var req struct {
		Server   string `json:"server_id"`
		Day      string `json:"date"`
		Question string `json:"question"`
	}
	if researchJSON(w, r, 8<<10, &req) != nil {
		writeErr(w, 400, "invalid investigation request")
		return
	}
	req.Question = strings.TrimSpace(req.Question)
	if req.Question == "" || len(req.Question) > 4000 {
		writeErr(w, 400, "question must be 1-4000 bytes")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	site, err := s.opt.Research.Site(ctx, r.PathValue("site"))
	if err != nil {
		s.researchError(w, err)
		return
	}
	worker := s.st.GetServer(req.Server)
	if worker == nil || worker.Revoked || !worker.Enrolled || !slices.Contains(site.Servers, req.Server) {
		writeErr(w, 403, "select an enrolled worker from this site's sources")
		return
	}
	var capability hubproto.Status
	_ = json.Unmarshal(worker.Status, &capability)
	if !capability.SupportsInvestigator || !capability.AcceptsMessages || !capability.ModelsEnabled {
		writeErr(w, 409, "worker needs an updated investigator-capable agent, accepted messages and a running model")
		return
	}
	report, err := s.opt.Research.Daily(ctx, site.ID, req.Day)
	if err != nil {
		s.researchError(w, err)
		return
	}
	through, err := s.opt.Research.LastSequence(ctx, site.ID)
	if err != nil {
		s.researchError(w, err)
		return
	}
	encoded, _ := json.Marshal(report)
	sources, _ := json.Marshal(site.Servers)
	m := &Message{ServerID: worker.ID, Author: c.user.Name, Body: req.Question, Command: hubproto.CommandInvestigate, RequestID: site.ID, ConversationID: "c_" + NewToken("")[:12]}
	// Admission is durable and bounded. A worker may have only one outstanding
	// research job, preventing a burst from reserving unbooked model spend.
	tx, err := s.st.db.BeginTx(ctx, nil)
	if err != nil {
		writeErr(w, 503, "investigation admission unavailable")
		return
	}
	defer tx.Rollback()
	now := time.Now()
	if _, err = tx.ExecContext(ctx, "DELETE FROM research_jobs WHERE expires<?", now.Unix()); err != nil {
		writeErr(w, 503, "investigation admission unavailable")
		return
	}
	var fleet, own int
	err = tx.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(CASE WHEN m.server_id=? THEN 1 ELSE 0 END),0) FROM research_jobs j JOIN messages m ON m.id=j.message_id WHERE m.status IN ('queued','delivered')`, worker.ID).Scan(&fleet, &own)
	if err != nil {
		writeErr(w, 503, "investigation admission unavailable")
		return
	}
	if fleet >= 32 || own > 0 {
		writeErr(w, 409, "an investigation is already queued/running on this worker, or fleet capacity is reached")
		return
	}
	var grants int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM research_jobs").Scan(&grants); err != nil || grants >= 128 {
		writeErr(w, 429, "research grant capacity reached; retry after existing grants expire")
		return
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO messages(server_id,author,body,conversation_id,created_at,command,request_id) VALUES(?,?,?,?,?,?,?)`, m.ServerID, m.Author, m.Body, m.ConversationID, now.Unix(), m.Command, m.RequestID)
	if err == nil {
		m.ID, err = res.LastInsertId()
	}
	if err == nil {
		_, err = tx.ExecContext(ctx, `INSERT INTO research_jobs(message_id,site,day,expires,sources,through_seq,overview) VALUES(?,?,?,?,?,?,?)`, m.ID, site.ID, req.Day, now.Add(30*time.Minute).Unix(), string(sources), through, string(encoded))
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		writeErr(w, 503, "could not queue investigation")
		return
	}
	m.Status = "queued"
	m.CreatedAt = now
	s.st.Audit(c.user.Name, "research.investigate", worker.ID, fmt.Sprintf("job=%d site=%s date=%s", m.ID, site.ID, req.Day), c.ip)
	s.wake(worker.ID)
	writeJSON(w, 200, m)
}

func (s *Server) handleInvestigations(w http.ResponseWriter, r *http.Request, c *opCtx) {
	if !s.researchEnabled(w) {
		return
	}
	list := s.st.messages("WHERE command=? AND request_id=? ORDER BY id DESC LIMIT 20", hubproto.CommandInvestigate, r.PathValue("site"))
	writeJSON(w, 200, list)
}

func (s *Server) handleResearchEvidence(w http.ResponseWriter, r *http.Request, serverID string) {
	if !s.researchEnabled(w) {
		return
	}
	var req struct {
		View  string `json:"view"`
		After int64  `json:"after"`
	}
	id, err := strconv.ParseInt(r.PathValue("job"), 10, 64)
	if err != nil || id <= 0 || researchJSON(w, r, 1024, &req) != nil || req.After < 0 || (req.View != "overview" && req.View != "evidence" && req.View != "sources") {
		writeErr(w, 400, "invalid research job query")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	var siteID, day, sourcesJSON, overview string
	var through int64
	err = s.st.db.QueryRowContext(ctx, `SELECT j.site,j.day,j.sources,j.through_seq,j.overview FROM research_jobs j JOIN messages m ON m.id=j.message_id WHERE j.message_id=? AND m.server_id=? AND m.command=? AND m.status='delivered' AND j.expires>?`, id, serverID, hubproto.CommandInvestigate, time.Now().Unix()).Scan(&siteID, &day, &sourcesJSON, &through, &overview)
	if err != nil {
		writeErr(w, 403, "no active research grant for this worker")
		return
	}
	site, err := s.opt.Research.Site(ctx, siteID)
	if err != nil || !slices.Contains(site.Servers, serverID) {
		writeErr(w, 403, "research site grant withdrawn")
		return
	}
	var granted []string
	_ = json.Unmarshal([]byte(sourcesJSON), &granted)
	sources := []string{}
	for _, source := range granted {
		if slices.Contains(site.Servers, source) {
			srv := s.st.GetServer(source)
			if srv != nil && !srv.Revoked && srv.Enrolled {
				sources = append(sources, source)
			}
		}
	}
	// Reserve before any read. All attempts consume budget, including invalid
	// cursors; partial success never refunds already returned evidence.
	res, err := s.st.db.ExecContext(ctx, "UPDATE research_jobs SET queries=queries+1 WHERE message_id=? AND queries<24 AND expires>?", id, time.Now().Unix())
	if err != nil {
		writeErr(w, 503, "research budget unavailable")
		return
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		writeErr(w, 429, "research job query budget reached")
		return
	}
	var report research.Report
	if json.Unmarshal([]byte(overview), &report) != nil {
		writeErr(w, 503, "research scope unavailable")
		return
	}
	var result any
	switch req.View {
	case "overview":
		result = map[string]any{"job_id": id, "site": siteID, "source_ids": sources, "through_sequence": through, "daily": report, "query_limit": 24, "detail": "Overview captured at job admission; retained details may subsequently expire. Findings are research leads, not actor identity."}
	case "evidence":
		result, err = s.opt.Research.Window(ctx, siteID, sources, report.Start, report.End, req.After, through)
	case "sources":
		// Only explicitly granted, currently enrolled site sources. No arbitrary
		// record kinds, secret settings, transcripts or raw host/container access.
		if req.After > int64(len(sources)) {
			writeErr(w, 400, "invalid source cursor")
			return
		}
		type record struct {
			Source     string    `json:"source"`
			Kind       string    `json:"kind"`
			ID         string    `json:"id"`
			At         time.Time `json:"updated_at"`
			Title      string    `json:"title"`
			Summary    string    `json:"summary"`
			CaseKind   string    `json:"case_kind,omitempty"`
			Provenance string    `json:"provenance"`
		}
		items := []record{}
		end := min(int(req.After)+4, len(sources))
		for _, source := range sources[int(req.After):end] {
			for _, kind := range []string{"incident", "finding"} {
				records, readErr := s.researchRecords(ctx, source, kind, report.Start, report.End)
				if readErr != nil {
					s.researchError(w, readErr)
					return
				}
				for _, rec := range records {
					var value map[string]any
					if json.Unmarshal(rec.Data, &value) != nil {
						continue
					}
					title, _ := value["title"].(string)
					caseKind, _ := value["kind"].(string)
					summary, _ := value["summary"].(string)
					if summary == "" {
						summary, _ = value["detail"].(string)
					}
					items = append(items, record{source, kind, rec.ID, rec.UpdatedAt, trimRunes(title, 160), trimRunes(summary, 400), trimRunes(caseKind, 40), "source_synced_summary"})
				}
			}
		}
		result = map[string]any{"records": items, "next": end, "capped": end < len(sources), "limits": "At most four newest records per kind/source, filtered by update time; not a full history. Missing/late syncs are unknown."}
	}
	if err != nil {
		s.researchError(w, err)
		return
	}
	b, err := json.Marshal(result)
	if err != nil || len(b) > 32<<10 {
		writeErr(w, 503, "research result exceeded response bound")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, _ = w.Write(b)
}

func (s *Server) researchRecords(ctx context.Context, source, kind string, start, end time.Time) ([]Rec, error) {
	rows, err := s.st.db.QueryContext(ctx, `SELECT rid,updated_at,data FROM records WHERE server_id=? AND kind=? AND updated_at>=? AND updated_at<? ORDER BY updated_at DESC LIMIT 4`, source, kind, start.Unix(), end.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []Rec{}
	for rows.Next() {
		var rec Rec
		var at int64
		var raw string
		if err = rows.Scan(&rec.ID, &at, &raw); err != nil {
			return nil, err
		}
		rec.Data = json.RawMessage(raw)
		rec.Kind = kind
		rec.UpdatedAt = time.Unix(at, 0).UTC()
		list = append(list, rec)
	}
	return list, rows.Err()
}
