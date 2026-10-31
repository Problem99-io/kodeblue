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
	s.researchAutoRoutes()
	s.researchCouncilRoutes()
	s.mux.HandleFunc("POST /api/research/sites/{site}/investigate", s.op(s.handleInvestigate))
	s.mux.HandleFunc("GET /api/research/sites/{site}/investigations", s.op(s.handleInvestigations))
	s.mux.HandleFunc("POST "+hubproto.PathPrefix+"research-job/{job}", s.agent(s.handleResearchEvidence))
}

type investigationRequest struct {
	Server   string `json:"server_id"`
	Day      string `json:"date"`
	Question string `json:"question"`
	council  *councilClaim
}

type researchDispatchError struct {
	status  int
	message string
}

func (e *researchDispatchError) Error() string { return e.message }
func researchDispatchProblem(status int, message string) error {
	return &researchDispatchError{status, message}
}

func (s *Server) handleInvestigate(w http.ResponseWriter, r *http.Request, c *opCtx) {
	if !s.researchEnabled(w) {
		return
	}
	var req investigationRequest
	if researchJSON(w, r, 8<<10, &req) != nil {
		writeErr(w, 400, "invalid investigation request")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	job, err := s.queueResearchInvestigation(ctx, r.PathValue("site"), req, c.user.Name, c.ip, nil)
	if err != nil {
		if problem, ok := err.(*researchDispatchError); ok {
			writeErr(w, problem.status, problem.message)
		} else {
			s.researchError(w, err)
		}
		return
	}
	writeJSON(w, 200, job)
}

// Manual and automatic jobs use exactly the same admission and native message path.
func (s *Server) queueResearchInvestigation(ctx context.Context, siteID string, req investigationRequest, author, ip string, claim *researchAutoClaim) (*Message, error) {
	req.Question = strings.TrimSpace(req.Question)
	if req.Question == "" || len(req.Question) > 4000 {
		return nil, researchDispatchProblem(400, "question must be 1-4000 bytes")
	}
	var site research.Site
	var err error
	native := req.council != nil && req.council.Room != nil && req.council.Room.Native
	if native {
		site, err = s.councilSite(ctx, *req.council.Room)
	} else if s.opt.Research != nil {
		site, err = s.opt.Research.Site(ctx, siteID)
	} else {
		err = researchDispatchProblem(409, "Traffic analytics are disabled.")
	}
	if err != nil {
		return nil, err
	}
	worker := s.st.GetServer(req.Server)
	if worker == nil || worker.Revoked || !worker.Enrolled || !slices.Contains(site.Servers, req.Server) {
		return nil, researchDispatchProblem(403, "select an enrolled worker from this site's sources")
	}
	var capability hubproto.Status
	_ = json.Unmarshal(worker.Status, &capability)
	if (!native && !capability.SupportsInvestigator) || (native && !capability.SupportsWarRoom) || !capability.AcceptsMessages || !capability.ModelsEnabled {
		return nil, researchDispatchProblem(409, "worker needs an updated investigator-capable agent, accepted messages and a running model")
	}
	var report research.Report
	var trafficGrant warRoomGrant
	var through int64
	if native {
		report, trafficGrant, err = s.nativeOverview(ctx, *req.council.Room)
	} else {
		report, err = s.opt.Research.Daily(ctx, site.ID, req.Day)
		if err == nil {
			through, err = s.opt.Research.LastSequence(ctx, site.ID)
		}
	}
	if err != nil {
		return nil, err
	}
	encoded, _ := json.Marshal(report)
	if req.council != nil {
		var snapshot map[string]any
		_ = json.Unmarshal(encoded, &snapshot)
		snapshot["council_context"] = req.council.Context
		if native {
			snapshot["warroom_scope"] = trafficGrant
		}
		encoded, _ = json.Marshal(snapshot)
	}
	grantedSources := site.Servers
	if req.council != nil && req.council.SourceOnly {
		grantedSources = []string{worker.ID}
	}
	sources, _ := json.Marshal(grantedSources)
	m := &Message{ServerID: worker.ID, Author: author, Body: req.Question, Command: hubproto.CommandInvestigate, RequestID: site.ID, ConversationID: "c_" + NewToken("")[:12]}
	tx, err := s.st.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	now := time.Now()
	if _, err = tx.ExecContext(ctx, "DELETE FROM research_jobs WHERE expires<?", now.Unix()); err != nil {
		return nil, err
	}
	var fleet, own int
	err = tx.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(CASE WHEN m.server_id=? THEN 1 ELSE 0 END),0) FROM research_jobs j JOIN messages m ON m.id=j.message_id WHERE m.status IN ('queued','delivered')`, worker.ID).Scan(&fleet, &own)
	if err != nil {
		return nil, err
	}
	if fleet >= 32 || own > 0 {
		return nil, researchDispatchProblem(409, "an investigation is already queued/running on this worker, or fleet capacity is reached")
	}
	var grants int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM research_jobs").Scan(&grants); err != nil {
		return nil, err
	}
	if grants >= 128 {
		return nil, researchDispatchProblem(429, "research grant capacity reached; retry after existing grants expire")
	}
	if claim != nil {
		claim.Count = report.SensitiveRequests
		if err = s.reserveResearchAuto(ctx, tx, site, req.Server, claim); err != nil {
			return nil, err
		}
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO messages(server_id,author,body,conversation_id,created_at,command,request_id) VALUES(?,?,?,?,?,?,?)`, m.ServerID, m.Author, m.Body, m.ConversationID, now.Unix(), m.Command, m.RequestID)
	if err == nil {
		m.ID, err = res.LastInsertId()
	}
	autoKind := ""
	if claim != nil {
		autoKind = "suspicious"
	}
	if err == nil {
		bindings := "{}"
		if native {
			b, _ := json.Marshal(req.council.Room.Enrollments)
			bindings = string(b)
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO research_jobs(message_id,site,day,expires,sources,through_seq,overview,auto_kind,source_only,native,enrollments) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, m.ID, site.ID, req.Day, now.Add(30*time.Minute).Unix(), string(sources), through, string(encoded), autoKind, req.council != nil && req.council.SourceOnly, native, bindings)
	}
	if err == nil && req.council != nil {
		err = s.reserveCouncilTurn(ctx, tx, site, req.council, m.ID)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		return nil, err
	}
	m.Status = "queued"
	m.CreatedAt = now
	s.st.Audit(author, "research.investigate", worker.ID, fmt.Sprintf("job=%d site=%s date=%s", m.ID, site.ID, req.Day), ip)
	s.wake(worker.ID)
	return m, nil
}

func (s *Server) handleInvestigations(w http.ResponseWriter, r *http.Request, c *opCtx) {
	if !s.researchEnabled(w) {
		return
	}
	list := s.st.messages("WHERE command=? AND request_id=? ORDER BY id DESC LIMIT 20", hubproto.CommandInvestigate, r.PathValue("site"))
	writeJSON(w, 200, list)
}

func (s *Server) handleResearchEvidence(w http.ResponseWriter, r *http.Request, serverID string) {
	var req struct {
		View  string `json:"view"`
		After int64  `json:"after"`
	}
	id, err := strconv.ParseInt(r.PathValue("job"), 10, 64)
	if err != nil || id <= 0 || researchJSON(w, r, 1024, &req) != nil || req.After < 0 || (req.View != "overview" && req.View != "evidence" && req.View != "sources" && req.View != "traffic") {
		writeErr(w, 400, "invalid research job query")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	var siteID, day, sourcesJSON, overview string
	var through int64
	var sourceOnly, native bool
	var enrollmentJSON string
	err = s.st.db.QueryRowContext(ctx, `SELECT j.site,j.day,j.sources,j.through_seq,j.overview,j.source_only,j.native,j.enrollments FROM research_jobs j JOIN messages m ON m.id=j.message_id WHERE j.message_id=? AND m.server_id=? AND m.command=? AND m.status='delivered' AND j.expires>?`, id, serverID, hubproto.CommandInvestigate, time.Now().Unix()).Scan(&siteID, &day, &sourcesJSON, &through, &overview, &sourceOnly, &native, &enrollmentJSON)
	if err != nil {
		writeErr(w, 403, "no active research grant for this worker")
		return
	}
	var granted []string
	_ = json.Unmarshal([]byte(sourcesJSON), &granted)
	sources := []string{}
	if native {
		var keys map[string]string
		_ = json.Unmarshal([]byte(enrollmentJSON), &keys)
		if len(keys) == 0 || len(keys) > 6 {
			writeErr(w, 403, "War room enrollment grant unavailable")
			return
		}
		for source, expected := range keys {
			var key string
			if s.st.db.QueryRowContext(ctx, "SELECT key_hash FROM servers WHERE id=? AND revoked=0 AND enrolled_at>0", source).Scan(&key) != nil || key == "" || key != expected {
				writeErr(w, 403, "War room enrollment grant withdrawn")
				return
			}
		}
		for _, source := range granted {
			var key string
			if s.st.db.QueryRowContext(ctx, "SELECT key_hash FROM servers WHERE id=? AND revoked=0 AND enrolled_at>0", source).Scan(&key) == nil && key != "" && keys[source] == key {
				sources = append(sources, source)
			}
		}
		if !slices.Contains(sources, serverID) {
			writeErr(w, 403, "War room enrollment grant withdrawn")
			return
		}
	} else {
		if s.opt.Research == nil {
			writeErr(w, 503, "Traffic analytics are disabled")
			return
		}
		site, e := s.opt.Research.Site(ctx, siteID)
		if e != nil || !slices.Contains(site.Servers, serverID) {
			writeErr(w, 403, "research site grant withdrawn")
			return
		}
		for _, source := range granted {
			if slices.Contains(site.Servers, source) {
				srv := s.st.GetServer(source)
				if srv != nil && !srv.Revoked && srv.Enrolled {
					sources = append(sources, source)
				}
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
	refs := []string{}
	if native {
		var saved map[string]json.RawMessage
		_ = json.Unmarshal([]byte(overview), &saved)
		var grant warRoomGrant
		_ = json.Unmarshal(saved["warroom_scope"], &grant)
		switch req.View {
		case "overview":
			result = map[string]any{"job_id": id, "server_ids": sources, "case": grant.Anchor, "window_start": report.Start, "window_end": report.End, "council_context": saved["council_context"], "query_limit": 24, "traffic_available": len(grant.Traffic) > 0, "notes": "KodeBlue infrastructure investigation. Sources/evidence contain bounded synced cases, findings, services, vulnerabilities and actions. Traffic is optional. Missing or stale evidence is unknown."}
		case "sources", "evidence":
			result, refs, err = s.nativeEvidence(ctx, sources, grant, report.Start, report.End, req.After)
		case "traffic":
			result, refs, err = s.nativeTraffic(ctx, grant, sources, report.Start, report.End, req.After, sourceOnly)
		}
	} else {
		switch req.View {
		case "traffic":
			writeErr(w, 400, "Use evidence for a traffic-collector investigation.")
			return
		case "overview":
			daily := json.RawMessage(overview)
			var saved map[string]json.RawMessage
			_ = json.Unmarshal([]byte(overview), &saved)
			councilContext, hasCouncil := saved["council_context"]
			if hasCouncil {
				delete(saved, "council_context")
				daily, _ = json.Marshal(saved)
			}
			payload := map[string]any{"job_id": id, "site": siteID, "source_ids": sources, "through_sequence": through, "daily": daily, "query_limit": 24, "detail": "Overview captured at job admission; retained details may subsequently expire. Findings are research leads, not actor identity."}
			if hasCouncil {
				payload["council_context"] = councilContext
			}
			result = payload
		case "evidence":
			if sourceOnly {
				result, err = s.opt.Research.SourceWindow(ctx, siteID, sources, report.Start, report.End, req.After, through)
			} else {
				result, err = s.opt.Research.Window(ctx, siteID, sources, report.Start, report.End, req.After, through)
			}
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
						if kind == "incident" && caseKind == "research" {
							continue
						} // Model reports are discussion, not independent source evidence.
						summary, _ := value["summary"].(string)
						if summary == "" {
							summary, _ = value["detail"].(string)
						}
						refs = append(refs, "record:"+source+":"+kind+":"+rec.ID)
						items = append(items, record{source, kind, rec.ID, rec.UpdatedAt, trimRunes(title, 160), trimRunes(summary, 400), trimRunes(caseKind, 40), "source_synced_summary"})
					}
				}
			}
			result = map[string]any{"records": items, "next": end, "capped": end < len(sources), "limits": "At most four newest records per kind/source, filtered by update time; not a full history. Missing/late syncs are unknown."}
		}
	}
	if err != nil {
		s.councilHTTPError(w, err)
		return
	}
	if page, ok := result.(research.Page); ok {
		for _, o := range page.Observations {
			refs = append(refs, fmt.Sprintf("event:%d", o.Sequence))
		}
	}
	b, err := json.Marshal(result)
	if err != nil || len(b) > 32<<10 {
		writeErr(w, 503, "research result exceeded response bound")
		return
	}
	if err = s.recordCouncilRefs(ctx, id, refs); err != nil {
		writeErr(w, 503, "evidence citation ledger unavailable")
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
