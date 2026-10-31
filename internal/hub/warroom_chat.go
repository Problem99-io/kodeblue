package hub

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
	"github.com/Problem99-io/kodeblue/internal/research"
)

type warRoomAnchor struct {
	Server string `json:"server_id"`
	ID     string `json:"id"`
	Title  string `json:"title"`
}
type warRoomTraffic struct {
	ID      string `json:"id"`
	Through int64  `json:"through"`
}
type warRoomGrant struct {
	Servers []string         `json:"server_ids"`
	Anchor  *warRoomAnchor   `json:"case,omitempty"`
	Traffic []warRoomTraffic `json:"traffic,omitempty"`
}

func warRoomRoleName(role string) string {
	switch role {
	case "responder":
		return "Responder"
	case "reviewer":
		return "Reviewer"
	case "learner":
		return "Learner"
	case "operator":
		return "Operator"
	case "investigator":
		return "Investigator"
	}
	return "Source specialist"
}
func validWarRoomRole(role string) bool {
	return slices.Contains([]string{"investigator", "responder", "reviewer", "learner", "operator"}, role)
}
func (s *Server) nativeWarRoomRoutes() {
	s.mux.HandleFunc("GET /api/warroom/conversations", s.op(s.handleWarRoomList))
	s.mux.HandleFunc("POST /api/warroom/conversations", s.op(s.handleWarRoomStart))
	s.mux.HandleFunc("POST /api/warroom/conversations/{council}", s.op(s.handleCouncilInput))
}
func (s *Server) handleWarRoomList(w http.ResponseWriter, r *http.Request, c *opCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	rows, err := s.st.db.QueryContext(ctx, "SELECT id FROM research_councils WHERE json_extract(data,'$.room.native')=1 ORDER BY updated DESC LIMIT 32")
	if err != nil {
		s.councilHTTPError(w, err)
		return
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			break
		}
		ids = append(ids, id)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		s.councilHTTPError(w, err)
		return
	}
	rooms := []researchCouncil{}
	selected := r.URL.Query().Get("selected")
	for _, id := range ids {
		room, e := readCouncil(ctx, s.st.db, id)
		if e != nil {
			s.councilHTTPError(w, e)
			return
		}
		if server := r.URL.Query().Get("server_id"); server != "" && !slices.Contains(room.Servers, server) {
			continue
		}
		if caseID := r.URL.Query().Get("case_id"); caseID != "" && (room.Anchor == nil || room.Anchor.ID != caseID || room.Anchor.Server != r.URL.Query().Get("server_id")) {
			continue
		}
		if selected == "" {
			selected = room.ID
		}
		if room.ID != selected && len(room.Entries) > 0 {
			entry := room.Entries[0]
			entry.Text = councilBytes(entry.Text, 100)
			room.Entries = []councilEntry{entry}
		}
		rooms = append(rooms, room)
		if len(rooms) == 12 {
			break
		}
	}
	writeJSON(w, 200, rooms)
}
func (s *Server) nativeParticipant(id, role string) (councilParticipant, error) {
	if !validWarRoomRole(role) {
		return councilParticipant{}, researchDispatchProblem(400, "Unknown War room role.")
	}
	srv := s.st.GetServer(id)
	if srv == nil || !srv.Enrolled || srv.Revoked {
		return councilParticipant{}, researchDispatchProblem(403, "Select an enrolled KodeBlue server.")
	}
	var status hubproto.Status
	_ = json.Unmarshal(srv.Status, &status)
	if !status.SupportsWarRoom || !status.ModelsEnabled || !status.AcceptsMessages {
		return councilParticipant{}, researchDispatchProblem(409, "Update this server for War room and enable its model and hub messages.")
	}
	return councilParticipant{Server: id, Name: trimRunes(srv.Name, 80), Role: role}, nil
}
func (s *Server) handleWarRoomStart(w http.ResponseWriter, r *http.Request, c *opCtx) {
	var req struct {
		Lead         string               `json:"lead"`
		Participants []councilParticipant `json:"participants"`
		Anchor       *warRoomAnchor       `json:"case"`
		Question     string               `json:"question"`
	}
	if researchJSON(w, r, 8<<10, &req) != nil || len(req.Participants) > 4 || strings.TrimSpace(req.Question) == "" || len(req.Question) > 2000 {
		writeErr(w, 400, "Enter a question and select up to four participating agents.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	lead, err := s.nativeParticipant(req.Lead, "investigator")
	if err != nil {
		s.councilHTTPError(w, err)
		return
	}
	room := researchCouncil{ID: "council_" + NewToken("")[:16], Native: true, Lead: lead, Participants: []councilParticipant{}, Servers: []string{lead.Server}, Enrollments: map[string]string{}, Status: "active", Round: 1, Created: time.Now().UTC(), Day: time.Now().UTC().Format("2006-01-02")}
	seen := map[string]bool{}
	for _, part := range req.Participants {
		key := part.Server + ":" + part.Role
		if seen[key] || part.Role == "investigator" {
			writeErr(w, 400, "Choose distinct specialist/server pairs; the Investigator already leads.")
			return
		}
		seen[key] = true
		p, e := s.nativeParticipant(part.Server, part.Role)
		if e != nil {
			s.councilHTTPError(w, e)
			return
		}
		room.Participants = append(room.Participants, p)
		if !slices.Contains(room.Servers, p.Server) {
			room.Servers = append(room.Servers, p.Server)
		}
	}
	if req.Anchor != nil {
		id, e := strconv.ParseInt(req.Anchor.ID, 10, 64)
		record := s.st.Record(req.Anchor.Server, "incident", req.Anchor.ID)
		srv := s.st.GetServer(req.Anchor.Server)
		if e != nil || id <= 0 || record == nil || srv == nil || srv.Revoked || !srv.Enrolled {
			writeErr(w, 400, "The selected KodeBlue case is unavailable.")
			return
		}
		var data struct {
			Title string `json:"title"`
		}
		_ = json.Unmarshal(record.Data, &data)
		room.Anchor = &warRoomAnchor{Server: req.Anchor.Server, ID: req.Anchor.ID, Title: trimRunes(data.Title, 160)}
		if !slices.Contains(room.Servers, req.Anchor.Server) {
			room.Servers = append(room.Servers, req.Anchor.Server)
		}
	}
	slices.Sort(room.Servers)
	for _, id := range room.Servers {
		var key string
		if err = s.st.db.QueryRowContext(ctx, "SELECT key_hash FROM servers WHERE id=? AND revoked=0 AND enrolled_at>0", id).Scan(&key); err != nil || key == "" {
			writeErr(w, 409, "Server enrollment changed; select agents again.")
			return
		}
		room.Enrollments[id] = key
	}
	grouping := strings.Join(room.Servers, ",")
	if room.Anchor != nil {
		grouping = room.Anchor.Server + ":" + room.Anchor.ID
	}
	room.Site = "wr_" + Hash(grouping)[:16]
	site, err := s.councilSite(ctx, room)
	if err != nil {
		s.councilHTTPError(w, err)
		return
	}
	room.Scope = researchScope(site)
	if err = room.add(c.user.Name, "admin", req.Question, 0); err != nil {
		s.councilHTTPError(w, err)
		return
	}
	tx, err := s.st.db.BeginTx(ctx, nil)
	if err != nil {
		s.councilHTTPError(w, err)
		return
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, "DELETE FROM research_councils WHERE updated<?", time.Now().AddDate(0, 0, -30).Unix())
	var count, active int
	if err == nil {
		err = tx.QueryRowContext(ctx, "SELECT COUNT(*),COALESCE(SUM(CASE WHEN site=? AND json_extract(data,'$.room.status') IN ('active','paused') THEN 1 ELSE 0 END),0) FROM research_councils", room.Site).Scan(&count, &active)
	}
	if err == nil && (count >= 32 || active > 0) {
		err = researchDispatchProblem(409, "Continue or end the existing discussion; War room retains up to 32 conversations.")
	}
	if err == nil {
		data, _ := json.Marshal(councilStored{Room: room, Scope: room.Scope, Enrollments: room.Enrollments})
		_, err = tx.ExecContext(ctx, "INSERT INTO research_councils(id,site,version,updated,data)VALUES(?,?,1,?,?)", room.ID, room.Site, time.Now().Unix(), string(data))
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		s.councilHTTPError(w, err)
		return
	}
	s.st.Audit(c.user.Name, "warroom.start", lead.Server, room.ID, c.ip)
	s.wakeResearchCouncil()
	writeJSON(w, 200, room)
}
func (s *Server) councilSite(ctx context.Context, room researchCouncil) (research.Site, error) {
	if !room.Native {
		if s.opt.Research == nil {
			return research.Site{}, researchDispatchProblem(409, "Traffic evidence module is disabled.")
		}
		return s.opt.Research.Site(ctx, room.Site)
	}
	for _, id := range room.Servers {
		var key string
		if s.st.db.QueryRowContext(ctx, "SELECT key_hash FROM servers WHERE id=? AND revoked=0 AND enrolled_at>0", id).Scan(&key) != nil || key == "" || room.Enrollments[id] != key {
			return research.Site{}, researchDispatchProblem(409, "An enrolled server changed; open a fresh scoped discussion.")
		}
	}
	return research.Site{ID: room.Site, Name: "KodeBlue investigation", Timezone: "UTC", Servers: room.Servers}, nil
}
func (s *Server) nativeOverview(ctx context.Context, room researchCouncil) (research.Report, warRoomGrant, error) {
	report := research.Report{Version: "kodeblue-warroom-v1", Start: room.Created.Add(-24 * time.Hour), End: time.Now().UTC().Truncate(time.Second).Add(time.Second), Date: room.Day, Timezone: "UTC", Baseline: "Case and infrastructure investigation; traffic analytics are optional."}
	grant := warRoomGrant{Servers: room.Servers, Anchor: room.Anchor}
	if s.opt.Research != nil {
		sites, err := s.opt.Research.Sites(ctx)
		if err != nil {
			return report, grant, nil
		}
		for _, site := range sites {
			linked := false
			for _, id := range room.Servers {
				linked = linked || slices.Contains(site.Servers, id)
			}
			if !linked {
				continue
			}
			through, err := s.opt.Research.LastSequence(ctx, site.ID)
			if err != nil {
				continue
			}
			grant.Traffic = append(grant.Traffic, warRoomTraffic{site.ID, through})
			if len(grant.Traffic) == 8 {
				break
			}
		}
	}
	return report, grant, nil
}
func (s *Server) nativeEvidence(ctx context.Context, sources []string, grant warRoomGrant, start, end time.Time, after int64) (any, []string, error) {
	if after > int64(len(sources)) {
		return nil, nil, researchDispatchProblem(400, "Invalid source cursor.")
	}
	type item struct {
		Source     string            `json:"source"`
		Kind       string            `json:"kind"`
		ID         string            `json:"id"`
		At         time.Time         `json:"updated_at"`
		Title      string            `json:"title"`
		Summary    string            `json:"summary"`
		Provenance string            `json:"provenance"`
		Context    map[string]string `json:"context,omitempty"`
	}
	items := []item{}
	refs := []string{}
	next := min(int(after)+1, len(sources))
	for _, source := range sources[int(after):next] {
		for _, kind := range []string{"incident", "finding", "service", "vulnerability", "action"} {
			anchorID := ""
			if grant.Anchor != nil && grant.Anchor.Server == source {
				anchorID = grant.Anchor.ID
			}
			rows, err := s.st.db.QueryContext(ctx, "SELECT rid,updated_at,data FROM records WHERE server_id=? AND kind=? AND ((updated_at>=? AND updated_at<?) OR kind IN ('service','vulnerability') OR (kind='finding' AND CAST(json_extract(data,'$.incident_id') AS TEXT)=?)) ORDER BY CASE WHEN kind='finding' AND CAST(json_extract(data,'$.incident_id') AS TEXT)=? THEN 0 ELSE 1 END,updated_at DESC LIMIT 2", source, kind, start.Unix(), end.Unix(), anchorID, anchorID)
			if err != nil {
				return nil, nil, err
			}
			records := []Rec{}
			for rows.Next() {
				var rec Rec
				var at int64
				var data string
				if err = rows.Scan(&rec.ID, &at, &data); err != nil {
					break
				}
				rec.Data = json.RawMessage(data)
				rec.UpdatedAt = time.Unix(at, 0)
				records = append(records, rec)
			}
			if err == nil {
				err = rows.Err()
			}
			rows.Close()
			if err != nil {
				return nil, nil, err
			}
			if kind == "incident" && grant.Anchor != nil && grant.Anchor.Server == source && !slices.ContainsFunc(records, func(r Rec) bool { return r.ID == grant.Anchor.ID }) {
				if anchor := s.st.Record(source, "incident", grant.Anchor.ID); anchor != nil {
					records = append(records, *anchor)
				}
			}
			for _, rec := range records {
				var data map[string]any
				if json.Unmarshal(rec.Data, &data) != nil {
					continue
				}
				if data["kind"] == "research" {
					continue
				}
				title, _ := data["title"].(string)
				if title == "" {
					title, _ = data["name"].(string)
				}
				summary, _ := data["summary"].(string)
				if summary == "" {
					summary, _ = data["detail"].(string)
				}
				if summary == "" {
					summary, _ = data["status"].(string)
				}
				ref := "record:" + source + ":" + kind + ":" + rec.ID
				if len(ref) > 240 {
					continue
				}
				refs = append(refs, ref)
				details := map[string]string{}
				for _, key := range []string{"status", "severity", "rule", "service", "container", "pid", "port", "path", "verdict", "product", "installed_version", "fixed_version"} {
					if value, ok := data[key]; ok {
						switch value.(type) {
						case string, float64, bool:
							details[key] = councilBytes(fmt.Sprint(value), 120)
						}
					}
					if len(details) == 8 {
						break
					}
				}
				if evidence, ok := data["evidence"].(map[string]any); ok {
					for _, key := range []string{"source_ip", "destination_ip", "client_ip", "ip", "pid", "exe", "container", "service", "path", "unit"} {
						if len(details) >= 8 {
							break
						}
						if value, ok := evidence[key].(string); ok {
							details[key] = councilBytes(value, 120)
						}
					}
				}
				provenance := "enrolled_source_synced_record"
				if kind == "incident" {
					provenance = "source_case_analysis_not_independent_proof"
				}
				items = append(items, item{Source: source, Kind: kind, ID: rec.ID, At: rec.UpdatedAt, Title: councilBytes(title, 160), Summary: councilBytes(summary, 1200), Provenance: provenance, Context: details})
			}
		}
	}
	truncated := false
	for len(items) > 0 {
		data, _ := json.Marshal(items)
		if len(data) <= 24<<10 {
			break
		}
		items = items[:len(items)-1]
		refs = refs[:len(items)]
		truncated = true
	}
	return map[string]any{"records": items, "next": next, "truncated": truncated, "capped": next < len(sources), "limits": "Bounded received records, at most two per kind/source plus the anchored case. Inventory may be older. Sync timestamps are not proof of live state. Research reports are excluded; incident summaries remain attributed model analysis, not independent corroboration. Oversized samples are marked truncated."}, refs, nil
}
func (s *Server) nativeTraffic(ctx context.Context, grant warRoomGrant, sources []string, start, end time.Time, after int64, sourceOnly bool) (any, []string, error) {
	observations := []research.Observation{}
	refs := []string{}
	if s.opt.Research == nil {
		return map[string]any{"observations": observations, "note": "No traffic analytics configured; infrastructure evidence remains available."}, refs, nil
	}
	for _, traffic := range grant.Traffic {
		site, err := s.opt.Research.Site(ctx, traffic.ID)
		if err != nil {
			continue
		}
		current := []string{}
		for _, id := range sources {
			if slices.Contains(site.Servers, id) {
				current = append(current, id)
			}
		}
		if len(current) == 0 {
			continue
		}
		var page research.Page
		if sourceOnly {
			page, err = s.opt.Research.SourceWindow(ctx, site.ID, current, start, end, after, traffic.Through)
		} else {
			page, err = s.opt.Research.Window(ctx, site.ID, current, start, end, after, traffic.Through)
		}
		if err != nil {
			return nil, nil, err
		}
		observations = append(observations, page.Observations...)
	}
	sort.Slice(observations, func(i, j int) bool { return observations[i].Sequence < observations[j].Sequence })
	capped := len(observations) > 25
	if capped {
		observations = observations[:25]
	}
	var next int64
	for _, o := range observations {
		refs = append(refs, fmt.Sprintf("event:%d", o.Sequence))
		next = o.Sequence
	}
	return map[string]any{"observations": observations, "next": next, "capped": capped, "note": "Optional traffic evidence from configured collectors linked to the granted servers. Missing traffic is unknown; browser observations are client claims."}, refs, nil
}
