package hub

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
	"github.com/Problem99-io/kodeblue/internal/research"
)

func (s *Server) researchRoutes() {
	s.mux.HandleFunc("GET /assets/research.html", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/#war-room-research", http.StatusSeeOther)
	})
	s.mux.HandleFunc("GET /api/research", s.op(func(w http.ResponseWriter, r *http.Request, c *opCtx) {
		if s.opt.Research == nil {
			writeJSON(w, 200, map[string]any{"enabled": false})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		sites, err := s.opt.Research.Sites(ctx)
		if err != nil {
			s.researchError(w, err)
			return
		}
		bytes, _ := s.opt.Research.PhysicalBytes()
		writeJSON(w, 200, map[string]any{"enabled": true, "sites": sites, "physical_bytes": bytes, "prototype": true, "investigator_enabled": false})
	}))
	s.mux.HandleFunc("PUT /api/research/sites/{site}", s.op(s.handleResearchSite))
	s.mux.HandleFunc("DELETE /api/research/sites/{site}", s.op(func(w http.ResponseWriter, r *http.Request, c *opCtx) {
		if !s.researchEnabled(w) {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := s.opt.Research.DeleteSite(ctx, r.PathValue("site")); err != nil {
			s.researchError(w, err)
			return
		}
		s.st.Audit(c.user.Name, "research.site.delete", r.PathValue("site"), "", c.ip)
		writeJSON(w, 200, map[string]bool{"ok": true})
	}))
	s.mux.HandleFunc("GET /api/research/sites/{site}/events", s.op(func(w http.ResponseWriter, r *http.Request, c *opCtx) {
		if !s.researchEnabled(w) {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		after, err := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
		if r.URL.Query().Get("after") == "" {
			after = 0
			err = nil
		}
		if err != nil {
			writeErr(w, 400, "invalid cursor")
			return
		}
		var result research.Page
		if r.URL.Query().Get("tail") == "1" {
			result, err = s.opt.Research.Tail(ctx, r.PathValue("site"), 100)
		} else {
			result, err = s.opt.Research.Events(ctx, r.PathValue("site"), after, 100)
		}
		if err != nil {
			s.researchError(w, err)
			return
		}
		writeJSON(w, 200, result)
	}))
	s.mux.HandleFunc("GET /api/research/sites/{site}/daily", s.op(func(w http.ResponseWriter, r *http.Request, c *opCtx) {
		if !s.researchEnabled(w) {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		result, err := s.opt.Research.Daily(ctx, r.PathValue("site"), r.URL.Query().Get("date"))
		if err != nil {
			s.researchError(w, err)
			return
		}
		writeJSON(w, 200, result)
	}))
	s.mux.HandleFunc("GET /api/research/sites/{site}/graph", s.op(func(w http.ResponseWriter, r *http.Request, c *opCtx) {
		if !s.researchEnabled(w) {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		result, err := s.opt.Research.Graph(ctx, r.PathValue("site"))
		if err != nil {
			s.researchError(w, err)
			return
		}
		writeJSON(w, 200, result)
	}))
	s.mux.HandleFunc("POST "+hubproto.PathPrefix+"research/{site}", func(w http.ResponseWriter, r *http.Request) {
		if !s.researchEnabled(w) || !s.researchAdmission(w, "trusted") {
			return
		}
		defer func() { <-s.researchSlots }()
		// Authenticate the existing enrollment key, without turning passive
		// telemetry into a write to the hub's control-plane Seen state.
		source := s.st.ServerByKey(bearer(r))
		if source == nil {
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		s.handleResearchIngest(w, r, source.ID)
	})
	s.mux.HandleFunc("OPTIONS /collect/research/{site}", s.handleResearchCollect)
	s.mux.HandleFunc("POST /collect/research/{site}", s.handleResearchCollect)
	s.mux.HandleFunc("GET /research-tracker.js", func(w http.ResponseWriter, r *http.Request) {
		b, err := webFS.ReadFile("web/research-tracker.js")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cross-Origin-Resource-Policy", "cross-origin")
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("Cache-Control", "public,max-age=300")
		_, _ = w.Write(b)
	})
}

func (s *Server) researchEnabled(w http.ResponseWriter) bool {
	if s.opt.Research == nil {
		writeErr(w, 404, "behavioral research is disabled")
		return false
	}
	return true
}

func (s *Server) researchError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, research.ErrInvalid):
		writeErr(w, 400, "invalid research data, date or site configuration")
	case errors.Is(err, research.ErrScope):
		writeErr(w, 403, "source not authorized for this site")
	case errors.Is(err, sql.ErrNoRows):
		writeErr(w, 404, "research site not found")
	case errors.Is(err, research.ErrCapacity):
		writeErr(w, 503, "research capacity reached; receipt not stored")
	case errors.Is(err, context.DeadlineExceeded):
		writeErr(w, 503, "research query deadline reached")
	default:
		s.log.Warn("research operation failed")
		writeErr(w, 503, "research unavailable")
	}
}

func researchJSON(w http.ResponseWriter, r *http.Request, limit int64, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return research.ErrInvalid
	}
	return nil
}

func (s *Server) handleResearchSite(w http.ResponseWriter, r *http.Request, c *opCtx) {
	if !s.researchEnabled(w) {
		return
	}
	var site research.Site
	if researchJSON(w, r, 8<<10, &site) != nil {
		writeErr(w, 400, "invalid site")
		return
	}
	site.ID = r.PathValue("site")
	if site.Timezone == "" {
		site.Timezone = "UTC"
	}
	for _, id := range site.Servers {
		srv := s.st.GetServer(id)
		if srv == nil || srv.Revoked || !srv.Enrolled {
			writeErr(w, 400, "site source must be an enrolled, non-revoked server")
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.opt.Research.PutSite(ctx, site); err != nil {
		s.researchError(w, err)
		return
	}
	s.st.Audit(c.user.Name, "research.site.update", site.ID, "", c.ip)
	writeJSON(w, 200, site)
}

func (s *Server) handleResearchIngest(w http.ResponseWriter, r *http.Request, server string) {
	if !s.researchEnabled(w) {
		return
	}
	if s.researchLimit.Reserve("source:"+server) == nil {
		writeErr(w, 429, "research ingest limit reached")
		return
	}
	var body struct {
		Events []research.Event `json:"events"`
	}
	if researchJSON(w, r, 64<<10, &body) != nil {
		writeErr(w, 400, "invalid observations")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	result, err := s.opt.Research.Ingest(ctx, r.PathValue("site"), server, false, body.Events, time.Now())
	if err != nil {
		s.researchError(w, err)
		return
	}
	writeJSON(w, 200, result)
}

func (s *Server) handleResearchCollect(w http.ResponseWriter, r *http.Request) {
	if !s.researchEnabled(w) {
		return
	}
	if !s.researchAdmission(w, "browser") {
		return
	}
	defer func() { <-s.researchSlots }()
	if s.researchPublicLimit.Reserve(throttleKey(s.clientAddr(r), s.clientIP(r))) == nil {
		writeErr(w, 429, "research collection limit reached")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	site, err := s.opt.Research.Site(ctx, r.PathValue("site"))
	if err != nil || !site.BrowserEnabled {
		http.NotFound(w, r)
		return
	}
	origin := r.Header.Get("Origin")
	allowed := false
	for _, o := range site.Origins {
		allowed = allowed || origin == o
	}
	if !allowed {
		writeErr(w, 403, "origin not configured")
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Vary", "Origin")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	if r.Method == http.MethodOptions {
		w.WriteHeader(204)
		return
	}
	if r.Header.Get("DNT") == "1" || r.Header.Get("Sec-GPC") == "1" {
		writeJSON(w, 200, map[string]any{"stored": false, "reason": "privacy_signal"})
		return
	}
	var body struct {
		Events []research.Event `json:"events"`
	}
	if researchJSON(w, r, 16<<10, &body) != nil {
		writeErr(w, 400, "invalid browser observations")
		return
	}
	result, err := s.opt.Research.Ingest(ctx, site.ID, "browser", true, body.Events, time.Now())
	if err != nil {
		s.researchError(w, err)
		return
	}
	// Origin matching is browser hygiene, not authentication; all fields stay
	// browser_claimed and cannot supply trusted source/fingerprint context.
	writeJSON(w, 200, result)
}

func (s *Server) researchAdmission(w http.ResponseWriter, class string) bool {
	if s.researchGlobalLimit.Reserve(class) == nil {
		writeErr(w, 429, "research admission limit reached")
		return false
	}
	select {
	case s.researchSlots <- struct{}{}:
		return true
	default:
		writeErr(w, 503, "research busy; receipt not stored")
		return false
	}
}

func (s *Server) ResearchMaintenance(ctx context.Context) {
	if s.opt.Research == nil {
		return
	}
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		c, cancel := context.WithTimeout(ctx, 2*time.Second)
		err := s.opt.Research.Maintain(c, time.Now())
		cancel()
		if err != nil && ctx.Err() == nil {
			s.log.Warn("research maintenance delayed")
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
