package hub

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/Problem99-io/kodeblue/internal/blue/cloudflare"
)

type cloudflareSettings struct {
	Configured bool              `json:"configured"`
	Zones      []string          `json:"zone_ids"`
	Labels     map[string]string `json:"zone_labels"`
}

func (s *Store) cloudflareSettings(id string) cloudflareSettings {
	zones := strings.Fields(s.Setting("cloudflare.zones." + id))
	var saved map[string]string
	_ = json.Unmarshal([]byte(s.Setting("cloudflare.labels."+id)), &saved)
	labels := map[string]string{}
	for _, zone := range zones {
		if label := saved[zone]; label != "" {
			labels[zone] = label
		}
	}
	return cloudflareSettings{Labels: labels, Configured: s.Setting("cloudflare.token."+id) != "" && len(zones) > 0, Zones: zones}
}

func (s *Server) cloudflareRoutes() {
	s.mux.HandleFunc("GET /api/servers/{id}/cloudflare", s.op(s.handleCloudflareGet))
	s.mux.HandleFunc("PUT /api/servers/{id}/cloudflare", s.op(s.handleCloudflarePut))
	s.mux.HandleFunc("POST "+cloudflare.HubPath, s.agent(s.handleCloudflareLookup))
}

func (s *Server) handleCloudflareGet(w http.ResponseWriter, r *http.Request, c *opCtx) {
	host := s.serverOr404(w, r)
	if host == nil {
		return
	}
	writeJSON(w, 200, s.st.cloudflareSettings(host.ID))
}

func (s *Server) handleCloudflarePut(w http.ResponseWriter, r *http.Request, c *opCtx) {
	host := s.serverOr404(w, r)
	if host == nil {
		return
	}
	var req struct {
		Token  *string            `json:"api_token"`
		Zones  *[]string          `json:"zone_ids"`
		Labels *map[string]string `json:"zone_labels"`
	}
	if readJSON(w, r, 8<<10, &req) != nil {
		writeErr(w, 400, "bad Cloudflare settings")
		return
	}
	values := map[string]string{}
	if req.Token != nil {
		token := strings.TrimSpace(*req.Token)
		if token != "" && !cloudflare.ValidToken(token) {
			writeErr(w, 400, "invalid Cloudflare API token format")
			return
		}
		values["cloudflare.token."+host.ID] = token
	}
	if req.Zones != nil {
		if err := cloudflare.ValidateZones(*req.Zones); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		values["cloudflare.zones."+host.ID] = strings.Join(*req.Zones, " ")
	}
	if req.Labels != nil {
		zones := s.st.cloudflareSettings(host.ID).Zones
		if req.Zones != nil {
			zones = *req.Zones
		}
		labels := map[string]string{}
		for zone, label := range *req.Labels {
			if !slices.Contains(zones, zone) || len([]rune(label)) > 128 {
				writeErr(w, 400, "zone labels must name configured zones and contain at most 128 characters")
				return
			}
			labels[zone] = cloudflare.Sanitize(label, "", 128)
		}
		data, _ := json.Marshal(labels)
		values["cloudflare.labels."+host.ID] = string(data)
	}
	tx, err := s.st.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeErr(w, 500, "could not save Cloudflare settings")
		return
	}
	defer tx.Rollback()
	for k, v := range values {
		if _, err = tx.Exec(`INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, k, v); err != nil {
			writeErr(w, 500, "could not save Cloudflare settings")
			return
		}
	}
	if tx.Commit() != nil {
		writeErr(w, 500, "could not save Cloudflare settings")
		return
	}
	s.st.Audit(c.user.Name, "cloudflare.settings", host.ID, "updated", c.ip)
	writeJSON(w, 200, s.st.cloudflareSettings(host.ID))
}

func (s *Server) handleCloudflareLookup(w http.ResponseWriter, r *http.Request, id string) {
	var q cloudflare.Query
	if readJSON(w, r, 4<<10, &q) != nil {
		writeErr(w, 400, "bad Cloudflare query")
		return
	}
	settings := s.st.cloudflareSettings(id)
	if q.IP != "" && !settings.Configured {
		writeErr(w, 400, "Cloudflare is not configured for this server")
		return
	}
	if _, err := cloudflare.Normalize(q, settings.Zones); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	var local, global *reservation
	if q.IP != "" {
		local = s.cfLimit.Reserve(id)
		if local != nil {
			global = s.cfGlobal.Reserve("all")
		}
		if local == nil || global == nil {
			if local != nil {
				local.Refund()
			}
			writeErr(w, 429, "Cloudflare lookup budget reached; wait a minute")
			return
		}
	}
	client := cloudflare.Client{Token: s.st.Setting("cloudflare.token." + id), HTTP: s.models.client, ZoneLabels: settings.Labels}
	result, err := client.Lookup(r.Context(), q, settings.Zones)
	if err != nil {
		var upstream *cloudflare.HTTPError
		if errors.As(err, &upstream) && upstream.Retryable() && local != nil {
			local.Refund()
			if upstream.StatusCode != 429 {
				global.Refund()
			}
		}
		writeErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, result)
}
