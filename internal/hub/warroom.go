package hub

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

const warEventLimit = 5000

var nonPublicSources = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("64:ff9b::/96"), netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
}

func canonicalSource(raw string) string {
	ip, err := netip.ParseAddr(raw)
	if err != nil {
		return ""
	}
	return ip.Unmap().String()
}

func publicSource(ip netip.Addr) bool {
	ip = ip.Unmap()
	if ip.Is6() && !netip.MustParsePrefix("2000::/3").Contains(ip) {
		return false
	}
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !inPrefixes(ip, nonPublicSources)
}

// Only explicit source fields are indexed. IPs in prose, URLs, destination
// fields and forwarded-header text are not evidence of an event's source.
func findingSources(data json.RawMessage) []netip.Addr {
	var f struct {
		Evidence map[string]string `json:"evidence"`
		Value    string            `json:"value"`
	}
	if json.Unmarshal(data, &f) != nil {
		return nil
	}
	seen := map[netip.Addr]bool{}
	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		ip, err := netip.ParseAddr(raw)
		if err != nil {
			if ap, e := netip.ParseAddrPort(raw); e == nil {
				ip = ap.Addr()
				err = nil
			}
		}
		if err == nil && ip.Zone() == "" && !ip.IsUnspecified() && !ip.IsMulticast() {
			seen[ip.Unmap()] = true
		}
	}
	for _, key := range []string{"ip", "source_ip", "src_ip", "client_ip", "remote_ip", "peer_ip", "src_addr"} {
		add(f.Evidence[key])
	}
	var value map[string]json.RawMessage
	if json.Unmarshal([]byte(f.Value), &value) == nil {
		for _, key := range []string{"source_ip", "src_ip", "client_ip", "remote_ip", "src_addr"} {
			var raw string
			_ = json.Unmarshal(value[key], &raw)
			add(raw)
		}
	}
	ips := make([]netip.Addr, 0, len(seen))
	for ip := range seen {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool { return ips[i].Compare(ips[j]) < 0 })
	return ips
}

func (s *Store) migrateWarRoom() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS war_sources (
ip TEXT PRIMARY KEY, public INTEGER NOT NULL, status TEXT NOT NULL, data TEXT NOT NULL DEFAULT '{}',
looked_at INTEGER NOT NULL DEFAULT 0, next_try INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS war_sources_lookup ON war_sources(public,next_try,looked_at);
CREATE INDEX IF NOT EXISTS records_kind_updated ON records(kind,updated_at);
CREATE TABLE IF NOT EXISTS war_events (
server_id TEXT NOT NULL, finding_id TEXT NOT NULL, ip TEXT NOT NULL REFERENCES war_sources(ip),
PRIMARY KEY(server_id,finding_id,ip),
FOREIGN KEY(server_id) REFERENCES servers(id) ON DELETE CASCADE);
CREATE TRIGGER IF NOT EXISTS war_finding_deleted AFTER DELETE ON records WHEN old.kind='finding'
BEGIN DELETE FROM war_events WHERE server_id=old.server_id AND finding_id=old.rid; END;
CREATE INDEX IF NOT EXISTS war_events_ip ON war_events(ip);`)
	// records' primary key also includes kind; the deletion trigger handles
	// finding retention without an ambiguous composite foreign key.
	return err
}

func indexWarFinding(tx *sql.Tx, server, id string, data json.RawMessage) error {
	if _, err := tx.Exec(`DELETE FROM war_events WHERE server_id=? AND finding_id=?`, server, id); err != nil {
		return err
	}
	for _, ip := range findingSources(data) {
		isPublic, status := publicSource(ip), "private"
		if isPublic {
			status = "pending"
		}
		if _, err := tx.Exec(`INSERT OR IGNORE INTO war_sources(ip,public,status) VALUES(?,?,?)`, ip.String(), isPublic, status); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO war_events(server_id,finding_id,ip) VALUES(?,?,?)`, server, id, ip.String()); err != nil {
			return err
		}
	}
	return nil
}

// Backfill existing findings in bounded batches without holding the single
// SQLite connection while writing. New syncs are indexed in their transaction.
func (s *Store) backfillWarRoom() error {
	if s.Setting("war_index_v1") == "done" {
		return nil
	}
	var cursor int64
	for {
		rows, err := s.db.Query(`SELECT rowid,server_id,rid,data FROM records WHERE kind='finding' AND rowid>? ORDER BY rowid LIMIT 200`, cursor)
		if err != nil {
			return err
		}
		type entry struct {
			row        int64
			server, id string
			data       string
		}
		batch := []entry{}
		for rows.Next() {
			var e entry
			if err := rows.Scan(&e.row, &e.server, &e.id, &e.data); err != nil {
				rows.Close()
				return err
			}
			batch = append(batch, e)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if len(batch) == 0 {
			break
		}
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		for _, e := range batch {
			if err = indexWarFinding(tx, e.server, e.id, json.RawMessage(e.data)); err != nil {
				break
			}
			cursor = e.row
		}
		if err != nil {
			tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	return s.SetSetting("war_index_v1", "done")
}

type IPIntel struct {
	Provider  string   `json:"provider,omitempty"`
	ASN       string   `json:"asn,omitempty"`
	Type      string   `json:"type,omitempty"`
	Country   string   `json:"country,omitempty"`
	City      string   `json:"city,omitempty"`
	Latitude  *float64 `json:"latitude,omitempty"`
	Longitude *float64 `json:"longitude,omitempty"`
	Flags     []string `json:"flags,omitempty"`
}

type WarEvent struct {
	ServerID       string            `json:"server_id"`
	ServerName     string            `json:"server_name"`
	FindingID      string            `json:"finding_id"`
	IncidentID     int64             `json:"incident_id,omitempty"`
	Title          string            `json:"title"`
	Detail         string            `json:"detail"`
	Severity       string            `json:"severity"`
	Rule           string            `json:"rule"`
	Status         string            `json:"status"`
	FirstAt        time.Time         `json:"first_at"`
	LastAt         time.Time         `json:"last_at"`
	Occurrences    int               `json:"occurrences"`
	Evidence       map[string]string `json:"evidence,omitempty"`
	IncidentTitle  string            `json:"incident_title,omitempty"`
	IncidentStatus string            `json:"incident_status,omitempty"`
	Context        string            `json:"context,omitempty"`
}

type WarSource struct {
	IP       string     `json:"ip"`
	Public   bool       `json:"public"`
	Status   string     `json:"status"`
	Intel    IPIntel    `json:"intel"`
	LookedAt time.Time  `json:"looked_at"`
	Events   []WarEvent `json:"events"`
}

func (s *Store) warSources(since time.Time, server string) ([]WarSource, bool, error) {
	q := `SELECT w.ip,p.public,p.status,p.data,p.looked_at,w.server_id,h.name,w.finding_id,f.data,COALESCE(i.data,'{}')
FROM war_events w JOIN war_sources p ON p.ip=w.ip
JOIN records f ON f.server_id=w.server_id AND f.kind='finding' AND f.rid=w.finding_id
JOIN servers h ON h.id=w.server_id
LEFT JOIN records i ON i.server_id=f.server_id AND i.kind='incident' AND i.rid=CAST(json_extract(f.data,'$.incident_id') AS TEXT)
WHERE f.updated_at>=?`
	args := []any{since.Unix()}
	if server != "" {
		q += ` AND w.server_id=?`
		args = append(args, server)
	}
	q += ` ORDER BY f.updated_at DESC,w.ip LIMIT ?`
	args = append(args, warEventLimit+1)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	out := []WarSource{}
	index := map[string]int{}
	count := 0
	for rows.Next() {
		var ip, status, raw, finding, incident string
		var pub bool
		var looked int64
		var ev WarEvent
		if err := rows.Scan(&ip, &pub, &status, &raw, &looked, &ev.ServerID, &ev.ServerName, &ev.FindingID, &finding, &incident); err != nil {
			return nil, false, err
		}
		count++
		if count > warEventLimit {
			break
		}
		var f struct {
			Title, Detail, Severity, Rule, Status string
			IncidentID                            int64     `json:"incident_id"`
			CreatedAt                             time.Time `json:"created_at"`
			UpdatedAt                             time.Time `json:"updated_at"`
			Occurrences                           int
			Evidence                              map[string]string
		}
		if json.Unmarshal([]byte(finding), &f) != nil {
			continue
		}
		ev.Title, ev.Detail, ev.Severity, ev.Rule, ev.Status = f.Title, trim(f.Detail, 4000), f.Severity, f.Rule, f.Status
		ev.IncidentID, ev.FirstAt, ev.LastAt, ev.Occurrences = f.IncidentID, f.CreatedAt, f.UpdatedAt, max(1, f.Occurrences)
		if at, err := time.Parse(time.RFC3339, f.Evidence["time"]); err == nil {
			ev.FirstAt = at
		}
		ev.Evidence = map[string]string{}
		for _, key := range []string{"user", "method", "source_ip", "ip", "client_ip", "remote_ip", "protected"} {
			if v := f.Evidence[key]; v != "" {
				ev.Evidence[key] = trim(v, 300)
			}
		}
		var in struct{ Title, Status, Summary string }
		_ = json.Unmarshal([]byte(incident), &in)
		ev.IncidentTitle, ev.IncidentStatus, ev.Context = trim(in.Title, 300), in.Status, trim(in.Summary, 4000)
		i, ok := index[ip]
		if !ok {
			i = len(out)
			index[ip] = i
			src := WarSource{IP: ip, Public: pub, Status: status, Events: []WarEvent{}}
			_ = json.Unmarshal([]byte(raw), &src.Intel)
			if looked > 0 {
				src.LookedAt = time.Unix(looked, 0)
			}
			out = append(out, src)
		}
		out[i].Events = append(out[i].Events, ev)
	}
	return out, count > warEventLimit, rows.Err()
}

func (s *Store) warSettings() map[string]any {
	limit := 30
	if s.Setting("war_api_key") != "" {
		limit = 1000
	}
	used := 0
	if s.Setting("war_lookup_day") == time.Now().UTC().Format("2006-01-02") {
		used, _ = strconv.Atoi(s.Setting("war_lookup_count"))
	}
	pause := ""
	if until, err := strconv.ParseInt(s.Setting("war_pause_until"), 10, 64); err == nil && until > time.Now().Unix() {
		pause = time.Unix(until, 0).UTC().Format(time.RFC3339)
	}
	return map[string]any{"enabled": s.Setting("war_enabled") != "false", "key_configured": s.Setting("war_api_key") != "", "provider": "ipapi.is", "daily_limit": limit, "used_today": used, "paused_until": pause}
}

func (s *Server) warRoutes() {
	s.mux.HandleFunc("GET /api/war-room", s.op(s.handleWarRoom))
	s.mux.HandleFunc("GET /api/settings/war-room", s.op(func(w http.ResponseWriter, r *http.Request, c *opCtx) { writeJSON(w, 200, s.st.warSettings()) }))
	s.mux.HandleFunc("PUT /api/settings/war-room", s.op(s.handleWarSettings))
}

func (s *Server) handleWarRoom(w http.ResponseWriter, r *http.Request, c *opCtx) {
	hours := 24
	if raw := r.URL.Query().Get("hours"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil || v < 1 || v > 720 {
			writeErr(w, 400, "hours must be between 1 and 720")
			return
		}
		hours = v
	}
	sources, truncated, err := s.st.warSources(time.Now().Add(-time.Duration(hours)*time.Hour), r.URL.Query().Get("server_id"))
	if err != nil {
		writeErr(w, 500, "could not load source activity")
		return
	}
	writeJSON(w, 200, map[string]any{"sources": sources, "truncated": truncated, "limit": warEventLimit, "hours": hours, "settings": s.st.warSettings()})
}

func (s *Server) handleWarSettings(w http.ResponseWriter, r *http.Request, c *opCtx) {
	var req struct {
		Enabled *bool   `json:"enabled"`
		Key     *string `json:"api_key"`
	}
	if readJSON(w, r, 4096, &req) != nil {
		writeErr(w, 400, "bad request")
		return
	}
	if req.Key != nil && (len(*req.Key) > 512 || strings.ContainsAny(*req.Key, "\r\n\x00")) {
		writeErr(w, 400, "invalid API key")
		return
	}
	tx, err := s.st.db.Begin()
	if err != nil {
		writeErr(w, 500, "could not save settings")
		return
	}
	defer tx.Rollback()
	values := map[string]string{}
	if req.Enabled != nil {
		values["war_enabled"] = strconv.FormatBool(*req.Enabled)
	}
	if req.Key != nil {
		values["war_api_key"] = strings.TrimSpace(*req.Key)
	}
	for key, value := range values {
		if _, err = tx.Exec(`INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, key, value); err != nil {
			writeErr(w, 500, "could not save settings")
			return
		}
	}
	if req.Key != nil && strings.TrimSpace(*req.Key) != "" {
		if _, err = tx.Exec(`DELETE FROM settings WHERE k='war_pause_until'`); err != nil {
			writeErr(w, 500, "could not save settings")
			return
		}
		if _, err = tx.Exec(`UPDATE war_sources SET next_try=0 WHERE public=1`); err != nil {
			writeErr(w, 500, "could not save settings")
			return
		}
	}
	if tx.Commit() != nil {
		writeErr(w, 500, "could not save settings")
		return
	}
	s.st.Audit(c.user.Name, "war.settings", "", "updated", c.ip)
	writeJSON(w, 200, s.st.warSettings())
}

// EnrichSources sends only a validated public IP to the fixed provider. Lookups
// are cached for seven days, paced, and bounded by a persistent daily budget.
func (s *Server) EnrichSources(ctx context.Context) {
	tick := time.NewTicker(3 * time.Second)
	defer tick.Stop()
	for {
		s.enrichNext(ctx)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (s *Server) enrichNext(ctx context.Context) {
	if ctx.Err() != nil || s.st.Setting("war_enabled") == "false" {
		return
	}
	settings := s.st.warSettings()
	used := settings["used_today"].(int)
	if used >= settings["daily_limit"].(int) || settings["paused_until"].(string) != "" {
		return
	}
	var ip string
	if s.st.db.QueryRow(`SELECT p.ip FROM war_sources p JOIN
(SELECT w.ip,MAX(f.updated_at) AS latest FROM war_events w JOIN records f ON f.server_id=w.server_id AND f.rid=w.finding_id AND f.kind='finding' GROUP BY w.ip) e ON e.ip=p.ip
WHERE p.public=1 AND p.next_try<=? ORDER BY e.latest DESC,p.looked_at,p.ip LIMIT 1`, time.Now().Unix()).Scan(&ip) != nil {
		return
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil || !publicSource(addr) {
		return
	}
	day := time.Now().UTC().Format("2006-01-02")
	// Reserve before calling: even timeouts consume our budget, including after restarts.
	tx, err := s.st.db.Begin()
	if err != nil {
		return
	}
	for key, value := range map[string]string{"war_lookup_day": day, "war_lookup_count": strconv.Itoa(used + 1)} {
		if _, err = tx.Exec(`INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, key, value); err != nil {
			tx.Rollback()
			return
		}
	}
	if tx.Commit() != nil {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	intel, status, quota, err := s.lookupSource(cctx, ip)
	next := time.Now().Add(7 * 24 * time.Hour)
	if err != nil {
		status = "unavailable"
		next = time.Now().Add(time.Hour)
	}
	if quota {
		next = time.Now().UTC().Truncate(24 * time.Hour).Add(24 * time.Hour)
		_ = s.st.SetSetting("war_pause_until", fmt.Sprint(next.Unix()))
	}
	if status == "unlocated" {
		next = time.Now().Add(24 * time.Hour)
	}
	if err != nil {
		_, _ = s.st.db.Exec(`UPDATE war_sources SET status='unavailable',next_try=? WHERE ip=?`, next.Unix(), ip)
		return
	}
	data, _ := json.Marshal(intel)
	_, _ = s.st.db.Exec(`UPDATE war_sources SET status=?,data=?,looked_at=?,next_try=? WHERE ip=?`, status, string(data), time.Now().Unix(), next.Unix(), ip)
}

func (s *Server) lookupSource(ctx context.Context, ip string) (IPIntel, string, bool, error) {
	var result IPIntel
	body, _ := json.Marshal(map[string]string{"q": ip, "key": s.st.Setting("war_api_key")})
	req, _ := http.NewRequestWithContext(ctx, "POST", "https://api.ipapi.is/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	client := *s.models.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return result, "", false, errors.New("IP lookup failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return result, "", (resp.StatusCode == 429 || resp.StatusCode == 403), errors.New("IP lookup unavailable")
	}
	var raw struct {
		IP            string          `json:"ip"`
		Error         string          `json:"error"`
		Bogon         bool            `json:"is_bogon"`
		Company       json.RawMessage `json:"company"`
		ASN           json.RawMessage `json:"asn"`
		City, Country string
		Lat           *float64 `json:"lat"`
		Lon           *float64 `json:"lon"`
		Location      struct {
			City, Country string
			Latitude      *float64 `json:"latitude"`
			Longitude     *float64 `json:"longitude"`
		} `json:"location"`
		Datacenter *bool `json:"is_datacenter"`
		VPN        *bool `json:"is_vpn"`
		Proxy      *bool `json:"is_proxy"`
		Tor        *bool `json:"is_tor"`
		Mobile     *bool `json:"is_mobile"`
		Satellite  *bool `json:"is_satellite"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 128<<10)).Decode(&raw) != nil || raw.Error != "" || canonicalSource(raw.IP) != ip {
		return result, "", false, errors.New("invalid IP lookup response")
	}
	var company struct{ Name, Type string }
	if json.Unmarshal(raw.Company, &company) == nil {
		result.Provider = company.Name
		result.Type = company.Type
	} else {
		_ = json.Unmarshal(raw.Company, &result.Provider)
	}
	var asn struct {
		ASN       int
		Org, Type string
	}
	if json.Unmarshal(raw.ASN, &asn) == nil {
		if asn.ASN > 0 {
			result.ASN = fmt.Sprintf("AS%d", asn.ASN)
		}
		if result.Provider == "" {
			result.Provider = asn.Org
		}
		if asn.Type != "" {
			result.Type = asn.Type
		}
	} else {
		_ = json.Unmarshal(raw.ASN, &result.ASN)
	}
	for _, flag := range []struct {
		name  string
		value *bool
	}{{"hosting", raw.Datacenter}, {"vpn", raw.VPN}, {"proxy", raw.Proxy}, {"tor", raw.Tor}, {"mobile", raw.Mobile}, {"satellite", raw.Satellite}} {
		if flag.value != nil && *flag.value {
			result.Flags = append(result.Flags, flag.name)
		}
	}
	if len(result.Flags) > 0 {
		result.Type = strings.Join(result.Flags, ", ")
	}
	if result.Type == "" {
		result.Type = "unknown"
	}
	result.City, result.Country, result.Latitude, result.Longitude = raw.Location.City, raw.Location.Country, raw.Location.Latitude, raw.Location.Longitude
	if result.Latitude == nil {
		result.City, result.Country, result.Latitude, result.Longitude = raw.City, raw.Country, raw.Lat, raw.Lon
	}
	result.Provider, result.ASN, result.Type, result.City, result.Country = trim(result.Provider, 200), trim(result.ASN, 200), trim(result.Type, 100), trim(result.City, 100), trim(result.Country, 100)
	if raw.Bogon || result.Latitude == nil || result.Longitude == nil || *result.Latitude < -90 || *result.Latitude > 90 || *result.Longitude < -180 || *result.Longitude > 180 {
		result.Latitude = nil
		result.Longitude = nil
		return result, "unlocated", false, nil
	}
	return result, "ready", false, nil
}
