package hub

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
)

// Model connections: the endpoints agents reach models through. The fleet
// has a list; agent settings pick a model on one of them per role. Keys are
// stored here and handed only to servers whose roles use the connection;
// the console never gets them back.

const settingConnections = "fleet_connections"

// legacyConnectionID is the connection the old single fleet endpoint
// (fleet set inference-*) becomes.
const legacyConnectionID = "default"

// Connections returns the fleet's connections, keys included.
func (s *Store) Connections() []hubproto.Connection {
	s.foldLegacyEndpoint()
	return s.connections()
}

func (s *Store) connections() []hubproto.Connection {
	var out []hubproto.Connection
	if v := s.Setting(settingConnections); v != "" {
		_ = json.Unmarshal([]byte(v), &out)
	}
	return out
}

// Connection returns one connection by ID.
func (s *Store) Connection(id string) (hubproto.Connection, bool) {
	for _, c := range s.Connections() {
		if c.ID == id {
			return c, true
		}
	}
	return hubproto.Connection{}, false
}

func (s *Store) setConnections(list []hubproto.Connection) error {
	if len(list) == 0 {
		return s.SetSetting(settingConnections, "")
	}
	b, err := json.Marshal(list)
	if err != nil {
		return err
	}
	return s.SetSetting(settingConnections, string(b))
}

// foldLegacyEndpoint moves the single fleet endpoint (fleet_inference_*,
// still what `kodeblue-hub fleet set inference-*` writes) into the
// connection "default", and its model into the fleet's default model.
func (s *Store) foldLegacyEndpoint() {
	u, p, m, k := s.Setting(SettingInferenceURL), s.Setting(SettingInferenceProvider), s.Setting(SettingInferenceModel), s.Setting(SettingInferenceKey)
	if u == "" && p == "" && m == "" && k == "" {
		return
	}
	list := s.connections()
	i := slices.IndexFunc(list, func(c hubproto.Connection) bool { return c.ID == legacyConnectionID })
	if i < 0 {
		if u == "" {
			return // wait for the URL before creating anything
		}
		list = append(list, hubproto.Connection{ID: legacyConnectionID, Name: "Default"})
		i = len(list) - 1
	}
	c := &list[i]
	if u != "" {
		c.BaseURL = normalizeBaseURL(u)
	}
	if k != "" {
		c.APIKey = k
	}
	switch {
	case strings.HasPrefix(c.BaseURL, OpenRouterURL):
		c.Kind = hubproto.ConnOpenRouter
	case p != "" && p != hubproto.ConnOpenAI && p != "openai":
		c.Kind = hubproto.ConnInferenceManager // a routing label means a multi-vendor gateway
	case c.Kind == "":
		c.Kind = hubproto.ConnOpenAI
	}
	if s.setConnections(list) != nil {
		return
	}
	if m != "" {
		fleet := s.agentSettings(settingFleetAgents)
		if fleet.Models == nil {
			fleet.Models = map[string]hubproto.ModelRef{}
		}
		ref := hubproto.ModelRef{Connection: legacyConnectionID, Model: m}
		if c.Kind == hubproto.ConnInferenceManager {
			ref.Provider = p
		}
		fleet.Models[hubproto.RoleDefault] = ref
		if s.setAgentSettings(settingFleetAgents, fleet) != nil {
			return
		}
	}
	for _, key := range []string{SettingInferenceURL, SettingInferenceProvider, SettingInferenceModel, SettingInferenceKey} {
		_ = s.SetSetting(key, "")
	}
}

// fleetDefaultModel is the fleet's default model and its connection.
func (s *Store) fleetDefaultModel() (hubproto.ModelRef, hubproto.Connection, bool) {
	ref, ok := s.FleetAgentSettings().Models[hubproto.RoleDefault]
	if !ok || ref.Connection == "" {
		return ref, hubproto.Connection{}, false
	}
	conn, ok := s.Connection(ref.Connection)
	return ref, conn, ok && conn.APIKey != ""
}

func (s *Server) fleetModelName() string {
	ref, conn, ok := s.st.fleetDefaultModel()
	if !ok {
		return ""
	}
	return ref.Model + " via " + map[bool]string{true: conn.Name, false: conn.ID}[conn.Name != ""]
}

// connectionUsers lists where a connection is picked: "fleet" and/or
// server IDs.
func (s *Store) connectionUsers(id string) []string {
	var out []string
	uses := func(a AgentSettings) bool {
		for _, r := range a.Models {
			if r.Connection == id {
				return true
			}
		}
		return false
	}
	if uses(s.FleetAgentSettings()) {
		out = append(out, "fleet")
	}
	for _, h := range s.Servers() {
		if uses(s.ServerAgentSettings(h.ID)) {
			out = append(out, h.Name)
		}
	}
	return out
}

// normalizeBaseURL trims a trailing slash and /v1: kodeblue appends
// /v1/chat/completions and /v1/models itself, and people paste either form.
func normalizeBaseURL(raw string) string {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	// Only a /v1 path: https://v1 is a host.
	if u, err := url.Parse(raw); err == nil && u.Host != "" && strings.HasSuffix(u.Path, "/v1") && u.RawQuery == "" && u.Fragment == "" {
		return strings.TrimSuffix(raw, "/v1")
	}
	return raw
}

var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

// newConnectionID derives a short, unique ID from the name or kind.
func newConnectionID(name, kind string, taken []hubproto.Connection) string {
	base := strings.Trim(slugRe.ReplaceAllString(strings.ToLower(name), "-"), "-")
	// Keep IDs short, cut at a word: "acme-inference-manager-eu" -> "acme-inference-manager".
	for len(base) > 24 {
		i := strings.LastIndex(base, "-")
		if i <= 0 {
			base = base[:24]
			break
		}
		base = base[:i]
	}
	if base == "" || !hubproto.ValidConnectionID(base) {
		base = map[string]string{hubproto.ConnInferenceManager: "im", hubproto.ConnOpenRouter: "openrouter"}[kind]
		if base == "" {
			base = "endpoint"
		}
	}
	used := func(id string) bool {
		return slices.ContainsFunc(taken, func(c hubproto.Connection) bool { return c.ID == id })
	}
	id := base
	for n := 2; used(id); n++ {
		id = fmt.Sprintf("%s-%d", base, n)
	}
	return id
}

// ---- operator API ----

// connectionView is a connection as the console sees it: never the key.
type connectionView struct {
	ID      string   `json:"id"`
	Kind    string   `json:"kind"`
	Name    string   `json:"name"`
	BaseURL string   `json:"base_url"`
	HasKey  bool     `json:"has_key"`
	Direct  bool     `json:"direct"`
	UsedBy  []string `json:"used_by"`
}

func (s *Server) connectionViews() []connectionView {
	out := []connectionView{}
	for _, c := range s.st.Connections() {
		out = append(out, connectionView{ID: c.ID, Kind: c.Kind, Name: c.Name, BaseURL: c.BaseURL, HasKey: c.APIKey != "", Direct: c.Direct, UsedBy: s.st.connectionUsers(c.ID)})
	}
	return out
}

func (s *Server) connectionRoutes() {
	s.mux.HandleFunc("GET /api/settings/connections", s.op(s.handleConnectionList))
	s.mux.HandleFunc("POST /api/settings/connections", s.op(s.handleConnectionCreate))
	s.mux.HandleFunc("PUT /api/settings/connections/{id}", s.op(s.handleConnectionUpdate))
	s.mux.HandleFunc("DELETE /api/settings/connections/{id}", s.op(s.handleConnectionDelete))
	s.mux.HandleFunc("POST /api/settings/connections/{id}/test", s.op(s.handleConnectionTest))
	s.mux.HandleFunc("GET /api/settings/models", s.op(s.handleModelList))
}

type connectionReq struct {
	Kind     string `json:"kind"`
	Name     string `json:"name"`
	BaseURL  string `json:"base_url"`
	APIKey   string `json:"api_key"`
	ClearKey bool   `json:"clear_key"`
	// Direct: servers call the endpoint themselves, so its key goes to them.
	// Absent (an older console) keeps the stored choice.
	Direct *bool `json:"direct"`
}

func (req *connectionReq) check() error {
	req.Name, req.APIKey = strings.TrimSpace(req.Name), strings.TrimSpace(req.APIKey)
	req.BaseURL = normalizeBaseURL(req.BaseURL)
	if req.Kind == hubproto.ConnOpenRouter && req.BaseURL == "" {
		req.BaseURL = OpenRouterURL
	}
	if !slices.Contains(hubproto.ConnectionKinds, req.Kind) {
		return fmt.Errorf("kind must be one of %s", strings.Join(hubproto.ConnectionKinds, ", "))
	}
	if err := ValidateEndpointURL(req.BaseURL); err != nil {
		return err
	}
	if len(req.Name) > 64 || strings.ContainsAny(req.Name, "\r\n") {
		return fmt.Errorf("the name is one line of at most 64 characters")
	}
	if len(req.APIKey) > 1024 || strings.ContainsAny(req.APIKey, " \t\r\n") {
		return fmt.Errorf("the API key must be a single line")
	}
	return nil
}

func (s *Server) handleConnectionList(w http.ResponseWriter, r *http.Request, c *opCtx) {
	writeJSON(w, http.StatusOK, map[string]any{"connections": s.connectionViews(), "kinds": hubproto.ConnectionKinds, "openrouter_url": OpenRouterURL})
}

func (s *Server) handleConnectionCreate(w http.ResponseWriter, r *http.Request, c *opCtx) {
	var req connectionReq
	if err := readJSON(w, r, 16<<10, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	if err := req.check(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.APIKey == "" {
		writeErr(w, http.StatusBadRequest, "an API key is required")
		return
	}
	list := s.st.Connections()
	if len(list) >= 32 {
		writeErr(w, http.StatusBadRequest, "at most 32 connections")
		return
	}
	conn := hubproto.Connection{ID: newConnectionID(req.Name, req.Kind, list), Kind: req.Kind, Name: req.Name, BaseURL: req.BaseURL, APIKey: req.APIKey, Direct: req.Direct != nil && *req.Direct}
	if err := s.st.setConnections(append(list, conn)); err != nil {
		writeErr(w, http.StatusInternalServerError, "store failed")
		return
	}
	s.models.forget(conn.ID)
	s.st.Audit(c.user.Name, "settings.connection_add", conn.ID, fmt.Sprintf("kind=%s url=%s direct=%t", conn.Kind, conn.BaseURL, conn.Direct), c.ip)
	writeJSON(w, http.StatusOK, map[string]any{"id": conn.ID, "connections": s.connectionViews()})
}

// sameOrigin reports whether two base URLs share scheme, host and port: a
// stored key may follow a path change, never a move to another endpoint.
func sameOrigin(a, b string) bool {
	origin := func(raw string) string {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return ""
		}
		port := u.Port()
		if port == "" {
			port = map[string]string{"http": "80", "https": "443"}[strings.ToLower(u.Scheme)]
		}
		return strings.ToLower(u.Scheme) + "://" + net.JoinHostPort(strings.ToLower(u.Hostname()), port)
	}
	oa := origin(a)
	return oa != "" && oa == origin(b)
}

// handleConnectionUpdate changes a connection. An empty api_key keeps the
// stored one, but only while the endpoint (scheme, host, port) stays the
// same: operators never see a stored key, so moving it to a host of their
// choosing would hand it out. clear_key removes it. The kind and ID never
// change.
func (s *Server) handleConnectionUpdate(w http.ResponseWriter, r *http.Request, c *opCtx) {
	id := r.PathValue("id")
	var req connectionReq
	if err := readJSON(w, r, 16<<10, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	list := s.st.Connections()
	i := slices.IndexFunc(list, func(c hubproto.Connection) bool { return c.ID == id })
	if i < 0 {
		writeErr(w, http.StatusNotFound, "no such connection")
		return
	}
	req.Kind = list[i].Kind
	if err := req.check(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	conn := &list[i]
	oldURL := conn.BaseURL
	if conn.APIKey != "" && req.APIKey == "" && !req.ClearKey && !sameOrigin(oldURL, req.BaseURL) {
		s.st.Audit(c.user.Name, "settings.connection_edit_refused", id, fmt.Sprintf("url=%s -> %s without a new key", oldURL, req.BaseURL), c.ip)
		writeErr(w, http.StatusBadRequest, "the endpoint moved to another host: enter its API key again (a stored key never follows a connection to a new host)")
		return
	}
	// Marking a connection direct hands its key to every server that uses
	// it, so, like a move to another host, it needs the key pasted again: a
	// stolen console session cannot send a stored key out.
	if req.Direct != nil && *req.Direct && !conn.Direct && req.APIKey == "" && conn.APIKey != "" {
		s.st.Audit(c.user.Name, "settings.connection_edit_refused", id, "direct without a new key", c.ip)
		writeErr(w, http.StatusBadRequest, "servers will call this endpoint themselves and receive its key: enter the API key again to confirm")
		return
	}
	oldDirect := conn.Direct
	if req.Direct != nil {
		conn.Direct = *req.Direct
	}
	conn.Name, conn.BaseURL = req.Name, req.BaseURL
	switch {
	case req.ClearKey:
		conn.APIKey = ""
	case req.APIKey != "":
		conn.APIKey = req.APIKey
	}
	if err := s.st.setConnections(list); err != nil {
		writeErr(w, http.StatusInternalServerError, "store failed")
		return
	}
	s.models.forget(id)
	key := map[bool]string{true: "set", false: "unchanged"}[req.APIKey != ""]
	if req.ClearKey {
		key = "cleared"
	}
	detail := fmt.Sprintf("url=%s key=%s", conn.BaseURL, key)
	if oldURL != conn.BaseURL {
		detail = fmt.Sprintf("url=%s -> %s key=%s", oldURL, conn.BaseURL, key)
	}
	if oldDirect != conn.Direct {
		detail += fmt.Sprintf(" direct=%t", conn.Direct)
	}
	s.st.Audit(c.user.Name, "settings.connection_edit", id, detail, c.ip)
	writeJSON(w, http.StatusOK, map[string]any{"connections": s.connectionViews()})
}

func (s *Server) handleConnectionDelete(w http.ResponseWriter, r *http.Request, c *opCtx) {
	id := r.PathValue("id")
	list := s.st.Connections()
	i := slices.IndexFunc(list, func(c hubproto.Connection) bool { return c.ID == id })
	if i < 0 {
		writeErr(w, http.StatusNotFound, "no such connection")
		return
	}
	if users := s.st.connectionUsers(id); len(users) > 0 {
		writeErr(w, http.StatusConflict, "still picked for models by: "+strings.Join(users, ", ")+". Choose other models there first.")
		return
	}
	if err := s.st.setConnections(slices.Delete(list, i, i+1)); err != nil {
		writeErr(w, http.StatusInternalServerError, "store failed")
		return
	}
	s.models.forget(id)
	s.st.Audit(c.user.Name, "settings.connection_remove", id, "", c.ip)
	writeJSON(w, http.StatusOK, map[string]any{"connections": s.connectionViews()})
}

// handleConnectionTest lists the connection's models now, bypassing the cache.
func (s *Server) handleConnectionTest(w http.ResponseWriter, r *http.Request, c *opCtx) {
	conn, ok := s.st.Connection(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "no such connection")
		return
	}
	s.models.forget(conn.ID)
	list, err := s.models.get(r.Context(), conn)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "models": len(list)})
}

// ---- model catalog ----

// ModelInfo is one model a connection offers.
type ModelInfo struct {
	Connection    string  `json:"connection"`
	Provider      string  `json:"provider,omitempty"`
	ID            string  `json:"id"`
	Name          string  `json:"name,omitempty"`
	ContextLength int     `json:"context_length,omitempty"`
	PromptUSD     float64 `json:"prompt_usd_per_mtok,omitempty"`
	CompletionUSD float64 `json:"completion_usd_per_mtok,omitempty"`
	// NoTools marks a model the catalog says cannot call tools; kodeblue's
	// agents need them, so such a model fails every agent request.
	NoTools bool `json:"no_tools,omitempty"`
}

// modelCache keeps each connection's model list for a few minutes.
type modelCache struct {
	client  *http.Client // endpointClient: never the default client
	mu      sync.Mutex
	entries map[string]modelEntry
}

type modelEntry struct {
	at     time.Time
	models []ModelInfo
}

func (m *modelCache) forget(id string) {
	m.mu.Lock()
	delete(m.entries, id)
	m.mu.Unlock()
}

func (m *modelCache) get(ctx context.Context, conn hubproto.Connection) ([]ModelInfo, error) {
	m.mu.Lock()
	e, ok := m.entries[conn.ID]
	m.mu.Unlock()
	if ok && time.Since(e.at) < 5*time.Minute {
		return e.models, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	list, err := fetchModels(ctx, m.client, conn)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	if m.entries == nil {
		m.entries = map[string]modelEntry{}
	}
	m.entries[conn.ID] = modelEntry{at: time.Now(), models: list}
	m.mu.Unlock()
	return list, nil
}

// handleModelList is the model catalog across every connection (or the one
// named by ?connection=). A connection that fails is reported in errors;
// the others still list.
func (s *Server) handleModelList(w http.ResponseWriter, r *http.Request, c *opCtx) {
	only := r.URL.Query().Get("connection")
	conns := s.st.Connections()
	if len(conns) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"models": []ModelInfo{}, "errors": map[string]string{}, "error": "add a model connection first"})
		return
	}
	type result struct {
		id     string
		models []ModelInfo
		err    error
	}
	results := make(chan result, len(conns))
	n := 0
	for _, conn := range conns {
		if only != "" && conn.ID != only {
			continue
		}
		n++
		go func(conn hubproto.Connection) {
			list, err := s.models.get(r.Context(), conn)
			results <- result{conn.ID, list, err}
		}(conn)
	}
	models, errs := []ModelInfo{}, map[string]string{}
	for range n {
		res := <-results
		if res.err != nil {
			errs[res.id] = res.err.Error()
			continue
		}
		models = append(models, res.models...)
	}
	sort.Slice(models, func(i, j int) bool {
		if models[i].Connection != models[j].Connection {
			return models[i].Connection < models[j].Connection
		}
		return models[i].ID < models[j].ID
	})
	writeJSON(w, http.StatusOK, map[string]any{"models": models, "errors": errs})
}

// fetchModels reads {base}/v1/models: the OpenAI shape, plus OpenRouter's
// name, context length and per-token prices, and an inference manager's
// per-model provider, when present.
func fetchModels(ctx context.Context, client *http.Client, conn hubproto.Connection) ([]ModelInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(conn.BaseURL, "/")+"/v1/models", nil)
	if err != nil {
		return nil, err
	}
	if conn.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+conn.APIKey)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("the endpoint did not answer: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the endpoint answered HTTP %d to /v1/models", resp.StatusCode)
	}
	// OpenRouter: name, context_length, pricing.{prompt,completion} in USD
	// per token as strings. Inference manager: display_name, context_window,
	// pricing.{input,output}_price_per_m_token as numbers.
	var body struct {
		Data []struct {
			ID            string `json:"id"`
			Name          string `json:"name"`
			DisplayName   string `json:"display_name"`
			Provider      string `json:"provider"`
			ContextLength int    `json:"context_length"`
			ContextWindow int    `json:"context_window"`
			// OpenRouter lists what a model accepts; "tools" is the one agents need.
			SupportedParameters []string `json:"supported_parameters"`
			Pricing             struct {
				Prompt     flexFloat `json:"prompt"`
				Completion flexFloat `json:"completion"`
				InputPerM  flexFloat `json:"input_price_per_m_token"`
				OutputPerM flexFloat `json:"output_price_per_m_token"`
			} `json:"pricing"`
		} `json:"data"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 16<<20)).Decode(&body); err != nil {
		return nil, fmt.Errorf("unreadable model list: %v", err)
	}
	first := func(vals ...float64) float64 {
		for _, v := range vals {
			if v > 0 {
				return v
			}
		}
		return 0
	}
	out := make([]ModelInfo, 0, len(body.Data))
	for _, m := range body.Data {
		if m.ID == "" || validModel(m.ID) != nil {
			continue
		}
		info := ModelInfo{Connection: conn.ID, ID: m.ID, Name: m.Name, ContextLength: max(m.ContextLength, m.ContextWindow),
			PromptUSD:     first(float64(m.Pricing.InputPerM), float64(m.Pricing.Prompt)*1e6),
			CompletionUSD: first(float64(m.Pricing.OutputPerM), float64(m.Pricing.Completion)*1e6)}
		if info.Name == "" {
			info.Name = m.DisplayName
		}
		if m.SupportedParameters != nil && !slices.Contains(m.SupportedParameters, "tools") {
			info.NoTools = true
		}
		if p := strings.ToLower(m.Provider); conn.Kind == hubproto.ConnInferenceManager && hubproto.ValidProvider(p) {
			info.Provider = p
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// flexFloat reads a JSON number or a numeric string ("0.000003"); anything
// else is 0.
type flexFloat float64

func (f *flexFloat) UnmarshalJSON(b []byte) error {
	var v float64
	if json.Unmarshal(b, &v) != nil {
		var str string
		if json.Unmarshal(b, &str) == nil {
			_, _ = fmt.Sscan(str, &v)
		}
	}
	*f = flexFloat(v)
	return nil
}
