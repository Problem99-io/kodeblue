package hub

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"

	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
	"github.com/Problem99-io/kodeblue/internal/blue/respond"
)

// AgentSettings are the agent choices operators make in the console: a
// model per role, extra instructions per agent, and a rule per containment
// action. The fleet has one set; each server can override single entries.
// An empty value means "not set here".
type AgentSettings struct {
	Models       map[string]hubproto.ModelRef `json:"models"`
	Instructions map[string]string            `json:"instructions"`
	Approvals    map[string]string            `json:"approvals"`
	// ResponseMode switches the server's response mode (off | recommend |
	// contain, empty = its own), up to what its root-owned config allows.
	ResponseMode string `json:"response_mode,omitempty"`
}

const (
	settingFleetAgents  = "fleet_agent_settings"
	settingServerPrefix = "server_settings:"
)

// OpenRouterURL is the base URL for OpenRouter's OpenAI-compatible API
// (kodeblue calls {base}/v1/chat/completions and {base}/v1/models).
const OpenRouterURL = "https://openrouter.ai/api"

func (s *Store) agentSettings(key string) AgentSettings {
	var a AgentSettings
	if v := s.Setting(key); v != "" {
		_ = json.Unmarshal([]byte(v), &a)
	}
	return a.clean()
}

func (s *Store) setAgentSettings(key string, a AgentSettings) error {
	a = a.clean()
	if len(a.Models)+len(a.Instructions)+len(a.Approvals) == 0 && a.ResponseMode == "" {
		return s.SetSetting(key, "")
	}
	b, err := json.Marshal(a)
	if err != nil {
		return err
	}
	return s.SetSetting(key, string(b))
}

func (s *Store) FleetAgentSettings() AgentSettings {
	s.foldLegacyEndpoint()
	return s.agentSettings(settingFleetAgents)
}
func (s *Store) SetFleetAgentSettings(a AgentSettings) error {
	return s.setAgentSettings(settingFleetAgents, a)
}
func (s *Store) ServerAgentSettings(id string) AgentSettings {
	return s.agentSettings(settingServerPrefix + id)
}
func (s *Store) SetServerAgentSettings(id string, a AgentSettings) error {
	return s.setAgentSettings(settingServerPrefix+id, a)
}

// clean drops empty entries and trims values.
func (a AgentSettings) clean() AgentSettings {
	trim := func(m map[string]string) map[string]string {
		out := map[string]string{}
		for k, v := range m {
			if v = strings.TrimSpace(v); v != "" {
				out[k] = v
			}
		}
		return out
	}
	models := map[string]hubproto.ModelRef{}
	for role, r := range a.Models {
		r = hubproto.ModelRef{Connection: strings.TrimSpace(r.Connection), Provider: strings.ToLower(strings.TrimSpace(r.Provider)), Model: strings.TrimSpace(r.Model)}
		if r.Model != "" {
			models[role] = r
		}
	}
	return AgentSettings{Models: models, Instructions: trim(a.Instructions), Approvals: trim(a.Approvals), ResponseMode: strings.TrimSpace(a.ResponseMode)}
}

// Validate checks role and action names, rules and sizes, and that each
// model is on one of conns (or on the server's own endpoint, connection "").
func (a AgentSettings) Validate(conns []hubproto.Connection) error {
	for role, m := range a.Models {
		if !slices.Contains(hubproto.ModelRoles, role) {
			return fmt.Errorf("unknown model role %q", role)
		}
		if err := validModel(m.Model); err != nil {
			return fmt.Errorf("%s model: %w", role, err)
		}
		if !hubproto.ValidProvider(m.Provider) {
			return fmt.Errorf("%s model: bad provider label", role)
		}
		if m.Connection != "" && !slices.ContainsFunc(conns, func(c hubproto.Connection) bool { return c.ID == m.Connection }) {
			return fmt.Errorf("%s model: no connection %q", role, m.Connection)
		}
	}
	for role, t := range a.Instructions {
		if !slices.Contains(hubproto.InstructionRoles, role) {
			return fmt.Errorf("unknown agent %q for instructions", role)
		}
		if len(t) > hubproto.MaxInstructions {
			return fmt.Errorf("%s instructions are longer than %d characters", role, hubproto.MaxInstructions)
		}
	}
	actions := respond.ActionNames()
	for action, rule := range a.Approvals {
		if !slices.Contains(actions, action) {
			return fmt.Errorf("unknown action %q", action)
		}
		if rule != hubproto.ActionAuto && rule != hubproto.ActionApprove && rule != hubproto.ActionOff {
			return fmt.Errorf("%s: rule must be auto, approve or off", action)
		}
	}
	if a.ResponseMode != "" && hubproto.ModeRank(a.ResponseMode) < 0 {
		return errors.New("response mode must be off, recommend or contain")
	}
	return nil
}

func validModel(m string) error {
	if len(m) > 200 || strings.ContainsAny(m, " \t\r\n") {
		return errors.New("a model id is one word of at most 200 characters")
	}
	return nil
}

// ValidateEndpointURL accepts an http(s) base URL without a query.
func ValidateEndpointURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.RawQuery != "" || u.User != nil {
		return errors.New("the endpoint must be an http(s) base URL, e.g. https://openrouter.ai/api")
	}
	return nil
}

// EffectiveSettings is what server id gets: the fleet agent settings with
// the server's overrides on top, and the connections those models use (only
// those: a server never holds keys it does not need). Version is a content
// hash; it is empty when nothing is set.
func (s *Store) EffectiveSettings(id string) *hubproto.Settings {
	fleet, own := s.FleetAgentSettings(), s.ServerAgentSettings(id)
	merge := func(a, b map[string]string) map[string]string {
		out := map[string]string{}
		for k, v := range a {
			out[k] = v
		}
		for k, v := range b {
			out[k] = v
		}
		if len(out) == 0 {
			return nil
		}
		return out
	}
	out := &hubproto.Settings{
		Instructions: merge(fleet.Instructions, own.Instructions),
		Approvals:    merge(fleet.Approvals, own.Approvals),
		ResponseMode: fleet.ResponseMode,
	}
	if own.ResponseMode != "" {
		out.ResponseMode = own.ResponseMode
	}
	conns := s.Connections()
	used := map[string]bool{}
	for _, m := range []map[string]hubproto.ModelRef{fleet.Models, own.Models} {
		for role, r := range m {
			if r.Connection != "" && !slices.ContainsFunc(conns, func(c hubproto.Connection) bool { return c.ID == r.Connection }) {
				continue // its connection was removed
			}
			if out.Models == nil {
				out.Models = map[string]hubproto.ModelRef{}
			}
			out.Models[role] = r
		}
	}
	for _, r := range out.Models {
		used[r.Connection] = true
	}
	for _, c := range conns {
		if used[c.ID] {
			out.Connections = append(out.Connections, c)
		}
	}
	if out.Models == nil && out.Instructions == nil && out.Approvals == nil && out.ResponseMode == "" {
		return &hubproto.Settings{}
	}
	b, _ := json.Marshal(out)
	sum := sha256.Sum256(b)
	out.Version = hex.EncodeToString(sum[:8])
	return out
}

// ---- operator API ----

func (s *Server) settingsRoutes() {
	s.mux.HandleFunc("GET /api/settings/agents", s.op(s.handleAgentSettingsGet))
	s.mux.HandleFunc("PUT /api/settings/agents", s.op(s.handleAgentSettingsPut))
	s.mux.HandleFunc("GET /api/servers/{id}/settings", s.op(s.handleServerSettingsGet))
	s.mux.HandleFunc("PUT /api/servers/{id}/settings", s.op(s.handleServerSettingsPut))
	s.connectionRoutes()
}

func settingsSchema() map[string]any {
	return map[string]any{
		"model_roles":       hubproto.ModelRoles,
		"instruction_roles": hubproto.InstructionRoles,
		"actions":           respond.ActionNames(),
		"max_instructions":  hubproto.MaxInstructions,
		"openrouter_url":    OpenRouterURL,
		"connection_kinds":  hubproto.ConnectionKinds,
	}
}

func (s *Server) handleAgentSettingsGet(w http.ResponseWriter, r *http.Request, c *opCtx) {
	writeJSON(w, http.StatusOK, map[string]any{"fleet": s.st.FleetAgentSettings(), "connections": s.connectionViews(), "schema": settingsSchema()})
}

func (s *Server) handleAgentSettingsPut(w http.ResponseWriter, r *http.Request, c *opCtx) {
	var a AgentSettings
	if err := readJSON(w, r, 128<<10, &a); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	a = a.clean()
	if err := a.Validate(s.st.Connections()); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.st.SetFleetAgentSettings(a); err != nil {
		writeErr(w, http.StatusInternalServerError, "store failed")
		return
	}
	s.st.Audit(c.user.Name, "settings.fleet_agents", "", summarizeSettings(a), c.ip)
	writeJSON(w, http.StatusOK, map[string]any{"fleet": s.st.FleetAgentSettings()})
}

func (s *Server) handleServerSettingsGet(w http.ResponseWriter, r *http.Request, c *opCtx) {
	id := r.PathValue("id")
	h := s.st.GetServer(id)
	if h == nil {
		writeErr(w, http.StatusNotFound, "no such server")
		return
	}
	eff := s.st.EffectiveSettings(id)
	for i := range eff.Connections {
		eff.Connections[i].APIKey = ""
	}
	var st hubproto.Status
	_ = json.Unmarshal(h.Status, &st)
	writeJSON(w, http.StatusOK, map[string]any{
		"server":      s.st.ServerAgentSettings(id),
		"fleet":       s.st.FleetAgentSettings(),
		"connections": s.connectionViews(),
		"effective":   eff,
		"applied": map[string]any{
			"accepts_settings": st.AcceptsSettings, "settings_version": st.SettingsVersion,
			"models": st.Models, "actions": st.Actions, "response_mode": st.ResponseMode, "root_response_mode": st.RootMode,
			"in_sync": st.AcceptsSettings && st.SettingsVersion == eff.Version,
		},
		"schema": settingsSchema(),
	})
}

func (s *Server) handleServerSettingsPut(w http.ResponseWriter, r *http.Request, c *opCtx) {
	id := r.PathValue("id")
	if s.st.GetServer(id) == nil {
		writeErr(w, http.StatusNotFound, "no such server")
		return
	}
	var a AgentSettings
	if err := readJSON(w, r, 128<<10, &a); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	a = a.clean()
	if err := a.Validate(s.st.Connections()); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.st.SetServerAgentSettings(id, a); err != nil {
		writeErr(w, http.StatusInternalServerError, "store failed")
		return
	}
	s.st.Audit(c.user.Name, "settings.server_agents", id, summarizeSettings(a), c.ip)
	writeJSON(w, http.StatusOK, map[string]any{"server": s.st.ServerAgentSettings(id)})
}

// summarizeSettings is the audit line: models and rules in full,
// instructions by size only.
func summarizeSettings(a AgentSettings) string {
	var parts []string
	keys := func(m map[string]string) []string {
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	roles := make([]string, 0, len(a.Models))
	for k := range a.Models {
		roles = append(roles, k)
	}
	sort.Strings(roles)
	for _, k := range roles {
		r := a.Models[k]
		parts = append(parts, "model."+k+"="+r.Connection+"/"+r.Model)
	}
	for _, k := range keys(a.Instructions) {
		parts = append(parts, fmt.Sprintf("instructions.%s=%d chars", k, len(a.Instructions[k])))
	}
	for _, k := range keys(a.Approvals) {
		parts = append(parts, "action."+k+"="+a.Approvals[k])
	}
	if a.ResponseMode != "" {
		parts = append(parts, "response_mode="+a.ResponseMode)
	}
	if len(parts) == 0 {
		return "cleared"
	}
	return strings.Join(parts, " ")
}
