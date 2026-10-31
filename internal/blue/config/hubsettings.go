package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
)

// HubSettingsPath is where the hub link keeps the settings hub operators
// chose for this server. It belongs to the kodeblue user, so nothing in it
// may widen what the root-owned config allows.
func (c Config) HubSettingsPath() string {
	return filepath.Join(c.Server.StateDir, "hub-settings.json")
}

// ReadHubSettings returns the settings saved by the hub link, or nil.
func (c Config) ReadHubSettings() *hubproto.Settings {
	b, err := os.ReadFile(c.HubSettingsPath())
	if err != nil {
		return nil
	}
	var s hubproto.Settings
	if json.Unmarshal(b, &s) != nil {
		return nil
	}
	return &s
}

// SaveHubSettings stores settings from the hub (0600: an older hub sends
// endpoint keys in them). An empty Version removes them.
func (c Config) SaveHubSettings(s *hubproto.Settings) error {
	path := c.HubSettingsPath()
	if s == nil || s.Version == "" {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ModeCeiling is the highest response mode this server may run: [response]
// mode, or hub_max_mode when the hub's settings are accepted. Both are
// root-owned.
func (c Config) ModeCeiling() string {
	return c.Response.Ceiling(c.Hub.Enabled() && c.Hub.AcceptSettings)
}

// WithHubSettings returns the config with the saved hub settings applied,
// when [hub] accept_settings allows it. The daemon and the agents' MCP
// server use it; the root response helper must not.
func (c Config) WithHubSettings() Config {
	c.RootResponseMode = c.Response.Mode
	c.RootCVEFeed = c.CVEFeed
	if !c.Hub.Enabled() || !c.Hub.AcceptSettings {
		return c
	}
	if s := c.ReadHubSettings(); s != nil {
		c = c.applyHubSettings(s)
	}
	return c
}

func (c Config) applyHubSettings(s *hubproto.Settings) Config {
	c.HubSettingsVersion = s.Version
	c.Inference.Connections = map[string]hubproto.Connection{}
	for _, conn := range s.Connections {
		if !hubproto.ValidConnectionID(conn.ID) {
			continue
		}
		if conn.ViaHub {
			conn.BaseURL, conn.APIKey = "", ""
			c.Inference.Connections[conn.ID] = conn
		} else if strings.TrimSpace(conn.BaseURL) != "" {
			conn.BaseURL = strings.TrimRight(strings.TrimSpace(conn.BaseURL), "/")
			c.Inference.Connections[conn.ID] = conn
		}
	}
	c.Inference.Refs = map[string]hubproto.ModelRef{}
	for role, ref := range s.Models {
		if !slices.Contains(hubproto.ModelRoles, role) || strings.TrimSpace(ref.Model) == "" {
			continue
		}
		if _, ok := c.Inference.Connections[ref.Connection]; ok || ref.Connection == "" {
			c.Inference.Refs[role] = ref
		}
	}
	c.Agents.Instructions = cloneMap(c.Agents.Instructions)
	for role, text := range s.Instructions {
		if slices.Contains(hubproto.InstructionRoles, role) {
			c.Agents.Instructions[role] = text
		}
	}
	c.ActionRules = map[string]string{}
	for action, rule := range s.Approvals {
		if rule == hubproto.ActionAuto || rule == hubproto.ActionApprove || rule == hubproto.ActionOff {
			c.ActionRules[action] = rule
		}
	}
	// The hub's response mode can lower the root-owned one, and raise it up
	// to the root-owned [response] hub_max_mode.
	if r := hubproto.ModeRank(s.ResponseMode); r >= 0 && r <= hubproto.ModeRank(c.ModeCeiling()) {
		c.Response.Mode = s.ResponseMode
	}
	c.applyTuning(s.Tuning)
	c.applyProtections(s)
	return c
}

func cloneMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// ModelRef returns the model a role uses. The hub's choice for the role
// wins, then the hub's default, then the local [inference] settings
// (agent_models, agent_model; triage_model for triage; the escalation model
// for critical incidents). Critical falls back to the responder's model.
func (c Config) ModelRef(role string) hubproto.ModelRef {
	in := c.Inference
	if r, ok := in.Refs[role]; ok {
		return r
	}
	switch role {
	case hubproto.RoleCritical:
		if in.EscalationModel != "" {
			return hubproto.ModelRef{Provider: in.EscalationProvider, Model: in.EscalationModel}
		}
		return c.ModelRef(hubproto.RoleResponder)
	case hubproto.RoleDefault:
		return hubproto.ModelRef{Provider: in.Provider, Model: in.AgentModel}
	}
	if r, ok := in.Refs[hubproto.RoleDefault]; ok {
		return r
	}
	local := in.AgentModel
	if role == hubproto.RoleTriage {
		local = in.TriageModel
	} else if m := strings.TrimSpace(in.AgentModels[role]); m != "" {
		local = m
	}
	return hubproto.ModelRef{Provider: in.Provider, Model: local}
}

// ModelFor returns the model ID a role uses.
func (c Config) ModelFor(role string) string { return c.ModelRef(role).Model }

// EngineProvider is the provider name the agent runtime knows a ref's
// connection by: the label alone for the server's own endpoint,
// "<connection>:<label>" for a hub connection.
func (c Config) EngineProvider(r hubproto.ModelRef) string {
	if r.Connection == "" {
		if r.Provider != "" {
			return r.Provider
		}
		return c.Inference.Provider
	}
	p := r.Provider
	if p == "" {
		p = hubproto.DefaultProvider(c.Inference.Connections[r.Connection].Kind)
	}
	return r.Connection + ":" + p
}

// UsesHubModels reports whether a connection goes through the hub's model
// proxy, which needs the daemon's forwarder.
func (c Config) UsesHubModels() bool {
	for _, conn := range c.Inference.Connections {
		if conn.ViaHub {
			return true
		}
	}
	return false
}

// Endpoint returns the base URL and key of a connection; "" is the
// server's own [inference] endpoint. A connection via the hub is the
// daemon's loopback forwarder and its token: the server holds no key for it.
func (c Config) Endpoint(connection string) (baseURL, key string, err error) {
	if connection == "" {
		key, err = c.APIKey()
		return strings.TrimRight(strings.TrimSpace(c.Inference.BaseURL), "/"), key, err
	}
	conn, ok := c.Inference.Connections[connection]
	if !ok {
		return "", "", fmt.Errorf("unknown model connection %q", connection)
	}
	if conn.ViaHub {
		if c.Inference.HubProxyURL == "" {
			return "", "", fmt.Errorf("model connection %q goes through the hub, and the forwarder to it is not running", connection)
		}
		return c.Inference.HubProxyURL + "/" + connection, c.Inference.HubProxyToken, nil
	}
	if strings.TrimSpace(conn.APIKey) == "" {
		return "", "", fmt.Errorf("model connection %q has no API key", connection)
	}
	return conn.BaseURL, conn.APIKey, nil
}

// ModelsReady reports why the model layers cannot run, or nil: triage and
// the agents each need a model on an endpoint with a key, or on a hub
// connection while the server reports to a hub.
func (c Config) ModelsReady() error {
	return c.modelsReady(false)
}

// ModelsRunnable is ModelsReady for the running daemon: a hub connection
// also needs its forwarder.
func (c Config) ModelsRunnable() error {
	return c.modelsReady(true)
}

func (c Config) modelsReady(running bool) error {
	for _, role := range []string{hubproto.RoleTriage, hubproto.RoleResponder} {
		r := c.ModelRef(role)
		if strings.TrimSpace(r.Model) == "" {
			if role == hubproto.RoleTriage {
				return errors.New("no models: set [inference] triage_model and agent_model, or pick models on the hub")
			}
			return errors.New("no agent model: set [inference] agent_model, or pick one on the hub")
		}
		if conn := c.Inference.Connections[r.Connection]; r.Connection != "" && conn.ViaHub && !running {
			if !c.Hub.Enabled() {
				return fmt.Errorf("model connection %q goes through the hub, and this server has no hub", r.Connection)
			}
			continue
		}
		if _, _, err := c.Endpoint(r.Connection); err != nil {
			return err
		}
	}
	return nil
}

// GatewayKeys are the endpoint keys the agent runtime needs, by secrets
// slot: "gateway" for the server's own endpoint, "gateway:<id>" for each
// hub connection.
func (c Config) GatewayKeys() map[string]string {
	keys := map[string]string{}
	if k, err := c.APIKey(); err == nil {
		keys["gateway"] = k
	}
	for id := range c.Inference.Connections {
		if _, key, err := c.Endpoint(id); err == nil && key != "" {
			keys["gateway:"+id] = key
		}
	}
	return keys
}

// InstructionsFor returns the extra instructions for an agent role: the
// ones for every agent first, then the role's own.
func (c Config) InstructionsFor(role string) string {
	var parts []string
	for _, k := range []string{hubproto.RoleAll, role} {
		if t := strings.TrimSpace(c.Agents.Instructions[k]); t != "" {
			parts = append(parts, t)
		}
	}
	return strings.Join(parts, "\n\n")
}

// ActionRule is the effective rule for a containment action: auto, approve
// or off. The root policy is the ceiling: mode off or an action outside
// allowed_actions is off, and only mode contain can run anything without a
// human. The hub's rules may only move an action further toward off.
func (c Config) ActionRule(action string) string {
	p := c.Response
	if p.Mode == "off" || !slices.Contains(p.AllowedActions, action) {
		return hubproto.ActionOff
	}
	rule := hubproto.ActionApprove
	if p.Mode == "contain" {
		rule = hubproto.ActionAuto
	}
	switch c.ActionRules[action] {
	case hubproto.ActionOff:
		return hubproto.ActionOff
	case hubproto.ActionApprove:
		return hubproto.ActionApprove
	}
	return rule
}

// EffectiveModels reports the model each role uses now, as
// "<connection>/<model>" for hub connections.
func (c Config) EffectiveModels() map[string]string {
	out := map[string]string{}
	for _, role := range []string{hubproto.RoleTriage, hubproto.RoleLearner, hubproto.RoleResponder, hubproto.RoleReviewer, hubproto.RoleOperator, hubproto.RoleCritical} {
		r := c.ModelRef(role)
		if r.Model == "" {
			continue
		}
		if r.Connection != "" {
			out[role] = r.Connection + "/" + r.Model
		} else {
			out[role] = r.Model
		}
	}
	return out
}
