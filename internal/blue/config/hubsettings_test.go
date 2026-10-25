package config

import (
	"os"
	"testing"

	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
)

func TestActionRuleNeverLoosensRootPolicy(t *testing.T) {
	cases := []struct {
		mode, hub, want string
	}{
		{"recommend", "", hubproto.ActionApprove},
		{"recommend", hubproto.ActionAuto, hubproto.ActionApprove},
		{"recommend", hubproto.ActionOff, hubproto.ActionOff},
		{"contain", "", hubproto.ActionAuto},
		{"contain", hubproto.ActionAuto, hubproto.ActionAuto},
		{"contain", hubproto.ActionApprove, hubproto.ActionApprove},
		{"contain", hubproto.ActionOff, hubproto.ActionOff},
		{"off", hubproto.ActionAuto, hubproto.ActionOff},
		{"off", "", hubproto.ActionOff},
	}
	for _, tc := range cases {
		c := Default()
		c.Response.Mode = tc.mode
		c.ActionRules = map[string]string{"block_ip": tc.hub}
		if got := c.ActionRule("block_ip"); got != tc.want {
			t.Errorf("mode=%s hub=%q: got %s, want %s", tc.mode, tc.hub, got, tc.want)
		}
	}
	c := Default()
	c.Response.Mode = "contain"
	c.Response.AllowedActions = []string{"kill_process"}
	c.ActionRules = map[string]string{"block_ip": hubproto.ActionAuto}
	if got := c.ActionRule("block_ip"); got != hubproto.ActionOff {
		t.Errorf("action outside allowed_actions: got %s, want off", got)
	}
}

func TestHubSettingsOverlay(t *testing.T) {
	c := Default()
	c.Server.StateDir = t.TempDir()
	c.Hub.URL = "https://hub.example"
	c.Inference = Inference{BaseURL: "https://local.example", Provider: "openai-compatible", TriageModel: "local-small", AgentModel: "local-agent", APIKeyFile: "/nonexistent"}
	c.Agents.Instructions = map[string]string{"all": "local note"}

	s := &hubproto.Settings{
		Version: "v1",
		Connections: []hubproto.Connection{
			{ID: "or", Kind: hubproto.ConnOpenRouter, BaseURL: "https://openrouter.ai/api/", APIKey: "sk-or-test"},
			{ID: "im", Kind: hubproto.ConnInferenceManager, BaseURL: "https://im.example", APIKey: "im-key"},
			{ID: "BAD ID", Kind: hubproto.ConnOpenAI, BaseURL: "https://x.example"},
		},
		Models: map[string]hubproto.ModelRef{
			hubproto.RoleDefault:   {Connection: "im", Provider: "z-ai", Model: "glm-small"},
			hubproto.RoleResponder: {Connection: "or", Model: "vendor/strong"},
			hubproto.RoleCritical:  {Connection: "or", Model: "vendor/strongest"},
			hubproto.RoleReviewer:  {Connection: "gone", Model: "dropped"},
			"bogus":                {Model: "dropped"},
		},
		Instructions: map[string]string{hubproto.RoleResponder: "Page the on-call for anything on prod-db.", "bogus": "dropped"},
		Approvals:    map[string]string{"block_ip": hubproto.ActionOff, "lock_user": "sometimes"},
	}
	if err := c.SaveHubSettings(s); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(c.HubSettingsPath()); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("settings file mode: %v %v", st, err)
	}

	got := c.WithHubSettings()
	if got.HubSettingsVersion != "v1" || len(got.Inference.Connections) != 2 || got.Inference.Connections["or"].BaseURL != "https://openrouter.ai/api" {
		t.Fatalf("connections not applied: %+v", got.Inference.Connections)
	}
	if err := got.ModelsReady(); err != nil {
		t.Fatalf("models not ready: %v", err)
	}
	// Triage and the learner take the hub default; the reviewer's ref names
	// a connection that does not exist, so it falls back to the default too.
	for role, want := range map[string]string{hubproto.RoleTriage: "im:z-ai/glm-small", hubproto.RoleLearner: "im:z-ai/glm-small", hubproto.RoleReviewer: "im:z-ai/glm-small",
		hubproto.RoleResponder: "or:openrouter/vendor/strong", hubproto.RoleCritical: "or:openrouter/vendor/strongest"} {
		r := got.ModelRef(role)
		if p := got.EngineProvider(r) + "/" + r.Model; p != want {
			t.Errorf("%s: %s, want %s", role, p, want)
		}
	}
	if u, k, err := got.Endpoint("or"); err != nil || u != "https://openrouter.ai/api" || k != "sk-or-test" {
		t.Fatalf("endpoint: %q %q %v", u, k, err)
	}
	keys := got.GatewayKeys()
	if keys["gateway:or"] != "sk-or-test" || keys["gateway:im"] != "im-key" || keys["gateway"] != "" {
		t.Fatalf("gateway keys: %v", keys)
	}
	if m := got.EffectiveModels(); m[hubproto.RoleResponder] != "or/vendor/strong" {
		t.Fatalf("effective models: %v", m)
	}
	if want := "local note\n\nPage the on-call for anything on prod-db."; got.InstructionsFor(hubproto.RoleResponder) != want {
		t.Fatalf("instructions: %q", got.InstructionsFor(hubproto.RoleResponder))
	}
	if got.InstructionsFor(hubproto.RoleLearner) != "local note" || got.Agents.Instructions["bogus"] != "" {
		t.Fatalf("instructions leaked: %+v", got.Agents.Instructions)
	}
	if got.ActionRule("block_ip") != hubproto.ActionOff || got.ActionRules["lock_user"] != "" {
		t.Fatalf("rules: %+v", got.ActionRules)
	}
	// The original value is untouched (maps are copied).
	if c.Agents.Instructions["responder"] != "" || c.Inference.Refs != nil {
		t.Fatal("overlay mutated the base config")
	}

	// Opted out, or no hub: the file is ignored.
	off := c
	off.Hub.AcceptSettings = false
	if off.WithHubSettings().ModelFor(hubproto.RoleResponder) != "local-agent" {
		t.Fatal("accept_settings=false still applied hub settings")
	}
	nohub := c
	nohub.Hub.URL = ""
	if nohub.WithHubSettings().HubSettingsVersion != "" {
		t.Fatal("settings applied without a hub")
	}

	// An empty version clears them.
	if err := c.SaveHubSettings(&hubproto.Settings{}); err != nil {
		t.Fatal(err)
	}
	if c.ReadHubSettings() != nil || c.WithHubSettings().HubSettingsVersion != "" {
		t.Fatal("settings not cleared")
	}
}

func TestLocalModelRefs(t *testing.T) {
	c := Default()
	c.Inference = Inference{BaseURL: "https://local.example", APIKey: "k", Provider: "openai-compatible", TriageModel: "small", AgentModel: "agent",
		AgentModels: map[string]string{hubproto.RoleReviewer: "reviewer-model"}}
	if err := c.ModelsReady(); err != nil {
		t.Fatal(err)
	}
	for role, want := range map[string]string{hubproto.RoleTriage: "small", hubproto.RoleResponder: "agent", hubproto.RoleReviewer: "reviewer-model", hubproto.RoleCritical: "agent"} {
		if got := c.ModelFor(role); got != want {
			t.Errorf("%s: %s, want %s", role, got, want)
		}
	}
	if p := c.EngineProvider(c.ModelRef(hubproto.RoleResponder)); p != "openai-compatible" {
		t.Fatalf("local provider: %s", p)
	}
	c.Inference.EscalationProvider, c.Inference.EscalationModel = "openai-compatible", "big"
	if c.ModelFor(hubproto.RoleCritical) != "big" {
		t.Fatal("escalation model ignored")
	}
	c.Inference.APIKey, c.Inference.APIKeyFile, c.Inference.APIKeyEnv = "", "", ""
	if c.ModelsReady() == nil {
		t.Fatal("ready without a key")
	}
}

func TestHubResponseModeIsCappedByRoot(t *testing.T) {
	cases := []struct{ root, hub, want string }{
		{"contain", "", "contain"},
		{"contain", "recommend", "recommend"},
		{"contain", "off", "off"},
		{"recommend", "contain", "recommend"}, // never above the root policy
		{"recommend", "off", "off"},
		{"off", "contain", "off"},
		{"contain", "bogus", "contain"},
	}
	for _, tc := range cases {
		c := Default()
		c.Server.StateDir = t.TempDir()
		c.Hub.URL = "https://hub.example"
		c.Response.Mode = tc.root
		if err := c.SaveHubSettings(&hubproto.Settings{Version: "v1", ResponseMode: tc.hub}); err != nil {
			t.Fatal(err)
		}
		got := c.WithHubSettings()
		if got.Response.Mode != tc.want || got.RootResponseMode != tc.root {
			t.Errorf("root=%s hub=%q: mode %s (root %s), want %s", tc.root, tc.hub, got.Response.Mode, got.RootResponseMode, tc.want)
		}
	}
}
