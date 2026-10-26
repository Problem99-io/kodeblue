package hub

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
)

func TestAgentSettingsFlow(t *testing.T) {
	// The test model endpoints listen on loopback, which the hub refuses
	// unless allowed.
	_, st, ts := newHubWith(t, func(o *Options) { o.EndpointAllow = loopbackProxies })
	_ = st.AddUser("alice", "correct horse battery")
	jar, _ := cookiejar.New(nil)
	c := ts.Client()
	c.Jar = jar
	code, b := do(t, c, "POST", ts.URL+"/api/login", "", "", map[string]string{"name": "alice", "password": "correct horse battery"})
	if code != 200 {
		t.Fatalf("login: %d %s", code, b)
	}
	var me struct {
		CSRF string `json:"csrf"`
	}
	_ = json.Unmarshal(b, &me)
	_, tok, _ := st.CreateServer("web-1", "test", time.Hour)
	srv, key, err := st.Enroll(tok, "web-1", "")
	if err != nil {
		t.Fatal(err)
	}
	put := func(path string, body any) (int, []byte) { return do(t, c, "PUT", ts.URL+path, "", me.CSRF, body) }

	// An OpenRouter-shaped catalog and an inference-manager-shaped one.
	models := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" || r.Header.Get("Authorization") != "Bearer sk-or-test" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"data":[{"id":"vendor/strong","name":"Strong","context_length":200000,"pricing":{"prompt":"0.000003","completion":"0.000015"}},{"id":"vendor/small","supported_parameters":["temperature"]},{"id":"bad id"}]}`))
	}))
	defer models.Close()
	im := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer im-test" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"data":[{"id":"glm-flash","provider":"Z-AI","display_name":"GLM Flash","context_window":128000,"pricing":{"input_price_per_m_token":0.1,"output_price_per_m_token":0.4}},{"id":"kimi-k3","provider":"moonshotai"}]}`))
	}))
	defer im.Close()
	post := func(path string, body any) (int, []byte) { return do(t, c, "POST", ts.URL+path, "", me.CSRF, body) }

	if code, _ := do(t, c, "POST", ts.URL+"/api/settings/connections", "", "", map[string]any{"kind": "openrouter", "base_url": models.URL, "api_key": "k"}); code != 403 {
		t.Fatalf("connection without csrf: %d", code)
	}
	for _, bad := range []map[string]any{
		{"kind": "openai-compatible", "base_url": "ftp://x", "api_key": "k"},
		{"kind": "anthropic", "base_url": models.URL, "api_key": "k"},
		{"kind": "openai-compatible", "base_url": models.URL},
	} {
		if code, _ := post("/api/settings/connections", bad); code != 400 {
			t.Errorf("accepted connection %v: %d", bad, code)
		}
	}
	var created struct {
		ID string `json:"id"`
	}
	code, b = post("/api/settings/connections", map[string]any{"kind": "openrouter", "name": "OpenRouter", "base_url": models.URL + "/v1/", "api_key": "sk-or-test"})
	_ = json.Unmarshal(b, &created)
	if code != 200 || created.ID != "openrouter" || strings.Contains(string(b), "sk-or-test") || !strings.Contains(string(b), `"has_key":true`) {
		t.Fatalf("add openrouter: %d %s", code, b)
	}
	if code, b = post("/api/settings/connections", map[string]any{"kind": "inference-manager", "name": "Inference manager", "base_url": im.URL, "api_key": "im-test"}); code != 200 || !strings.Contains(string(b), `"id":"inference-manager"`) {
		t.Fatalf("add im: %d %s", code, b)
	}
	if code, b = post("/api/settings/connections", map[string]any{"kind": "openai-compatible", "name": "OpenRouter", "base_url": "http://127.0.0.1:9", "api_key": "dead"}); code != 200 || !strings.Contains(string(b), `"id":"openrouter-2"`) {
		t.Fatalf("add a third with a taken name: %d %s", code, b)
	}
	// An empty key keeps the stored one; the base URL lost its /v1.
	if code, _ := put("/api/settings/connections/openrouter", map[string]any{"name": "OR", "base_url": models.URL}); code != 200 {
		t.Fatalf("edit: %d", code)
	}
	if conn, _ := st.Connection("openrouter"); conn.APIKey != "sk-or-test" || conn.BaseURL != models.URL || conn.Name != "OR" {
		t.Fatalf("after edit: %+v", conn)
	}
	if _, b := post("/api/settings/connections/openrouter/test", nil); !strings.Contains(string(b), `"models":2`) {
		t.Fatalf("test connection: %s", b)
	}

	// One catalog across connections; the dead one is reported, not fatal.
	_, b = do(t, c, "GET", ts.URL+"/api/settings/models", "", "", nil)
	var ml struct {
		Models []ModelInfo       `json:"models"`
		Errors map[string]string `json:"errors"`
	}
	_ = json.Unmarshal(b, &ml)
	if len(ml.Models) != 4 || ml.Errors["openrouter-2"] == "" || len(ml.Errors) != 1 {
		t.Fatalf("catalog: %s", b)
	}
	byID := map[string]ModelInfo{}
	for _, m := range ml.Models {
		byID[m.Connection+"/"+m.ID] = m
	}
	if m := byID["openrouter/vendor/strong"]; m.ContextLength != 200000 || m.PromptUSD < 2.99 || m.PromptUSD > 3.01 {
		t.Fatalf("openrouter model: %+v", m)
	}
	if !byID["openrouter/vendor/small"].NoTools || byID["openrouter/vendor/strong"].NoTools {
		t.Fatalf("tool support: %+v", byID)
	}
	if m := byID["inference-manager/glm-flash"]; m.Provider != "z-ai" || m.Name != "GLM Flash" || m.ContextLength != 128000 || m.PromptUSD != 0.1 || m.CompletionUSD != 0.4 {
		t.Fatalf("im model keeps its provider: %+v", m)
	}

	for _, bad := range []AgentSettings{
		{Models: map[string]hubproto.ModelRef{"root": {Connection: "openrouter", Model: "m"}}},
		{Models: map[string]hubproto.ModelRef{"triage": {Connection: "openrouter", Model: "two words"}}},
		{Models: map[string]hubproto.ModelRef{"triage": {Connection: "nowhere", Model: "m"}}},
		{Models: map[string]hubproto.ModelRef{"triage": {Connection: "openrouter", Provider: "Bad Label", Model: "m"}}},
		{Instructions: map[string]string{"triage": "x"}},
		{Instructions: map[string]string{"all": strings.Repeat("a", hubproto.MaxInstructions+1)}},
		{Approvals: map[string]string{"format_disk": "auto"}},
		{Approvals: map[string]string{"block_ip": "always"}},
	} {
		if code, _ := put("/api/settings/agents", bad); code != 400 {
			t.Errorf("accepted %+v: %d", bad, code)
		}
	}
	fleet := AgentSettings{
		Models: map[string]hubproto.ModelRef{
			"default":   {Connection: "inference-manager", Provider: "z-ai", Model: "glm-flash"},
			"responder": {Connection: "openrouter", Model: "vendor/strong"},
			"reviewer":  {Model: " "},
		},
		Instructions: map[string]string{"all": "Our maintenance window is Sunday 02:00-04:00 UTC."},
		Approvals:    map[string]string{"block_ip": "approve", "lock_user": "off"},
	}
	if code, b := put("/api/settings/agents", fleet); code != 200 || strings.Contains(string(b), "reviewer") {
		t.Fatalf("fleet: %d %s", code, b)
	}
	if code, b := put("/api/servers/"+srv.ID+"/settings", AgentSettings{Models: map[string]hubproto.ModelRef{"responder": {Connection: "openrouter", Model: "vendor/other"}}, Approvals: map[string]string{"block_ip": "auto"}}); code != 200 {
		t.Fatalf("server override: %d %s", code, b)
	}
	// A connection in use cannot be removed; an unused one can.
	if code, b := do(t, c, "DELETE", ts.URL+"/api/settings/connections/openrouter", "", me.CSRF, nil); code != 409 || !strings.Contains(string(b), "fleet") || !strings.Contains(string(b), "web-1") {
		t.Fatalf("delete in use: %d %s", code, b)
	}
	if code, _ := do(t, c, "DELETE", ts.URL+"/api/settings/connections/openrouter-2", "", me.CSRF, nil); code != 200 {
		t.Fatalf("delete unused: %d", code)
	}

	sync := func(accepts bool, version string) *hubproto.Settings {
		var resp hubproto.SyncResponse
		code, b := do(t, ts.Client(), "POST", ts.URL+hubproto.PathSync, key, "", hubproto.SyncRequest{Status: hubproto.Status{AcceptsSettings: accepts, SettingsVersion: version}})
		if code != 200 {
			t.Fatalf("sync: %d %s", code, b)
		}
		_ = json.Unmarshal(b, &resp)
		return resp.Settings
	}
	if s := sync(false, ""); s != nil {
		t.Fatalf("settings sent to a server that does not take them: %+v", s)
	}
	s := sync(true, "")
	if s == nil || s.Version == "" {
		t.Fatal("no settings for a server that takes them")
	}
	if len(s.Connections) != 2 || s.Connections[0].APIKey != "sk-or-test" || s.Connections[1].APIKey != "im-test" {
		t.Fatalf("connections: %+v", s.Connections)
	}
	if s.Models["default"].Model != "glm-flash" || s.Models["default"].Provider != "z-ai" || s.Models["responder"] != (hubproto.ModelRef{Connection: "openrouter", Model: "vendor/other"}) {
		t.Fatalf("models: %+v", s.Models)
	}
	if s.Approvals["block_ip"] != "auto" || s.Approvals["lock_user"] != "off" || !strings.Contains(s.Instructions["all"], "Sunday") {
		t.Fatalf("rules/instructions: %+v %+v", s.Approvals, s.Instructions)
	}
	if again := sync(true, s.Version); again != nil {
		t.Fatal("settings re-sent for the version the server has")
	}

	// The console never gets a key back.
	_, b = do(t, c, "GET", ts.URL+"/api/servers/"+srv.ID+"/settings", "", "", nil)
	if strings.Contains(string(b), "sk-or-test") || strings.Contains(string(b), "im-test") || !strings.Contains(string(b), `"vendor/other"`) {
		t.Fatalf("server settings view: %s", b)
	}
	for _, path := range []string{"/api/settings/agents", "/api/settings/connections", "/api/me"} {
		if _, b := do(t, c, "GET", ts.URL+path, "", "", nil); strings.Contains(string(b), "sk-or-test") || strings.Contains(string(b), "im-test") {
			t.Fatalf("%s leaks a key: %s", path, b)
		}
	}
	for _, e := range st.AuditLog(50) {
		if strings.Contains(e.Detail, "sk-or-test") || strings.Contains(e.Detail, "im-test") || strings.Contains(e.Detail, "Sunday") {
			t.Fatalf("audit leaks a secret or instruction text: %+v", e)
		}
	}

	// Enrollment hands over the fleet default model and its connection.
	_, tok2, _ := st.CreateServer("web-2", "test", time.Hour)
	var er hubproto.EnrollResponse
	_, b = do(t, ts.Client(), "POST", ts.URL+hubproto.PathEnroll, "", "", hubproto.EnrollRequest{Token: tok2, Name: "web-2"})
	_ = json.Unmarshal(b, &er)
	if er.Inference == nil || er.Inference.BaseURL != im.URL || er.Inference.Model != "glm-flash" || er.Inference.Provider != "z-ai" || er.InferenceKey != "im-test" {
		t.Fatalf("enroll defaults: %+v", er.Inference)
	}

	// Clearing everything yields an empty version, which the server applies
	// as "remove what you had".
	_, _ = put("/api/settings/agents", AgentSettings{})
	_, _ = put("/api/servers/"+srv.ID+"/settings", AgentSettings{})
	if cleared := sync(true, s.Version); cleared == nil || cleared.Version != "" || cleared.Connections != nil {
		t.Fatalf("clear: %+v", cleared)
	}
}

// The single fleet endpoint older hubs kept (and `fleet set inference-*`
// still writes) becomes the connection "default" and the default model.
func TestLegacyEndpointFolds(t *testing.T) {
	_, st, _ := newHub(t)
	_ = st.SetSetting(SettingInferenceURL, "https://gw.example/v1/")
	_ = st.SetSetting(SettingInferenceProvider, "z-ai")
	_ = st.SetSetting(SettingInferenceModel, "glm-flash")
	_ = st.SetSetting(SettingInferenceKey, "gw-key")
	_ = st.SetSetting(settingFleetAgents, `{"models":{"responder":"vendor/strong"}}`)
	conns := st.Connections()
	if len(conns) != 1 || conns[0] != (hubproto.Connection{ID: "default", Kind: hubproto.ConnInferenceManager, Name: "Default", BaseURL: "https://gw.example", APIKey: "gw-key"}) {
		t.Fatalf("folded: %+v", conns)
	}
	m := st.FleetAgentSettings().Models
	if m["default"] != (hubproto.ModelRef{Connection: "default", Provider: "z-ai", Model: "glm-flash"}) || m["responder"].Model != "vendor/strong" {
		t.Fatalf("models: %+v", m)
	}
	if st.Setting(SettingInferenceURL) != "" || st.Setting(SettingInferenceKey) != "" {
		t.Fatal("legacy settings left behind")
	}
	// A later `fleet set inference-key` updates the same connection.
	_ = st.SetSetting(SettingInferenceKey, "rotated")
	if c, _ := st.Connection("default"); c.APIKey != "rotated" || len(st.Connections()) != 1 {
		t.Fatalf("key rotation: %+v", c)
	}
}

func TestNewConnectionID(t *testing.T) {
	taken := []hubproto.Connection{{ID: "openrouter"}}
	for name, want := range map[string]string{
		"Acme inference manager EU": "acme-inference-manager",
		"OpenRouter":                "openrouter-2",
		"!!!":                       "im",
		strings.Repeat("x", 40):     strings.Repeat("x", 24),
	} {
		if got := newConnectionID(name, hubproto.ConnInferenceManager, taken); got != want {
			t.Errorf("%q: %q, want %q", name, got, want)
		}
	}
}

func TestResponseModeSetting(t *testing.T) {
	_, st, _ := newHub(t)
	_, tok, _ := st.CreateServer("web-1", "test", time.Hour)
	srv, _, err := st.Enroll(tok, "web-1", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := (AgentSettings{ResponseMode: "always"}).Validate(nil); err == nil {
		t.Fatal("bad response mode accepted")
	}
	_ = st.SetFleetAgentSettings(AgentSettings{ResponseMode: "recommend"})
	if got := st.EffectiveSettings(srv.ID); got.ResponseMode != "recommend" || got.Version == "" {
		t.Fatalf("fleet mode not delivered: %+v", got)
	}
	before := st.EffectiveSettings(srv.ID).Version
	_ = st.SetServerAgentSettings(srv.ID, AgentSettings{ResponseMode: "contain"})
	got := st.EffectiveSettings(srv.ID)
	if got.ResponseMode != "contain" || got.Version == before {
		t.Fatalf("server override not delivered or version unchanged: %+v", got)
	}
	if got := st.ServerAgentSettings(srv.ID); got.ResponseMode != "contain" {
		t.Fatalf("a mode-only override must be stored: %+v", got)
	}
	if s := summarizeSettings(AgentSettings{ResponseMode: "off"}); s != "response_mode=off" {
		t.Fatalf("audit line %q", s)
	}
}

// Tuning and protections reach the server merged: a server's value for a key
// wins, protected lists add up, and a PUT that leaves them out keeps them.
func TestServerSettingsTuningMergeAndKeep(t *testing.T) {
	_, st, _ := newHubWith(t, func(o *Options) {})
	_, tok, _ := st.CreateServer("web-1", "test", time.Hour)
	srv, _, err := st.Enroll(tok, "web-1", "")
	if err != nil {
		t.Fatal(err)
	}
	fleet := AgentSettings{Tuning: map[string]string{"budget.daily_usd": "3", "schedule.review_hours": "12"}, ProtectedUsers: []string{"deploy"}, MaxActionsPerHour: 5}
	if err := fleet.clean().Validate(nil); err != nil {
		t.Fatal(err)
	}
	_ = st.SetFleetAgentSettings(fleet)
	_ = st.SetServerAgentSettings(srv.ID, AgentSettings{Tuning: map[string]string{"budget.daily_usd": "8"}, ProtectedUsers: []string{"backup"}})
	eff := st.EffectiveSettings(srv.ID)
	if eff.Version == "" || eff.Tuning["budget.daily_usd"] != "8" || eff.Tuning["schedule.review_hours"] != "12" || eff.MaxActionsPerHour != 5 {
		t.Fatalf("effective: %+v", eff)
	}
	if strings.Join(eff.ProtectedUsers, ",") != "deploy,backup" {
		t.Fatalf("protected users %v", eff.ProtectedUsers)
	}
	// An older console saves only the agent fields: the rest is kept.
	body := []byte(`{"models":{},"instructions":{},"approvals":{},"response_mode":""}`)
	var a AgentSettings
	_ = json.Unmarshal(body, &a)
	if kept := keepUnsent(body, a, st.FleetAgentSettings()).clean(); kept.Tuning["budget.daily_usd"] != "3" || kept.MaxActionsPerHour != 5 || len(kept.ProtectedUsers) != 1 {
		t.Fatalf("a partial save dropped settings: %+v", kept)
	}
	for _, bad := range []AgentSettings{
		{Tuning: map[string]string{"detect.bruteforce_threshold": "100000"}},
		{Tuning: map[string]string{"server.root": "/"}},
		{ProtectedIPs: []string{"not-an-ip"}},
	} {
		if bad.clean().Validate(nil) == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}
