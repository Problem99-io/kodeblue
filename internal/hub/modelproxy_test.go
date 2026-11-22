package hub

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/config"
	"github.com/Problem99-io/kodeblue/internal/blue/hublink"
	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
	"github.com/Problem99-io/kodeblue/internal/blue/llm"
)

// upstream is a model endpoint that records what reached it.
type upstream struct {
	mu     sync.Mutex
	auth   []string
	paths  []string
	bodies []string
}

func (u *upstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	u.mu.Lock()
	u.auth = append(u.auth, r.Header.Get("Authorization"))
	u.paths = append(u.paths, r.URL.RequestURI())
	u.bodies = append(u.bodies, string(b))
	u.mu.Unlock()
	if strings.Contains(string(b), `"stream":true`) {
		w.Header().Set("Content-Type", "text/event-stream")
		for _, ev := range []string{`{"choices":[{"delta":{"content":"hel"}}]}`, `{"choices":[{"delta":{"content":"lo"}}]}`, "[DONE]"} {
			_, _ = io.WriteString(w, "data: "+ev+"\n\n")
			w.(http.Flusher).Flush()
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Path == "/v1/models" {
		_, _ = io.WriteString(w, `{"data":[{"id":"small-model"}]}`)
		return
	}
	_, _ = io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"hello from the model"}}],"usage":{"prompt_tokens":3,"completion_tokens":4}}`)
}

const providerKey = "sk-provider-secret"

// proxyHub is a hub with one connection, picked as the fleet default, and
// one enrolled server that uses the model proxy.
func proxyHub(t *testing.T) (*Server, *Store, *httptest.Server, *upstream, hubproto.EnrollResponse) {
	t.Helper()
	srv, st, ts := newHubWith(t, allowLoopback)
	up := &upstream{}
	model := httptest.NewServer(up)
	t.Cleanup(model.Close)
	if err := st.setConnections([]hubproto.Connection{{ID: "main", Kind: hubproto.ConnectionKinds[0], BaseURL: model.URL, APIKey: providerKey}}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetFleetAgentSettings(AgentSettings{Models: map[string]hubproto.ModelRef{hubproto.RoleDefault: {Connection: "main", Model: "small-model"}}}); err != nil {
		t.Fatal(err)
	}
	er, body := enroll(t, st, ts, "web-1", true)
	if er.InferenceKey != "" || er.Inference != nil || strings.Contains(body, providerKey) {
		t.Fatalf("enrollment handed a model key to a proxy server: %s", body)
	}
	return srv, st, ts, up, er
}

func enroll(t *testing.T, st *Store, ts *httptest.Server, name string, proxy bool) (hubproto.EnrollResponse, string) {
	t.Helper()
	_, tok, _ := st.CreateServer(name, "test", time.Hour)
	code, body := do(t, ts.Client(), "POST", ts.URL+hubproto.PathEnroll, "", "", hubproto.EnrollRequest{Token: tok, ModelProxy: proxy})
	if code != 200 {
		t.Fatalf("enroll: %d %s", code, body)
	}
	var er hubproto.EnrollResponse
	_ = json.Unmarshal(body, &er)
	return er, string(body)
}

func syncSettings(t *testing.T, ts *httptest.Server, key string, proxy bool) *hubproto.Settings {
	t.Helper()
	return syncStatus(t, ts, key, hubproto.Status{Version: "0.3.0", AcceptsSettings: true, ModelProxy: proxy})
}

func syncStatus(t *testing.T, ts *httptest.Server, key string, status hubproto.Status) *hubproto.Settings {
	t.Helper()
	proxy := status.ModelProxy
	code, body := do(t, ts.Client(), "POST", ts.URL+hubproto.PathSync, key, "", hubproto.SyncRequest{Status: status})
	if code != 200 {
		t.Fatalf("sync: %d %s", code, body)
	}
	if proxy && strings.Contains(string(body), providerKey) {
		t.Fatalf("sync handed a model key to a proxy server: %s", body)
	}
	var resp hubproto.SyncResponse
	_ = json.Unmarshal(body, &resp)
	return resp.Settings
}

func TestModelProxySettingsCarryNoKeys(t *testing.T) {
	srv, st, ts, _, er := proxyHub(t)
	s := syncSettings(t, ts, er.APIKey, true)
	if s == nil || len(s.Connections) != 1 || !s.Connections[0].ViaHub || s.Connections[0].BaseURL != "" || s.Connections[0].APIKey != "" {
		t.Fatalf("proxy settings %+v", s)
	}
	// A server on the proxy cannot get the keys back by claiming to be older.
	if again := syncSettings(t, ts, er.APIKey, false); again == nil || again.Version != s.Version || again.Connections[0].APIKey != "" {
		t.Fatalf("a proxy server asking as an older one got %+v", again)
	}

	// An older server still gets the key until it is upgraded, and the two
	// forms have different versions, so an upgrade resyncs.
	old, body := enroll(t, st, ts, "old-1", false)
	if old.InferenceKey != providerKey {
		t.Fatalf("older server enrollment: %s", body)
	}
	legacy := syncSettings(t, ts, old.APIKey, false)
	if legacy == nil || legacy.Connections[0].APIKey != providerKey || legacy.Version == s.Version {
		t.Fatalf("legacy settings %+v", legacy)
	}
	if srv.modelKeys(*st.GetServer(old.ServerID)) != keysOld || srv.modelKeys(*st.GetServer(er.ServerID)) != "" {
		t.Fatal("model_keys flag")
	}
	// A key an older enrollment left on a server that now uses the proxy.
	syncStatus(t, ts, er.APIKey, hubproto.Status{Version: "0.3.0", AcceptsSettings: true, ModelProxy: true, InferenceKeySum: hubproto.KeySum(providerKey)})
	if why := srv.modelKeys(*st.GetServer(er.ServerID)); why != keysStale {
		t.Fatalf("stale key: %q", why)
	}
	syncStatus(t, ts, er.APIKey, hubproto.Status{Version: "0.3.0", AcceptsSettings: true, ModelProxy: true, InferenceKeySum: hubproto.KeySum("sk-its-own")})
	if why := srv.modelKeys(*st.GetServer(er.ServerID)); why != "" {
		t.Fatalf("a server's own endpoint key flagged: %q", why)
	}
	// An older server the hub sends no connection key to holds none.
	other, _ := enroll(t, st, ts, "own-endpoint", false)
	syncStatus(t, ts, other.APIKey, hubproto.Status{Version: "0.3.0"})
	if why := srv.modelKeys(*st.GetServer(other.ServerID)); why != "" {
		t.Fatalf("older server without hub settings flagged: %q", why)
	}

	// model-keys off: no server gets a key, at sync or enrollment.
	_ = st.SetSetting(SettingModelKeys, "off")
	if off := syncSettings(t, ts, old.APIKey, false); off == nil || off.Connections[0].APIKey != "" || !off.Connections[0].ViaHub {
		t.Fatalf("model keys off still sent %+v", off)
	}
	if late, body := enroll(t, st, ts, "old-2", false); late.InferenceKey != "" || strings.Contains(body, providerKey) {
		t.Fatalf("model keys off still enrolled with a key: %s", body)
	}
	if srv.modelKeys(*st.GetServer(old.ServerID)) != "" {
		t.Fatal("model_keys flag with keys off")
	}
}

func TestModelProxyDirectConnection(t *testing.T) {
	srv, st, ts, _, er := proxyHub(t)
	c, csrf := signIn(t, st, ts)
	conns := ts.URL + "/api/settings/connections/main"
	put := func(body map[string]any) int {
		code, _ := do(t, c, "PUT", conns, "", csrf, body)
		return code
	}
	// Marking it direct hands its key to servers: only with the key pasted again.
	if code := put(map[string]any{"name": "main", "base_url": "https://gw.internal.example", "api_key": "sk-new", "direct": false}); code != 200 {
		t.Fatalf("edit: %d", code)
	}
	if code := put(map[string]any{"name": "main", "base_url": "https://gw.internal.example", "direct": true}); code != 400 {
		t.Fatalf("direct without the key again: %d", code)
	}
	if code := put(map[string]any{"name": "main", "base_url": "https://gw.internal.example", "api_key": "sk-new", "direct": true}); code != 200 {
		t.Fatalf("direct with the key: %d", code)
	}
	s := syncSettings(t, ts, er.APIKey, true)
	if s == nil || s.Connections[0].ViaHub || s.Connections[0].APIKey != "sk-new" {
		t.Fatalf("direct connection %+v", s)
	}
	if why := srv.modelKeys(*st.GetServer(er.ServerID)); why != keysDirect {
		t.Fatalf("direct connection key flag: %q", why)
	}
	if code, _ := do(t, ts.Client(), "POST", ts.URL+hubproto.PathModels+"main/v1/chat/completions", er.APIKey, "", map[string]any{"model": "small-model"}); code != 404 {
		t.Fatalf("the hub proxied a direct connection: %d", code)
	}
}

func TestModelProxyLeavesModelsOnEachServerDirect(t *testing.T) {
	srv, st, ts, _, er := proxyHub(t)
	srv.opt.EndpointAllow = nil // 127.0.0.1 is then a model on each server, not one the hub reaches
	_ = st.setConnections([]hubproto.Connection{{ID: "main", Kind: hubproto.ConnectionKinds[0], BaseURL: "http://127.0.0.1:11434", APIKey: "ollama"}})
	srv.grants = grantCache{}
	s := syncSettings(t, ts, er.APIKey, true)
	if c := s.Connections[0]; c.ViaHub || c.BaseURL != "http://127.0.0.1:11434" {
		t.Fatalf("a model on each server went via the hub: %+v", c)
	}
	if code, _ := do(t, ts.Client(), "POST", ts.URL+hubproto.PathModels+"main/v1/chat/completions", er.APIKey, "", map[string]any{"model": "small-model"}); code != 404 {
		t.Fatalf("the hub proxied a model on each server: %d", code)
	}
}

func TestModelProxyAddsTheKeyAndChecksTheModel(t *testing.T) {
	srv, st, ts, up, er := proxyHub(t)
	c := ts.Client()
	chat := ts.URL + hubproto.PathModels + "main/v1/chat/completions"

	code, body := do(t, c, "POST", chat, er.APIKey, "", map[string]any{"model": "small-model", "messages": []any{}})
	if code != 200 || !strings.Contains(string(body), "hello from the model") {
		t.Fatalf("proxied call: %d %s", code, body)
	}
	if code, _ := do(t, c, "GET", ts.URL+hubproto.PathModels+"main/v1/models?provider=x&extra=1", er.APIKey, "", nil); code != 200 {
		t.Fatalf("models: %d", code)
	}
	if code, _ := do(t, c, "POST", chat+"?api-version=x", er.APIKey, "", map[string]any{"model": "small-model"}); code != 200 {
		t.Fatalf("chat with a query: %d", code)
	}
	up.mu.Lock()
	if len(up.auth) != 3 || up.auth[0] != "Bearer "+providerKey || up.paths[1] != "/v1/models?provider=x" || up.paths[2] != "/v1/chat/completions" {
		t.Fatalf("upstream saw auth %v paths %v", up.auth, up.paths)
	}
	if !strings.Contains(up.bodies[0], `"model":"small-model"`) {
		t.Fatalf("upstream body %s", up.bodies[0])
	}
	for _, a := range up.auth {
		if strings.Contains(a, er.APIKey) {
			t.Fatal("the server's hub key reached the model endpoint")
		}
	}
	up.mu.Unlock()

	for _, tc := range []struct {
		name, url, key string
		body           any
		want           int
	}{
		{"no key", chat, "", map[string]any{"model": "small-model"}, 401},
		{"model not picked", chat, er.APIKey, map[string]any{"model": "expensive-model"}, 403},
		{"not JSON", chat, er.APIKey, "x", 403},
		{"case variant", chat, er.APIKey, json.RawMessage(`{"model":"expensive-model","Model":"small-model"}`), 403},
		{"duplicate", chat, er.APIKey, json.RawMessage(`{"model":"expensive-model","model":"small-model"}`), 403},
		{"fallback models", chat, er.APIKey, json.RawMessage(`{"model":"small-model","models":["expensive-model"]}`), 403},
		{"provider routing", chat, er.APIKey, json.RawMessage(`{"model":"small-model","provider":{"order":["x"]}}`), 403},
		{"valid", chat, er.APIKey, json.RawMessage(`{"model":"small-model","stream":false}`), 200},
		{"unknown connection", ts.URL + hubproto.PathModels + "other/v1/chat/completions", er.APIKey, map[string]any{"model": "small-model"}, 404},
		{"other path", ts.URL + hubproto.PathModels + "main/v1/embeddings", er.APIKey, map[string]any{"model": "small-model"}, 404},
	} {
		if code, b := do(t, c, "POST", tc.url, tc.key, "", tc.body); code != tc.want {
			t.Errorf("%s: %d %s, want %d", tc.name, code, b, tc.want)
		}
	}

	up.mu.Lock()
	for _, b := range up.bodies {
		if strings.Contains(b, "expensive-model") {
			t.Fatalf("a refused request reached the endpoint: %s", b)
		}
	}
	up.mu.Unlock()

	// A model picked later is allowed at once (the grant cache follows
	// settings), and the one the server still runs until it applies the new
	// settings, so a running session is not cut off.
	proxied := hubproto.Status{Version: "0.3.0", AcceptsSettings: true, ModelProxy: true}
	v1 := syncStatus(t, ts, er.APIKey, proxied).Version
	proxied.SettingsVersion = v1
	syncStatus(t, ts, er.APIKey, proxied)
	_ = st.SetFleetAgentSettings(AgentSettings{Models: map[string]hubproto.ModelRef{hubproto.RoleDefault: {Connection: "main", Model: "other-model"}}})
	for _, m := range []string{"other-model", "small-model"} {
		if code, _ := do(t, c, "POST", chat, er.APIKey, "", map[string]any{"model": m}); code != 200 {
			t.Fatalf("%s before the server applied the change: %d", m, code)
		}
	}
	v2 := syncStatus(t, ts, er.APIKey, proxied)
	if v2 == nil || v2.Version == v1 {
		t.Fatalf("new settings not sent: %+v", v2)
	}
	proxied.SettingsVersion = v2.Version
	syncStatus(t, ts, er.APIKey, proxied)
	if code, _ := do(t, c, "POST", chat, er.APIKey, "", map[string]any{"model": "small-model"}); code != 403 {
		t.Fatalf("the old model after the server applied the change: %d", code)
	}
	if code, _ := do(t, c, "POST", chat, er.APIKey, "", map[string]any{"model": "other-model"}); code != 200 {
		t.Fatalf("newly picked model: %d", code)
	}

	// The per-server limit applies before the body is read.
	for i := 0; i < modelProxyPerServer; i++ {
		srv.modelSlot(er.ServerID)
	}
	if code, _ := do(t, c, "POST", chat, er.APIKey, "", "not even JSON"); code != 429 {
		t.Fatalf("over the limit: %d", code)
	}
	for i := 0; i < modelProxyPerServer; i++ {
		srv.releaseModelSlot(er.ServerID)
	}

	// Revoking the server ends its model access with everything else.
	_ = st.Revoke(er.ServerID)
	if code, _ := do(t, c, "POST", chat, er.APIKey, "", map[string]any{"model": "small-model"}); code != 401 {
		t.Fatalf("revoked server: %d", code)
	}
}

func TestModelProxyLimitsCallsPerServer(t *testing.T) {
	srv, _, _, _, _ := proxyHub(t)
	for i := 0; i < modelProxyPerServer; i++ {
		if !srv.modelSlot("a") {
			t.Fatalf("slot %d refused", i)
		}
	}
	if srv.modelSlot("a") || !srv.modelSlot("b") {
		t.Fatal("per-server limit")
	}
	srv.releaseModelSlot("a")
	if !srv.modelSlot("a") {
		t.Fatal("released slot not reusable")
	}
}

// The whole path a server's triage takes: model client → loopback
// forwarder (token) → hub (server key) → endpoint (provider key). The
// server's config holds no provider key at any point.
func TestModelForwarderEndToEnd(t *testing.T) {
	_, _, ts, up, er := proxyHub(t)
	s := syncSettings(t, ts, er.APIKey, true)

	dir := t.TempDir()
	keyFile := filepath.Join(dir, "hub.key")
	_ = os.WriteFile(keyFile, []byte(er.APIKey+"\n"), 0o600)
	cfg := config.Config{}
	cfg.Hub.URL, cfg.Hub.KeyFile, cfg.Hub.AcceptSettings = ts.URL, keyFile, true
	cfg.Server.StateDir = dir
	if err := cfg.SaveHubSettings(s); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(cfg.HubSettingsPath())
	if strings.Contains(string(raw), providerKey) {
		t.Fatal("the saved hub settings hold the provider key")
	}
	cfg = cfg.WithHubSettings()
	if !cfg.UsesHubModels() || cfg.ModelsReady() != nil || cfg.ModelsRunnable() == nil {
		t.Fatalf("readiness: uses=%v ready=%v runnable=%v", cfg.UsesHubModels(), cfg.ModelsReady(), cfg.ModelsRunnable())
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fw, err := hublink.StartModelForwarder(ctx, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Inference.HubProxyURL, cfg.Inference.HubProxyToken = fw.URL, fw.Token
	if err := cfg.ModelsRunnable(); err != nil {
		t.Fatal(err)
	}
	base, key, err := cfg.Endpoint("main")
	if err != nil || !strings.HasPrefix(base, "http://127.0.0.1:") || key != fw.Token {
		t.Fatalf("endpoint %q %q %v", base, key, err)
	}
	if k := cfg.GatewayKeys()["gateway:main"]; k != fw.Token {
		t.Fatalf("engine key %q", k)
	}

	resp, err := llm.New(base, key).Chat(ctx, llm.Request{Model: "small-model", Messages: []llm.Message{{Role: "user", Content: "hi"}}})
	if err != nil || !strings.Contains(resp.Content, "hello from the model") {
		t.Fatalf("chat through the forwarder: %+v %v", resp, err)
	}
	up.mu.Lock()
	if last := up.auth[len(up.auth)-1]; last != "Bearer "+providerKey {
		t.Fatalf("endpoint saw %q", last)
	}
	up.mu.Unlock()

	// A streamed answer comes through as events.
	sreq, _ := http.NewRequest("POST", base+"/v1/chat/completions", strings.NewReader(`{"model":"small-model","stream":true,"messages":[]}`))
	sreq.Header.Set("Authorization", "Bearer "+key)
	sreq.Header.Set("Content-Type", "application/json")
	sresp, err := http.DefaultClient.Do(sreq)
	if err != nil {
		t.Fatal(err)
	}
	sb, _ := io.ReadAll(sresp.Body)
	sresp.Body.Close()
	if sresp.Header.Get("Content-Type") != "text/event-stream" || !strings.Contains(string(sb), `"content":"lo"`) || !strings.Contains(string(sb), "data: [DONE]") {
		t.Fatalf("stream: %s %q", sresp.Header.Get("Content-Type"), sb)
	}

	// The forwarder takes only its own token and only the two model paths.
	for _, tc := range []struct{ method, path, tok string }{
		{"POST", "/main/v1/chat/completions", "wrong"},
		{"POST", "/main/v1/chat/completions", er.APIKey},
		{"GET", "/main/v1/chat/completions", fw.Token},
		{"POST", "/../sync", fw.Token},
	} {
		req, _ := http.NewRequest(tc.method, fw.URL+tc.path, strings.NewReader(`{"model":"small-model"}`))
		req.Header.Set("Authorization", "Bearer "+tc.tok)
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode != 401 && r.StatusCode != 404 {
			t.Errorf("%s %s with %q: %d", tc.method, tc.path, tc.tok, r.StatusCode)
		}
	}
}

func TestKeepModelHeaders(t *testing.T) {
	resp := &http.Response{Header: http.Header{"Content-Type": {"text/event-stream"}, "X-Request-Id": {"req-1"},
		"X-Openrouter-Request-Id": {"or-1"}, "Set-Cookie": {"a=b"}, "X-Upstream-Secret": {"s"}}}
	_ = keepModelHeaders(resp)
	if resp.Header.Get("X-Request-Id") != "req-1" || resp.Header.Get("X-Openrouter-Request-Id") != "or-1" ||
		resp.Header.Get("Set-Cookie") != "" || resp.Header.Get("X-Upstream-Secret") != "" {
		t.Fatalf("kept %v", resp.Header)
	}
}

// The hub keeps the model choices of the last five settings versions it
// sent each server.
func TestRecordSentKeepsTheLastFive(t *testing.T) {
	_, st, _, _, er := proxyHub(t)
	for i := 0; i < 7; i++ {
		st.recordSent(er.ServerID, &hubproto.Settings{Version: fmt.Sprint("v", i), Models: map[string]hubproto.ModelRef{"default": {Connection: "main", Model: fmt.Sprint("m", i)}}}, "v0")
	}
	var n int
	_ = st.db.QueryRow(`SELECT COUNT(*) FROM sent_settings WHERE server_id=?`, er.ServerID).Scan(&n)
	// The last five, and v0, which the server still runs.
	if n != 6 || st.sentModels(er.ServerID, "v6")["default"].Model != "m6" || st.sentModels(er.ServerID, "v0")["default"].Model != "m0" {
		t.Fatalf("%d versions kept, v6 %+v", n, st.sentModels(er.ServerID, "v6"))
	}
}
