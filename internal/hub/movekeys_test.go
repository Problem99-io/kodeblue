package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
)

// moveHub is a proxy hub whose model clients reach a test endpoint named
// http://models.test (an httptest server on loopback, which a server's own
// endpoint must not be).
func moveHub(t *testing.T) (*Server, *Store, *httptest.Server, *upstream, hubproto.EnrollResponse) {
	t.Helper()
	srv, st, ts, _, er := proxyHub(t)
	up := &upstream{}
	model := httptest.NewServer(up)
	t.Cleanup(model.Close)
	addr := strings.TrimPrefix(model.URL, "http://")
	tr := &http.Transport{DialContext: func(ctx context.Context, network, a string) (net.Conn, error) {
		if a != "models.test:80" {
			return nil, errors.New("unreachable")
		}
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}}
	srv.models.client = &http.Client{Transport: tr}
	srv.proxy = &http.Client{Transport: tr}
	return srv, st, ts, up, er
}

func moveKeys(t *testing.T, ts *httptest.Server, key string, req hubproto.MoveKeysRequest) (int, hubproto.MoveKeysResponse, string) {
	t.Helper()
	code, body := do(t, ts.Client(), "POST", ts.URL+hubproto.PathMoveKeys, key, "", req)
	var resp hubproto.MoveKeysResponse
	_ = json.Unmarshal(body, &resp)
	return code, resp, string(body)
}

func TestMoveKeysTakesOverTheServersEndpoint(t *testing.T) {
	srv, st, ts, up, er := moveHub(t)
	own := map[string]hubproto.ModelRef{hubproto.RoleTriage: {Model: "own-small"}, hubproto.RoleResponder: {Model: "own-big"}}
	code, resp, body := moveKeys(t, ts, er.APIKey, hubproto.MoveKeysRequest{BaseURL: "http://models.test", Key: "sk-own", Models: own})
	if code != 200 || !resp.Created || resp.Connection == "" || strings.Join(resp.Roles, ",") != "responder,triage" {
		t.Fatalf("move: %d %s", code, body)
	}
	conn, ok := st.Connection(resp.Connection)
	if !ok || conn.APIKey != "sk-own" || conn.BaseURL != "http://models.test" {
		t.Fatalf("connection %+v", conn)
	}
	if m := st.ServerAgentSettings(er.ServerID).Models; m[hubproto.RoleTriage] != (hubproto.ModelRef{Connection: resp.Connection, Model: "own-small"}) || m[hubproto.RoleResponder].Model != "own-big" {
		t.Fatalf("server models %+v", m)
	}
	// The server gets it through the hub, without the key, and its calls
	// reach the endpoint with the moved key.
	s := syncSettings(t, ts, er.APIKey, true)
	if s == nil || strings.Contains(mustJSON(s), "sk-own") {
		t.Fatalf("settings after the move %+v", s)
	}
	chat := ts.URL + hubproto.PathModels + resp.Connection + "/v1/chat/completions"
	if code, b := do(t, ts.Client(), "POST", chat, er.APIKey, "", map[string]any{"model": "own-small", "messages": []any{}}); code != 200 {
		t.Fatalf("call on the moved endpoint: %d %s", code, b)
	}
	up.mu.Lock()
	if last := up.auth[len(up.auth)-1]; last != "Bearer sk-own" {
		t.Fatalf("endpoint saw %q", last)
	}
	up.mu.Unlock()
	if a := st.AuditLog(5); !strings.Contains(a[0].Action+a[0].Detail, "server.keys_moved") {
		t.Fatalf("audit %+v", a[0])
	}

	// The same endpoint and key again: the same connection.
	if code, again, body := moveKeys(t, ts, er.APIKey, hubproto.MoveKeysRequest{BaseURL: "http://models.test/", Key: "sk-own", Models: own}); code != 200 || again.Created || again.Connection != resp.Connection {
		t.Fatalf("second move: %d %s", code, body)
	}
	// Another endpoint: one new connection per server.
	if code, _, body := moveKeys(t, ts, er.APIKey, hubproto.MoveKeysRequest{BaseURL: "http://models.test", Key: "sk-other"}); code != 422 {
		t.Fatalf("a second endpoint: %d %s", code, body)
	}
	_ = srv
}

func TestMoveKeysRefusals(t *testing.T) {
	_, st, ts, _, er := moveHub(t)
	n := len(st.Connections())
	for name, req := range map[string]hubproto.MoveKeysRequest{
		"on the server itself": {BaseURL: "http://127.0.0.1:11434", Key: "ollama"},
		"localhost":            {BaseURL: "http://localhost:8000", Key: "k"},
		"unreachable":          {BaseURL: "https://elsewhere.test", Key: "k"},
		"not a URL":            {BaseURL: "ftp://models.test", Key: "k"},
		"bad role":             {BaseURL: "http://models.test", Key: "k", Models: map[string]hubproto.ModelRef{"root": {Model: "x"}}},
	} {
		if code, _, body := moveKeys(t, ts, er.APIKey, req); code != 422 {
			t.Errorf("%s: %d %s", name, code, body)
		}
	}
	if len(st.Connections()) != n {
		t.Fatal("a refused move created a connection")
	}
	// Each attempt counts: the hub would otherwise probe addresses for it.
	if code, _, _ := moveKeys(t, ts, er.APIKey, hubproto.MoveKeysRequest{BaseURL: "https://elsewhere.test", Key: "k"}); code != 429 {
		t.Fatalf("sixth attempt within the hour: %d", code)
	}
}

// A key file an older enrollment left, holding the fleet default's key: the
// hub has it, so the server may drop it. An empty request only marks the
// server as calling its models through the hub, and says the hub's version.
func TestMoveKeysKeyOnlyAndNothing(t *testing.T) {
	srv, st, ts, _, _ := moveHub(t)
	old, _ := enroll(t, st, ts, "old-1", false)
	if code, resp, body := moveKeys(t, ts, old.APIKey, hubproto.MoveKeysRequest{Key: providerKey}); code != 200 || resp.Connection != "main" || resp.Created {
		t.Fatalf("key only: %d %s", code, body)
	}
	other, _ := enroll(t, st, ts, "old-2", false)
	if srv.usesProxy(other.ServerID, false) {
		t.Fatal("proxy before the move")
	}
	if code, resp, _ := moveKeys(t, ts, other.APIKey, hubproto.MoveKeysRequest{}); code != 200 || resp.Connection != "" || resp.HubVersion != hubproto.Version {
		t.Fatalf("empty move: %d %+v", code, resp)
	}
	if !srv.usesProxy(other.ServerID, false) {
		t.Fatal("an empty move did not mark the server")
	}
	if s := syncSettings(t, ts, other.APIKey, false); s == nil || s.Connections[0].APIKey != "" {
		t.Fatalf("keys after the move %+v", s)
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// One role naming a vendor makes the connection a multi-vendor gateway,
// whatever the order the roles arrive in; and a failed check tells the
// server nothing about how the endpoint answered.
func TestMoveKeysKindAndRefusalDetail(t *testing.T) {
	_, st, ts, _, er := moveHub(t)
	code, resp, body := moveKeys(t, ts, er.APIKey, hubproto.MoveKeysRequest{BaseURL: "http://models.test", Key: "sk-own", Models: map[string]hubproto.ModelRef{
		hubproto.RoleDefault: {Provider: "openai", Model: "big"}, hubproto.RoleCritical: {Provider: "anthropic", Model: "huge"}}})
	if code != 200 {
		t.Fatalf("move: %d %s", code, body)
	}
	c, _ := st.Connection(resp.Connection)
	if c.Kind != hubproto.ConnInferenceManager || st.ServerAgentSettings(er.ServerID).Models[hubproto.RoleCritical].Provider != "anthropic" {
		t.Fatalf("kind %s, models %+v", c.Kind, st.ServerAgentSettings(er.ServerID).Models)
	}
	other, _ := enroll(t, st, ts, "web-2", true)
	_, _, body = moveKeys(t, ts, other.APIKey, hubproto.MoveKeysRequest{BaseURL: "https://elsewhere.test", Key: "k"})
	if strings.Contains(body, "unreachable") || strings.Contains(body, "did not answer") {
		t.Fatalf("the refusal tells the server how the endpoint failed: %s", body)
	}
}

// Moves from one server at the same time still create one connection.
func TestMoveKeysConcurrent(t *testing.T) {
	_, st, ts, _, er := moveHub(t)
	n := len(st.Connections())
	done := make(chan int, 4)
	for i := 0; i < 4; i++ {
		go func(i int) {
			code, _ := do(t, ts.Client(), "POST", ts.URL+hubproto.PathMoveKeys, er.APIKey, "", hubproto.MoveKeysRequest{BaseURL: "http://models.test", Key: "sk-" + string(rune('a'+i))})
			done <- code
		}(i)
	}
	for i := 0; i < 4; i++ {
		<-done
	}
	if got := len(st.Connections()) - n; got != 1 {
		t.Fatalf("%d connections created", got)
	}
}

// A key no connection has, which the server holds without using: the hub
// keeps it aside so the server can delete its copy. An operator never sees
// it; they may make it a connection, only to the endpoint the server used
// it with, or delete it.
func TestMoveKeysKeepsUnknownKeys(t *testing.T) {
	_, st, ts, up, er := moveHub(t)
	code, resp, body := moveKeys(t, ts, er.APIKey, hubproto.MoveKeysRequest{Key: "sk-leftover", SeenWith: "http://models.test/v1"})
	if code != 200 || !resp.Kept || resp.Connection != "" || resp.HubVersion == "" {
		t.Fatalf("keep: %d %s", code, body)
	}
	// Again (an interrupted move): kept once.
	if code, resp, _ := moveKeys(t, ts, er.APIKey, hubproto.MoveKeysRequest{Key: "sk-leftover"}); code != 200 || !resp.Kept {
		t.Fatalf("keep again: %d", code)
	}
	other, _ := enroll(t, st, ts, "web-2", true)
	if code, resp, _ := moveKeys(t, ts, other.APIKey, hubproto.MoveKeysRequest{Key: "sk-nowhere"}); code != 200 || !resp.Kept {
		t.Fatalf("keep without an endpoint: %d", code)
	}
	if k := st.KeptKeys(); len(k) != 2 || k[1].SeenWith != "http://models.test" || k[0].SeenWith != "" {
		t.Fatalf("kept %+v", k)
	}
	if a := st.AuditLog(5); a[0].Action != "server.keys_kept" || strings.Contains(a[0].Detail, "sk-") {
		t.Fatalf("audit %+v", a[0])
	}
	// Deleting the server keeps its key: the hub has the only copy.
	if err := st.DeleteServer(other.ServerID); err != nil {
		t.Fatal(err)
	}
	if k := st.KeptKeys(); len(k) != 2 || k[0].Server != "web-2" {
		t.Fatalf("kept after deleting the server %+v", k)
	}

	c, csrf := signIn(t, st, ts)
	code, b := do(t, c, "GET", ts.URL+"/api/settings/kept-keys", "", "", nil)
	if code != 200 || strings.Contains(string(b), "sk-leftover") || strings.Contains(string(b), "sk-nowhere") {
		t.Fatalf("list shows a key: %d %s", code, b)
	}
	var list struct {
		Kept []KeptKey `json:"kept_keys"`
	}
	_ = json.Unmarshal(b, &list)
	var withURL, without int64
	for _, k := range list.Kept {
		if k.SeenWith != "" {
			withURL = k.ID
		} else {
			without = k.ID
		}
	}
	mk := func(id int64, url string) (int, string) {
		code, b := do(t, c, "POST", ts.URL+"/api/settings/kept-keys/"+fmt.Sprint(id)+"/connection", "", csrf, map[string]any{"kind": "openai-compatible", "name": "Leftover", "base_url": url})
		return code, string(b)
	}
	if code, b := mk(without, "http://models.test"); code != 409 {
		t.Fatalf("a key with no endpoint made a connection: %d %s", code, b)
	}
	if code, b := mk(withURL, "https://elsewhere.test"); code != 409 {
		t.Fatalf("a kept key sent to another host: %d %s", code, b)
	}
	n := len(st.Connections())
	if code, b := mk(withURL, "http://models.test"); code != 200 {
		t.Fatalf("make a connection: %d %s", code, b)
	}
	conns := st.Connections()
	if len(conns) != n+1 || conns[n].APIKey != "sk-leftover" || conns[n].Direct {
		t.Fatalf("connections %+v", conns)
	}
	// The connection works with the key, and the kept copy is gone.
	if code, b := do(t, c, "POST", ts.URL+"/api/settings/connections/"+conns[n].ID+"/test", "", csrf, nil); code != 200 || !strings.Contains(string(b), `"ok":true`) {
		t.Fatalf("test: %d %s", code, b)
	}
	up.mu.Lock()
	last := up.auth[len(up.auth)-1]
	up.mu.Unlock()
	if last != "Bearer sk-leftover" {
		t.Fatalf("endpoint saw %q", last)
	}
	if code, _ := do(t, c, "DELETE", ts.URL+"/api/settings/kept-keys/"+fmt.Sprint(without), "", "", nil); code != 403 {
		t.Fatalf("delete without csrf: %d", code)
	}
	if code, _ := do(t, c, "DELETE", ts.URL+"/api/settings/kept-keys/"+fmt.Sprint(without), "", csrf, nil); code != 200 || len(st.KeptKeys()) != 0 {
		t.Fatalf("delete: %d %+v", code, st.KeptKeys())
	}
}

// The hub keeps at most a few keys per server.
func TestMoveKeysKeepLimit(t *testing.T) {
	_, st, ts, _, er := moveHub(t)
	for i := 0; i < keptPerServer; i++ {
		if code, _, b := moveKeys(t, ts, er.APIKey, hubproto.MoveKeysRequest{Key: fmt.Sprint("sk-", i)}); code != 200 {
			t.Fatalf("%d: %d %s", i, code, b)
		}
	}
	if code, _, _ := moveKeys(t, ts, er.APIKey, hubproto.MoveKeysRequest{Key: "sk-more"}); code != 422 || len(st.KeptKeys()) != keptPerServer {
		t.Fatalf("over the limit: %d, %d kept", code, len(st.KeptKeys()))
	}
}
