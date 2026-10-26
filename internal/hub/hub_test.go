package hub

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
)

func newHub(t *testing.T) (*Server, *Store, *httptest.Server) {
	t.Helper()
	return newHubWith(t, func(*Options) {})
}

// newHubWith is newHub with options changed by set.
func newHubWith(t *testing.T, set func(*Options)) (*Server, *Store, *httptest.Server) {
	t.Helper()
	dir := t.TempDir()
	st, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	dist := filepath.Join(dir, "dist")
	_ = os.MkdirAll(dist, 0o755)
	_ = os.WriteFile(filepath.Join(dist, "install.sh"), []byte("#!/bin/sh\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dist, "kodeblue-linux-amd64.tar.gz"), []byte("tarball"), 0o644)
	opt := Options{DataDir: dir, DistDir: dist}
	set(&opt)
	s := NewServer(opt, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return s, st, ts
}

func do(t *testing.T, c *http.Client, method, url, auth, csrf string, body any) (int, []byte) {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, url, r)
	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	if csrf != "" {
		req.Header.Set("X-Kodeblue-CSRF", csrf)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func TestEnrollSyncAndMessages(t *testing.T) {
	_, st, ts := newHub(t)
	c := ts.Client()
	srv, tok, err := st.CreateServer("web-1", "test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// Release files need the token; anonymous download is refused.
	if code, _ := do(t, c, "GET", ts.URL+"/dist/kodeblue-linux-amd64.tar.gz", "", "", nil); code != 401 {
		t.Fatalf("anonymous dist download: %d", code)
	}
	if code, _ := do(t, c, "GET", ts.URL+"/dist/kodeblue-linux-amd64.tar.gz", tok, "", nil); code != 200 {
		t.Fatalf("token dist download: %d", code)
	}
	if code, _ := do(t, c, "GET", ts.URL+"/dist/..%2fhub.db", tok, "", nil); code == 200 {
		t.Fatal("path traversal served a file")
	}

	code, body := do(t, c, "POST", ts.URL+hubproto.PathEnroll, "", "", hubproto.EnrollRequest{Token: tok, Hostname: "h1"})
	if code != 200 {
		t.Fatalf("enroll: %d %s", code, body)
	}
	var er hubproto.EnrollResponse
	_ = json.Unmarshal(body, &er)
	if er.ServerID != srv.ID || !strings.HasPrefix(er.APIKey, "kbk_") {
		t.Fatalf("bad enroll response %+v", er)
	}
	// One-time: the same token cannot enroll twice.
	if code, _ := do(t, c, "POST", ts.URL+hubproto.PathEnroll, "", "", hubproto.EnrollRequest{Token: tok}); code != 401 {
		t.Fatalf("token reuse: %d", code)
	}
	// The hub never stores the key itself.
	var stored string
	_ = st.db.QueryRow(`SELECT key_hash FROM servers WHERE id=?`, srv.ID).Scan(&stored)
	if stored == er.APIKey || stored != Hash(er.APIKey) {
		t.Fatal("key must be stored hashed")
	}

	// Sync needs the key.
	sync := hubproto.SyncRequest{Status: hubproto.Status{Name: "web-1", Phase: "watching"}, Records: []hubproto.Record{
		{Kind: "incident", ID: "1", UpdatedAt: time.Now(), Data: json.RawMessage(`{"id":1,"kind":"incident","status":"needs_human","severity":"critical","title":"x","created_at":"` + time.Now().Format(time.RFC3339Nano) + `"}`)},
		{Kind: "monitor", ID: "a", UpdatedAt: time.Now(), Data: json.RawMessage(`{"id":"a","last_ok":true,"disabled":false}`)},
		{Kind: "monitor", ID: "b", UpdatedAt: time.Now(), Data: json.RawMessage(`{"id":"b","last_ok":false,"disabled":false}`)},
		{Kind: "evil", ID: "x", UpdatedAt: time.Now(), Data: json.RawMessage(`{}`)},
	}, Replace: []string{"monitor"}}
	if code, _ := do(t, c, "POST", ts.URL+hubproto.PathSync, "kbk_wrong", "", sync); code != 401 {
		t.Fatalf("bad key sync: %d", code)
	}
	if code, b := do(t, c, "POST", ts.URL+hubproto.PathSync, er.APIKey, "", sync); code != 200 {
		t.Fatalf("sync: %d %s", code, b)
	}
	cnt := st.Counts(srv.ID)
	if cnt.NeedsHuman != 1 || cnt.Monitors != 2 || cnt.FailingMonitor != 1 || cnt.Incidents24h != 1 {
		t.Fatalf("counts %+v", cnt)
	}
	if st.Record(srv.ID, "evil", "x") != nil {
		t.Fatal("unknown kinds must be dropped")
	}
	// Replace semantics: monitor b removed on the server disappears here.
	sync.Records = sync.Records[1:2]
	_, _ = do(t, c, "POST", ts.URL+hubproto.PathSync, er.APIKey, "", sync)
	if st.Record(srv.ID, "monitor", "b") != nil || st.Record(srv.ID, "monitor", "a") == nil {
		t.Fatal("replace did not prune monitor b")
	}

	// Operator message -> long-poll -> reply.
	m := &Message{ServerID: srv.ID, Author: "alice", Body: "why did you block 203.0.113.9?"}
	if err := st.AddMessage(m); err != nil {
		t.Fatal(err)
	}
	code, body = do(t, c, "GET", ts.URL+hubproto.PathMessages+"?wait=1", er.APIKey, "", nil)
	var mr hubproto.MessagesResponse
	_ = json.Unmarshal(body, &mr)
	if code != 200 || len(mr.Messages) != 1 || mr.Messages[0].Body != m.Body {
		t.Fatalf("poll: %d %s", code, body)
	}
	if code, _ := do(t, c, "POST", ts.URL+hubproto.PathMessages+"/999/reply", er.APIKey, "", hubproto.MessageReply{Status: "done", Text: "x"}); code != 409 {
		t.Fatalf("reply to unknown message: %d", code)
	}
	if code, b := do(t, c, "POST", ts.URL+hubproto.PathMessages+"/"+itoa(m.ID)+"/reply", er.APIKey, "", hubproto.MessageReply{Status: "done", Text: "because"}); code != 200 {
		t.Fatalf("reply: %d %s", code, b)
	}
	if got := st.Messages(srv.ID, 5)[0]; got.Status != "done" || got.Reply != "because" {
		t.Fatalf("message after reply %+v", got)
	}

	// Another server's key cannot answer this server's messages.
	_, tok2, _ := st.CreateServer("db-1", "test", time.Hour)
	_, body = do(t, c, "POST", ts.URL+hubproto.PathEnroll, "", "", hubproto.EnrollRequest{Token: tok2})
	var er2 hubproto.EnrollResponse
	_ = json.Unmarshal(body, &er2)
	m2 := &Message{ServerID: srv.ID, Author: "alice", Body: "second"}
	_ = st.AddMessage(m2)
	if code, _ := do(t, c, "POST", ts.URL+hubproto.PathMessages+"/"+itoa(m2.ID)+"/reply", er2.APIKey, "", hubproto.MessageReply{Status: "done", Text: "spoof"}); code != 409 {
		t.Fatalf("cross-server reply: %d", code)
	}

	// Revocation cuts the key off.
	_ = st.Revoke(srv.ID)
	if code, _ := do(t, c, "POST", ts.URL+hubproto.PathSync, er.APIKey, "", sync); code != 401 {
		t.Fatalf("revoked key sync: %d", code)
	}
}

func TestOperatorAuthAndCSRF(t *testing.T) {
	_, st, ts := newHub(t)
	if err := st.AddUser("alice", "short"); err == nil {
		t.Fatal("short password accepted")
	}
	if err := st.AddUser("alice", "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	jar, _ := cookiejar.New(nil)
	c := ts.Client()
	c.Jar = jar

	if code, _ := do(t, c, "GET", ts.URL+"/api/fleet", "", "", nil); code != 401 {
		t.Fatalf("fleet without session: %d", code)
	}
	code, body := do(t, c, "POST", ts.URL+"/api/login", "", "", map[string]string{"name": "alice", "password": "correct horse battery"})
	if code != 200 {
		t.Fatalf("login: %d %s", code, body)
	}
	var lr struct {
		CSRF string `json:"csrf"`
	}
	_ = json.Unmarshal(body, &lr)
	if code, _ := do(t, c, "GET", ts.URL+"/api/fleet", "", "", nil); code != 200 {
		t.Fatalf("fleet with session: %d", code)
	}
	// State changes without the CSRF header are refused even with the cookie.
	if code, _ := do(t, c, "POST", ts.URL+"/api/servers", "", "", map[string]string{"name": "x"}); code != 403 {
		t.Fatalf("create without csrf: %d", code)
	}
	code, body = do(t, c, "POST", ts.URL+"/api/servers", "", lr.CSRF, map[string]string{"name": "web-2"})
	if code != 200 || !strings.Contains(string(body), "install.sh") || !strings.Contains(string(body), "--token kbe_") {
		t.Fatalf("create: %d %s", code, body)
	}

	// Brute force is throttled.
	c2 := ts.Client()
	for i := 0; i < 8; i++ {
		do(t, c2, "POST", ts.URL+"/api/login", "", "", map[string]string{"name": "alice", "password": "wrong password!!"})
	}
	if code, _ := do(t, c2, "POST", ts.URL+"/api/login", "", "", map[string]string{"name": "alice", "password": "correct horse battery"}); code != 429 {
		t.Fatalf("login after 8 failures: %d", code)
	}
}

func TestTasksBoard(t *testing.T) {
	_, st, ts := newHub(t)
	_ = st.AddUser("alice", "correct horse battery")
	jar, _ := cookiejar.New(nil)
	c := ts.Client()
	c.Jar = jar
	if code, _ := do(t, c, "GET", ts.URL+"/api/tasks", "", "", nil); code != 401 {
		t.Fatalf("tasks without session: %d", code)
	}
	if code, b := do(t, c, "POST", ts.URL+"/api/login", "", "", map[string]string{"name": "alice", "password": "correct horse battery"}); code != 200 {
		t.Fatalf("login: %d %s", code, b)
	}
	now := time.Now()
	var ids []string
	for i, name := range []string{"web-1", "db-1"} {
		_, tok, _ := st.CreateServer(name, "test", time.Hour)
		srv, _, err := st.Enroll(tok, name, "")
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, srv.ID)
		long := strings.Repeat("é", 400)
		rec := `{"id":` + itoa(int64(i+1)) + `,"kind":"incident","status":"investigating","severity":"high","title":"t` + name + `","session_id":"sess_x","summary":"` + long + `","report":"secret long report","self_eval":"x"}`
		if err := st.ApplySync(srv.ID, &hubproto.SyncRequest{Records: []hubproto.Record{{Kind: "incident", ID: itoa(int64(i + 1)), UpdatedAt: now.Add(time.Duration(i) * time.Second), Data: json.RawMessage(rec)}}}); err != nil {
			t.Fatal(err)
		}
	}
	_ = st.AddMessage(&Message{ServerID: ids[0], Author: "alice", Body: "new task please"})

	var res struct {
		Tasks []struct {
			ServerID   string         `json:"server_id"`
			ServerName string         `json:"server_name"`
			Data       map[string]any `json:"data"`
		} `json:"tasks"`
		Messages []Message `json:"messages"`
	}
	code, body := do(t, c, "GET", ts.URL+"/api/tasks", "", "", nil)
	if code != 200 {
		t.Fatalf("tasks: %d %s", code, body)
	}
	_ = json.Unmarshal(body, &res)
	if len(res.Tasks) != 2 || res.Tasks[0].ServerName != "db-1" || res.Tasks[1].ServerID != ids[0] || len(res.Messages) != 1 {
		t.Fatalf("fleet tasks: %s", body)
	}
	d := res.Tasks[0].Data
	if d["report"] != nil || d["self_eval"] != nil || d["title"] != "tdb-1" || d["session_id"] != "sess_x" {
		t.Fatalf("task fields: %v", d)
	}
	if sum, _ := d["summary"].(string); len([]rune(sum)) != 241 || !strings.HasSuffix(sum, "…") {
		t.Fatalf("summary not trimmed on a rune boundary: %d runes", len([]rune(sum)))
	}

	res.Tasks, res.Messages = nil, nil
	_, body = do(t, c, "GET", ts.URL+"/api/tasks?server="+ids[1], "", "", nil)
	_ = json.Unmarshal(body, &res)
	if len(res.Tasks) != 1 || res.Tasks[0].ServerID != ids[1] || len(res.Messages) != 0 {
		t.Fatalf("one server's tasks: %s", body)
	}
	if code, _ := do(t, c, "GET", ts.URL+"/api/tasks?server=srv_nope", "", "", nil); code != 404 {
		t.Fatalf("unknown server: %d", code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	_, _, ts := newHub(t)
	resp, err := ts.Client().Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe-inline") || resp.Header.Get("X-Frame-Options") != "DENY" {
		t.Fatalf("headers: %v", resp.Header)
	}
}

// The console is served from the hub itself (no third-party origin) and its
// script never parses server data as HTML.
func TestConsoleAssets(t *testing.T) {
	_, _, ts := newHub(t)
	for path, ctype := range map[string]string{"/assets/app.js": "javascript", "/assets/app.css": "text/css",
		"/assets/JetBrainsMono-Regular.woff2": "font/woff2", "/assets/icon.svg": "image/svg+xml"} {
		resp, err := ts.Client().Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Content-Type"), ctype) || resp.Header.Get("Cache-Control") != "no-cache" {
			t.Fatalf("%s: %d %q %q", path, resp.StatusCode, resp.Header.Get("Content-Type"), resp.Header.Get("Cache-Control"))
		}
	}
	js, _ := webFS.ReadFile("web/app.js")
	for _, bad := range []string{".innerHTML", ".outerHTML", "insertAdjacentHTML(", "document.write(", "eval(", "new Function("} {
		if strings.Contains(string(js), bad) {
			t.Fatalf("app.js uses %s", bad)
		}
	}
	page, _ := webFS.ReadFile("web/index.html")
	if strings.Contains(string(page), "<style") || strings.Contains(string(page), "<script>") || strings.Contains(string(page), "style=") || strings.Contains(string(page), "https://") {
		t.Fatal("index.html must not carry inline styles, inline script or third-party URLs")
	}
}

func TestPasswordHash(t *testing.T) {
	h, err := HashPassword("a long enough password")
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPassword(h, "a long enough password") || CheckPassword(h, "a long enough passwore") {
		t.Fatal("password check")
	}
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }

func TestEnrollHandsOverFleetInference(t *testing.T) {
	_, st, ts := newHub(t)
	enroll := func() hubproto.EnrollResponse {
		_, tok, err := st.CreateServer("web", "test", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		code, body := do(t, ts.Client(), "POST", ts.URL+hubproto.PathEnroll, "", "", hubproto.EnrollRequest{Token: tok})
		if code != 200 {
			t.Fatalf("enroll: %d %s", code, body)
		}
		var er hubproto.EnrollResponse
		_ = json.Unmarshal(body, &er)
		return er
	}
	if er := enroll(); er.Inference != nil || er.InferenceKey != "" {
		t.Fatalf("no fleet defaults set, got %+v", er)
	}
	// An endpoint without a model is incomplete and not handed out.
	_ = st.SetSetting(SettingInferenceURL, "https://api.example.com")
	if er := enroll(); er.Inference != nil {
		t.Fatalf("endpoint without a model handed out: %+v", er.Inference)
	}
	_ = st.SetSetting(SettingInferenceModel, "small-model")
	_ = st.SetSetting(SettingInferenceKey, "sk-test")
	er := enroll()
	if er.Inference == nil || er.Inference.BaseURL != "https://api.example.com" || er.Inference.Model != "small-model" || er.InferenceKey != "sk-test" {
		t.Fatalf("fleet defaults not handed over: %+v", er)
	}
}

func TestApprovalsAndCaseState(t *testing.T) {
	_, st, ts := newHub(t)
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
	srv, _, _ := st.Enroll(tok, "web-1", "")
	sync := func(accepts bool) {
		now := time.Now()
		if err := st.ApplySync(srv.ID, &hubproto.SyncRequest{Status: hubproto.Status{AcceptsApprovals: accepts},
			Records: []hubproto.Record{
				{Kind: "incident", ID: "7", UpdatedAt: now, Data: json.RawMessage(`{"id":7,"kind":"incident","status":"needs_human","title":"x"}`)},
				{Kind: "pending_action", ID: "act_1", UpdatedAt: now, Data: json.RawMessage(`{"id":"act_1","incident_id":7,"action":"block_ip","params":{"ip":"203.0.113.9"}}`)},
			}}); err != nil {
			t.Fatal(err)
		}
	}
	decide := func(rid, d string) (int, []byte) {
		return do(t, c, "POST", ts.URL+"/api/servers/"+srv.ID+"/actions/"+rid+"/decision", "", me.CSRF, map[string]string{"decision": d})
	}

	sync(false)
	if code, b := decide("act_1", "approve"); code != 409 || !strings.Contains(string(b), "respond approve act_1") {
		t.Fatalf("server without hub approvals: %d %s", code, b)
	}
	sync(true)
	if code, _ := decide("act_1", "maybe"); code != 400 {
		t.Fatalf("bad decision: %d", code)
	}
	if code, _ := decide("act_nope", "approve"); code != 404 {
		t.Fatalf("unknown request: %d", code)
	}
	if code, _ := do(t, c, "POST", ts.URL+"/api/servers/"+srv.ID+"/actions/act_1/decision", "", "", map[string]string{"decision": "approve"}); code != 403 {
		t.Fatalf("decision without csrf: %d", code)
	}
	if code, b := decide("act_1", "approve"); code != 200 {
		t.Fatalf("approve: %d %s", code, b)
	}
	if code, _ := decide("act_1", "deny"); code != 409 {
		t.Fatalf("second decision while one is open: %d", code)
	}
	msgs := st.TakeQueued(srv.ID)
	if len(msgs) != 1 || msgs[0].Decision != "approve" || msgs[0].RequestID != "act_1" || msgs[0].IncidentID != 7 || !strings.Contains(msgs[0].Body, "block_ip ip=203.0.113.9") {
		t.Fatalf("queued decision: %+v", msgs)
	}

	// Board state: move, archive, reject bad input.
	post := func(body map[string]any) (int, []byte) {
		return do(t, c, "POST", ts.URL+"/api/cases/state", "", me.CSRF, body)
	}
	if code, _ := post(map[string]any{"server_id": srv.ID, "incident_id": 7, "column": "live"}); code != 400 {
		t.Fatalf("bad column: %d", code)
	}
	if code, _ := post(map[string]any{"server_id": srv.ID, "incident_id": 99, "archived": true}); code != 404 {
		t.Fatalf("unknown case: %d", code)
	}
	if code, b := post(map[string]any{"server_id": srv.ID, "incident_id": 7, "column": "done"}); code != 200 {
		t.Fatalf("move: %d %s", code, b)
	}
	if code, b := post(map[string]any{"server_id": srv.ID, "incident_id": 7, "archived": true}); code != 200 {
		t.Fatalf("archive: %d %s", code, b)
	}
	var res struct {
		Tasks []struct {
			Board *CaseState `json:"board"`
		} `json:"tasks"`
		Approvals []Approval `json:"approvals"`
	}
	_, body := do(t, c, "GET", ts.URL+"/api/tasks", "", "", nil)
	_ = json.Unmarshal(body, &res)
	if len(res.Tasks) != 1 || res.Tasks[0].Board == nil || res.Tasks[0].Board.Column != "done" || !res.Tasks[0].Board.Archived || res.Tasks[0].Board.UpdatedBy != "alice" {
		t.Fatalf("board state: %s", body)
	}
	if len(res.Approvals) != 1 || res.Approvals[0].ServerID != srv.ID {
		t.Fatalf("approvals: %s", body)
	}
}

func TestLearningCommands(t *testing.T) {
	_, st, ts := newHub(t)
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
	srv, _, _ := st.Enroll(tok, "web-1", "")
	sync := func(s hubproto.Status) {
		if err := st.ApplySync(srv.ID, &hubproto.SyncRequest{Status: s}); err != nil {
			t.Fatal(err)
		}
	}
	learn := func(mode string) (int, []byte) {
		return do(t, c, "POST", ts.URL+"/api/servers/"+srv.ID+"/learn", "", me.CSRF, map[string]string{"mode": mode})
	}

	sync(hubproto.Status{Phase: "watching"})
	if code, b := learn("relearn"); code != 409 || !strings.Contains(string(b), "kodeblue relearn") {
		t.Fatalf("server without hub learning: %d %s", code, b)
	}
	sync(hubproto.Status{Phase: "watching", AcceptsLearning: true})
	if code, _ := learn("forget"); code != 400 {
		t.Fatalf("bad mode: %d", code)
	}
	if code, b := learn("learn"); code != 409 || !strings.Contains(string(b), "models") {
		t.Fatalf("learner without models: %d %s", code, b)
	}
	if code, _ := do(t, c, "POST", ts.URL+"/api/servers/"+srv.ID+"/learn", "", "", map[string]string{"mode": "relearn"}); code != 403 {
		t.Fatalf("learn without csrf: %d", code)
	}
	if code, b := learn("relearn"); code != 200 {
		t.Fatalf("relearn: %d %s", code, b)
	}
	if code, _ := learn("relearn"); code != 409 {
		t.Fatalf("second command while one is open: %d", code)
	}
	msgs := st.TakeQueued(srv.ID)
	if len(msgs) != 1 || msgs[0].Command != hubproto.CommandRelearn || msgs[0].Author != "alice" {
		t.Fatalf("queued command: %+v", msgs)
	}
	_ = st.Reply(srv.ID, msgs[0].ID, hubproto.MessageReply{Status: "done", Text: "Relearning"})
	sync(hubproto.Status{Phase: "learning", AcceptsLearning: true, ModelsEnabled: true, Learning: true})
	if code, b := learn("learn"); code != 409 || !strings.Contains(string(b), "already") {
		t.Fatalf("learn while learning: %d %s", code, b)
	}
	sync(hubproto.Status{Phase: "watching", AcceptsLearning: true, ModelsEnabled: true})
	if code, b := learn("learn"); code != 200 {
		t.Fatalf("learn: %d %s", code, b)
	}
}

func TestServicesAndVulnerabilities(t *testing.T) {
	_, st, ts := newHub(t)
	_ = st.AddUser("alice", "correct horse battery")
	jar, _ := cookiejar.New(nil)
	c := ts.Client()
	c.Jar = jar
	_, b := do(t, c, "POST", ts.URL+"/api/login", "", "", map[string]string{"name": "alice", "password": "correct horse battery"})
	var me struct {
		CSRF string `json:"csrf"`
	}
	_ = json.Unmarshal(b, &me)
	_, tok, _ := st.CreateServer("web-1", "test", time.Hour)
	srv, _, _ := st.Enroll(tok, "web-1", "")
	rec := func(kind, id, data string) hubproto.Record {
		return hubproto.Record{Kind: kind, ID: id, UpdatedAt: time.Now(), Data: json.RawMessage(data)}
	}
	if err := st.ApplySync(srv.ID, &hubproto.SyncRequest{Replace: []string{"service", "vulnerability"}, Records: []hubproto.Record{
		rec("service", "nginx", `{"name":"nginx","role":"workload","checks":[]}`),
		rec("vulnerability", "nginx-old", `{"id":"nginx-old","service":"nginx","severity":"high","status":"open"}`),
		rec("vulnerability", "nginx-listing", `{"id":"nginx-listing","service":"nginx","severity":"medium","status":"open"}`),
		rec("vulnerability", "ssh-root", `{"id":"ssh-root","service":"host","severity":"high","status":"accepted"}`),
	}}); err != nil {
		t.Fatal(err)
	}
	cnt := st.Counts(srv.ID)
	if cnt.Services != 1 || cnt.OpenVulns["high"] != 1 || cnt.OpenVulns["medium"] != 1 {
		t.Fatalf("counts: %+v", cnt)
	}
	if code, b := do(t, c, "GET", ts.URL+"/api/servers/"+srv.ID+"/records/vulnerability", "", "", nil); code != 200 || !strings.Contains(string(b), "nginx-old") {
		t.Fatalf("records: %d %s", code, b)
	}

	vuln := func(id string, body any) (int, []byte) {
		return do(t, c, "POST", ts.URL+"/api/servers/"+srv.ID+"/vulnerabilities/"+id, "", me.CSRF, body)
	}
	if code, _ := vuln("nginx-old", map[string]string{"command": "vuln_delete"}); code != 400 {
		t.Fatalf("unknown command: %d", code)
	}
	if code, _ := vuln("nginx-old", map[string]string{"command": "vuln_accept"}); code != 400 {
		t.Fatalf("accepting a risk needs a reason: %d", code)
	}
	if code, _ := vuln("nope", map[string]string{"command": "vuln_recheck"}); code != 404 {
		t.Fatalf("unknown vulnerability: %d", code)
	}
	if code, b := vuln("nginx-old", map[string]string{"command": "vuln_accept", "note": "behind the WAF"}); code != 200 {
		t.Fatalf("accept: %d %s", code, b)
	}
	// A pending vulnerability command does not block learning commands.
	if st.OpenCommand(srv.ID) != nil {
		t.Fatal("a vulnerability command is not a learning command")
	}
	msgs := st.TakeQueued(srv.ID)
	if len(msgs) != 1 || msgs[0].Command != hubproto.CommandVulnAccept || msgs[0].RequestID != "nginx-old" || msgs[0].Body != "behind the WAF" {
		t.Fatalf("queued: %+v", msgs)
	}
	if st.OpenDecision(srv.ID, "nginx-old") != nil {
		t.Fatal("a vulnerability command is not a containment decision")
	}

	// A full set without a vulnerability drops it.
	_ = st.ApplySync(srv.ID, &hubproto.SyncRequest{Replace: []string{"vulnerability"}, Records: []hubproto.Record{
		rec("vulnerability", "nginx-old", `{"id":"nginx-old","service":"nginx","severity":"high","status":"accepted"}`)}})
	if cnt := st.Counts(srv.ID); len(cnt.OpenVulns) != 0 {
		t.Fatalf("after replace: %+v", cnt.OpenVulns)
	}
}

// A containment rule ruling is relayed with the content the operator saw; an
// approval of a rule that changed since is refused on the hub already.
func TestContainmentRuleCommands(t *testing.T) {
	_, st, ts := newHub(t)
	_ = st.AddUser("alice", "correct horse battery")
	jar, _ := cookiejar.New(nil)
	c := ts.Client()
	c.Jar = jar
	_, b := do(t, c, "POST", ts.URL+"/api/login", "", "", map[string]string{"name": "alice", "password": "correct horse battery"})
	var me struct {
		CSRF string `json:"csrf"`
	}
	_ = json.Unmarshal(b, &me)
	_, tok, _ := st.CreateServer("web-1", "test", time.Hour)
	srv, _, _ := st.Enroll(tok, "web-1", "")
	if err := st.ApplySync(srv.ID, &hubproto.SyncRequest{Replace: []string{"containment_rule"}, Records: []hubproto.Record{
		{Kind: "containment_rule", ID: "cr-ssh", UpdatedAt: time.Now(), Data: json.RawMessage(`{"id":"cr-ssh","status":"proposed","hash":"abc123"}`)},
		{Kind: "containment_rule", ID: "cr-web", UpdatedAt: time.Now(), Data: json.RawMessage(`{"id":"cr-web","status":"active","hash":"def456"}`)},
	}}); err != nil {
		t.Fatal(err)
	}
	if n := st.Counts(srv.ID).RulesWaiting; n != 1 {
		t.Fatalf("rules waiting: %d", n)
	}
	rule := func(id string, body any) (int, []byte) {
		return do(t, c, "POST", ts.URL+"/api/servers/"+srv.ID+"/rules/"+id, "", me.CSRF, body)
	}
	if code, _ := rule("cr-ssh", map[string]string{"command": "rule_edit"}); code != 400 {
		t.Fatalf("unknown command: %d", code)
	}
	if code, _ := rule("cr-nope", map[string]string{"command": "rule_pause", "note": "x"}); code != 404 {
		t.Fatalf("unknown rule: %d", code)
	}
	if code, _ := rule("cr-ssh", map[string]string{"command": "rule_approve", "hash": "old"}); code != 409 {
		t.Fatalf("approval of changed content: %d", code)
	}
	if code, _ := rule("cr-web", map[string]string{"command": "rule_pause"}); code != 400 {
		t.Fatalf("pause needs a reason: %d", code)
	}
	if code, b := rule("cr-ssh", map[string]string{"command": "rule_approve", "hash": "abc123"}); code != 200 {
		t.Fatalf("approve: %d %s", code, b)
	}
	msgs := st.TakeQueued(srv.ID)
	if len(msgs) != 1 || msgs[0].Command != hubproto.CommandRuleApprove || msgs[0].RequestID != "cr-ssh" || msgs[0].RuleHash != "abc123" {
		t.Fatalf("queued: %+v", msgs)
	}
}

// Update in the console asks one server to upgrade to the hub's version. The
// hub names nothing else, and refuses what the server would refuse.
func TestUpgradeCommand(t *testing.T) {
	_, st, ts := newHub(t)
	_ = st.AddUser("alice", "correct horse battery")
	jar, _ := cookiejar.New(nil)
	c := ts.Client()
	c.Jar = jar
	_, b := do(t, c, "POST", ts.URL+"/api/login", "", "", map[string]string{"name": "alice", "password": "correct horse battery"})
	var me struct {
		CSRF    string `json:"csrf"`
		Version string `json:"version"`
	}
	_ = json.Unmarshal(b, &me)
	_, b = do(t, c, "GET", ts.URL+"/api/me", "", "", nil)
	_ = json.Unmarshal(b, &me)
	_, tok, _ := st.CreateServer("web-1", "test", time.Hour)
	srv, _, _ := st.Enroll(tok, "web-1", "")
	sync := func(s hubproto.Status) {
		if err := st.ApplySync(srv.ID, &hubproto.SyncRequest{Status: s}); err != nil {
			t.Fatal(err)
		}
	}
	up := func() (int, []byte) {
		return do(t, c, "POST", ts.URL+"/api/servers/"+srv.ID+"/upgrade", "", me.CSRF, map[string]string{"version": "v9.9.9"})
	}
	old := hubproto.Version
	t.Cleanup(func() { hubproto.Version = old })

	hubproto.Version = "dev"
	sync(hubproto.Status{Phase: "watching", Version: "v0.1.6", AcceptsUpgrades: true})
	if code, b := up(); code != 409 || !strings.Contains(string(b), "development build") {
		t.Fatalf("dev hub: %d %s", code, b)
	}
	hubproto.Version = "v0.1.7"
	if _, b := do(t, c, "GET", ts.URL+"/api/me", "", "", nil); !strings.Contains(string(b), `"version":"v0.1.7"`) {
		t.Fatalf("hub version not in /api/me: %s", b)
	}
	sync(hubproto.Status{Phase: "watching", Version: "v0.1.6"})
	if code, b := up(); code != 409 || !strings.Contains(string(b), "install command") {
		t.Fatalf("server without hub upgrades: %d %s", code, b)
	}
	sync(hubproto.Status{Phase: "watching", Version: "v0.1.8", AcceptsUpgrades: true})
	if code, b := up(); code != 409 || !strings.Contains(string(b), "downgrade") {
		t.Fatalf("downgrade: %d %s", code, b)
	}
	sync(hubproto.Status{Phase: "watching", Version: "v0.1.6", AcceptsUpgrades: true})
	if code, _ := do(t, c, "POST", ts.URL+"/api/servers/"+srv.ID+"/upgrade", "", "", nil); code != 403 {
		t.Fatalf("upgrade without csrf: %d", code)
	}
	if code, b := up(); code != 200 {
		t.Fatalf("upgrade: %d %s", code, b)
	}
	if code, _ := up(); code != 409 {
		t.Fatalf("second upgrade while one is open: %d", code)
	}
	if st.OpenCommand(srv.ID) != nil {
		t.Fatal("an upgrade is not a learning command")
	}
	msgs := st.TakeQueued(srv.ID)
	// The hub's own version, whatever the request body said.
	if len(msgs) != 1 || msgs[0].Command != hubproto.CommandUpgrade || msgs[0].Body != "v0.1.7" || msgs[0].Author != "alice" {
		t.Fatalf("queued: %+v", msgs)
	}
	_ = st.Reply(srv.ID, msgs[0].ID, hubproto.MessageReply{Status: "done", Text: "recorded"})
	sync(hubproto.Status{Phase: "watching", Version: "v0.1.6", AcceptsUpgrades: true, Upgrade: &hubproto.UpgradeStatus{To: "v0.1.7", State: "installing"}})
	if code, b := up(); code != 409 || !strings.Contains(string(b), "installing") {
		t.Fatalf("while installing: %d %s", code, b)
	}
	sync(hubproto.Status{Phase: "watching", Version: "v0.1.7", AcceptsUpgrades: true})
	if code, b := up(); code != 409 || !strings.Contains(string(b), "already runs") {
		t.Fatalf("up to date: %d %s", code, b)
	}
}
