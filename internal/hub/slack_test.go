package hub

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
)

type slackMock struct {
	mu    sync.Mutex
	posts []string
	fail  bool
}

func (m *slackMock) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		w.WriteHeader(500)
		return
	}
	m.posts = append(m.posts, string(b))
}

func (m *slackMock) count() int { m.mu.Lock(); defer m.mu.Unlock(); return len(m.posts) }

func note(id, sev, title string) hubproto.Record {
	b, _ := json.Marshal(map[string]any{"id": id, "kind": "agent", "severity": sev, "title": title, "body": "details", "incident_id": 4,
		"fields": map[string]string{"Incident": "#4"}})
	return hubproto.Record{Kind: "notification", ID: id, UpdatedAt: time.Now(), Data: b}
}

// The Slack mocks listen on loopback, which the hub's poster refuses unless
// allowed.
func allowLoopback(o *Options) { o.EndpointAllow = loopbackProxies }

func TestSlackLivesInTheHub(t *testing.T) {
	srv, st, ts := newHubWith(t, allowLoopback)
	mock := &slackMock{}
	slack := httptest.NewServer(mock)
	defer slack.Close()

	// Enrollment no longer hands a webhook to servers.
	_ = st.SetSetting(settingSlackWebhook, slack.URL)
	host, tok, _ := st.CreateServer("web-1", "test", time.Hour)
	_, body := do(t, ts.Client(), "POST", ts.URL+hubproto.PathEnroll, "", "", hubproto.EnrollRequest{Token: tok})
	var er hubproto.EnrollResponse
	_ = json.Unmarshal(body, &er)
	if strings.Contains(string(body), "slack") || strings.Contains(string(body), slack.URL) {
		t.Fatal("the hub must not hand its Slack webhook to servers")
	}

	// A server reports notifications with its sync; a re-sent batch is stored once.
	sync := hubproto.SyncRequest{Status: hubproto.Status{Name: "spoofed-name"}, Records: []hubproto.Record{note("1", "high", "Containment done: block_ip"), note("2", "low", "noise")}}
	for i := 0; i < 2; i++ {
		if code, b := do(t, ts.Client(), "POST", ts.URL+hubproto.PathSync, er.APIKey, "", sync); code != 200 {
			t.Fatalf("sync: %d %s", code, b)
		}
	}
	_ = st.SetSetting(settingSlackMinSev, "medium")
	srv.forwardDue(context.Background())
	if mock.count() != 1 {
		t.Fatalf("want exactly one post (dedupe + min severity), got %d", mock.count())
	}
	if p := mock.posts[0]; !strings.Contains(p, "[web-1]") || strings.Contains(p, "spoofed-name") {
		t.Fatalf("server name must come from the hub: %s", p)
	}
	list := st.Notifications(host.ID, 10)
	if len(list) != 2 || list[0].Status != "skipped" || list[1].Status != "delivered" || list[1].IncidentID != 4 {
		t.Fatalf("statuses %+v", list)
	}

	// Slack down: the notification stays pending with the error, then delivers.
	mock.fail = true
	sync.Records = []hubproto.Record{note("3", "critical", "Root key added")}
	do(t, ts.Client(), "POST", ts.URL+hubproto.PathSync, er.APIKey, "", sync)
	srv.forwardDue(context.Background())
	if n := st.Notifications(host.ID, 1)[0]; n.Status != "pending" || n.Attempts != 1 || n.Error == "" {
		t.Fatalf("want pending retry, got %+v", n)
	}
	mock.fail = false
	_, _ = st.db.Exec(`UPDATE notifications SET next_try=0`)
	srv.forwardDue(context.Background())
	if n := st.Notifications(host.ID, 1)[0]; n.Status != "delivered" {
		t.Fatalf("retry did not deliver: %+v", n)
	}
}

func TestSlackSettingsAPI(t *testing.T) {
	_, st, ts := newHubWith(t, allowLoopback)
	mock := &slackMock{}
	slack := httptest.NewServer(mock)
	defer slack.Close()
	_ = st.AddUser("alice", "correct horse battery")
	jar, _ := cookiejar.New(nil)
	c := ts.Client()
	c.Jar = jar
	_, body := do(t, c, "POST", ts.URL+"/api/login", "", "", map[string]string{"name": "alice", "password": "correct horse battery"})
	var lr struct {
		CSRF string `json:"csrf"`
	}
	_ = json.Unmarshal(body, &lr)

	if code, _ := do(t, c, "PUT", ts.URL+"/api/settings/slack", "", lr.CSRF, map[string]string{"webhook_url": "http://evil.example/hook"}); code != 400 {
		t.Fatalf("plain-http webhook accepted: %d", code)
	}
	if code, _ := do(t, c, "PUT", ts.URL+"/api/settings/slack", "", "", map[string]string{"webhook_url": slack.URL}); code != 403 {
		t.Fatalf("settings change without CSRF: %d", code)
	}
	code, body := do(t, c, "PUT", ts.URL+"/api/settings/slack", "", lr.CSRF, map[string]any{"webhook_url": slack.URL, "min_severity": "high"})
	if code != 200 || strings.Contains(string(body), slack.URL) || !strings.Contains(string(body), `"configured":true`) {
		t.Fatalf("put: %d %s", code, body)
	}
	_, body = do(t, c, "GET", ts.URL+"/api/settings/slack", "", "", nil)
	if strings.Contains(string(body), slack.URL) || !strings.Contains(string(body), `"min_severity":"high"`) {
		t.Fatalf("settings must never reveal the webhook: %s", body)
	}
	_, body = do(t, c, "POST", ts.URL+"/api/settings/slack/test", "", lr.CSRF, map[string]any{})
	if !strings.Contains(string(body), `"ok":true`) || mock.count() != 1 {
		t.Fatalf("test message: %s (posts %d)", body, mock.count())
	}
	if code, _ := do(t, c, "GET", ts.URL+"/api/notifications", "", "", nil); code != 200 {
		t.Fatalf("notifications list: %d", code)
	}
}
