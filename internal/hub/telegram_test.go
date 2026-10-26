package hub

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
)

type telegramTransport func(*http.Request) (*http.Response, error)

func (f telegramTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestTelegramSettingsAPI(t *testing.T) {
	srv, st, ts := newHubWith(t, allowLoopback)
	posts := 0
	srv.models.client = &http.Client{Transport: telegramTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "api.telegram.org" || r.URL.Scheme != "https" {
			t.Fatalf("unexpected destination: %s", r.URL)
		}
		posts++
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"ok":true}`)), Header: make(http.Header)}, nil
	})}
	if code, _ := do(t, ts.Client(), "GET", ts.URL+"/api/settings/telegram", "", "", nil); code != 401 {
		t.Fatalf("anonymous settings access: %d", code)
	}
	_ = st.AddUser("alice", "correct horse battery")
	jar, _ := cookiejar.New(nil)
	c := ts.Client()
	c.Jar = jar
	_, body := do(t, c, "POST", ts.URL+"/api/login", "", "", map[string]string{"name": "alice", "password": "correct horse battery"})
	var lr struct {
		CSRF string `json:"csrf"`
	}
	_ = json.Unmarshal(body, &lr)
	settings := map[string]string{"bot_token": "123456:secret", "chat_id": "-1001234", "min_severity": "high"}
	if code, _ := do(t, c, "PUT", ts.URL+"/api/settings/telegram", "", "", settings); code != 403 {
		t.Fatalf("missing CSRF: %d", code)
	}
	for _, bad := range []map[string]string{
		{"bot_token": "123:secret/../getUpdates"}, {"chat_id": "https://evil.example"},
		{"bot_token": "123456:secret", "min_severity": "invalid"},
	} {
		if code, _ := do(t, c, "PUT", ts.URL+"/api/settings/telegram", "", lr.CSRF, bad); code != 400 {
			t.Fatalf("invalid settings accepted: %d", code)
		}
	}
	if st.Setting(settingTelegramToken) != "" {
		t.Fatal("partially saved invalid request")
	}
	code, body := do(t, c, "PUT", ts.URL+"/api/settings/telegram", "", lr.CSRF, settings)
	if code != 200 || strings.Contains(string(body), "secret") || !strings.Contains(string(body), `"configured":true`) {
		t.Fatalf("save: %d %s", code, body)
	}
	_, body = do(t, c, "GET", ts.URL+"/api/settings/telegram", "", "", nil)
	if strings.Contains(string(body), "secret") || !strings.Contains(string(body), `"min_severity":"high"`) {
		t.Fatalf("unsafe settings: %s", body)
	}
	do(t, c, "PUT", ts.URL+"/api/settings/telegram", "", lr.CSRF, map[string]string{"chat_id": "@alerts_channel"})
	if st.Setting(settingTelegramToken) != "123456:secret" {
		t.Fatal("omitted token was overwritten")
	}
	_, body = do(t, c, "POST", ts.URL+"/api/settings/telegram/test", "", lr.CSRF, map[string]any{})
	if !strings.Contains(string(body), `"ok":true`) || posts != 1 {
		t.Fatalf("test: %s posts=%d", body, posts)
	}
	// Enrollment must never expose Telegram credentials.
	_, tok, _ := st.CreateServer("web-1", "test", time.Hour)
	_, body = do(t, c, "POST", ts.URL+hubproto.PathEnroll, "", "", hubproto.EnrollRequest{Token: tok})
	if strings.Contains(string(body), "secret") || strings.Contains(string(body), "telegram") {
		t.Fatalf("credentials leaked to server: %s", body)
	}
	do(t, c, "PUT", ts.URL+"/api/settings/telegram", "", lr.CSRF, map[string]string{"bot_token": "", "chat_id": ""})
	if st.TelegramSettings().Configured || st.Setting(settingTelegramToken) != "" {
		t.Fatal("clear failed")
	}
}

func TestNotificationDestinationsRetryIndependently(t *testing.T) {
	srv, st, _ := newHubWith(t, allowLoopback)
	_ = st.SetSetting(settingSlackWebhook, "https://hooks.slack.com/services/test")
	_ = st.SetSetting(settingTelegramToken, "123456:secret")
	_ = st.SetSetting(settingTelegramChat, "-1001234")
	_ = st.SetSetting(settingTelegramMinSev, "high")
	slackPosts, telegramPosts := 0, 0
	failTelegram := true
	srv.models.client = &http.Client{Transport: telegramTransport(func(r *http.Request) (*http.Response, error) {
		code, body := 200, `{"ok":true}`
		if r.URL.Host == "api.telegram.org" {
			telegramPosts++
			if failTelegram {
				code = 429
				body = `{"ok":false,"description":"123456:secret"}`
			}
		} else {
			slackPosts++
		}
		return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	host, _, _ := st.CreateServer("web-1", "test", time.Hour)
	add := func(r hubproto.Record) {
		tx, err := st.db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if _, err := addNotification(tx, host.ID, r); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	add(note("1", "critical", "Root key added"))
	add(note("1", "critical", "Root key added"))
	srv.forwardDue(context.Background())
	n := st.Notifications(host.ID, 1)[0]
	if n.Status != "pending" || n.Attempts != 1 || strings.Contains(n.Error, "secret") || slackPosts != 1 || telegramPosts != 1 {
		t.Fatalf("first delivery: %+v slack=%d telegram=%d", n, slackPosts, telegramPosts)
	}
	failTelegram = false
	_, _ = st.db.Exec(`UPDATE notification_deliveries SET next_try=0`)
	srv.forwardDue(context.Background())
	if n := st.Notifications(host.ID, 1)[0]; n.Status != "delivered" || n.Error != "" || slackPosts != 1 || telegramPosts != 2 {
		t.Fatalf("retry: %+v slack=%d telegram=%d", n, slackPosts, telegramPosts)
	}
	add(note("2", "low", "noise"))
	srv.forwardDue(context.Background())
	if slackPosts != 2 || telegramPosts != 2 {
		t.Fatalf("per-destination severity failed: slack=%d telegram=%d", slackPosts, telegramPosts)
	}
	// Telegram-only setup must deliver even when Slack is skipped.
	_ = st.SetSetting(settingSlackWebhook, "")
	add(note("3", "high", "Telegram only"))
	srv.forwardDue(context.Background())
	if n := st.Notifications(host.ID, 1)[0]; n.Status != "delivered" || slackPosts != 2 || telegramPosts != 3 {
		t.Fatalf("Telegram only: %+v", n)
	}
	// Reopening/migrating the database must not replay successful destinations.
	if err := st.migrateSlack(); err != nil {
		t.Fatal(err)
	}
	srv.forwardDue(context.Background())
	if slackPosts != 2 || telegramPosts != 3 {
		t.Fatal("migration replayed successful deliveries")
	}
	// Exhaustion is tracked per provider and is visible in notification history.
	failTelegram = true
	add(note("4", "critical", "Persistent failure"))
	for i := 0; i < slackMaxAttempts; i++ {
		_, _ = st.db.Exec(`UPDATE notification_deliveries SET next_try=0`)
		srv.forwardDue(context.Background())
	}
	if n := st.Notifications(host.ID, 1)[0]; n.Status != "failed" || n.Attempts != slackMaxAttempts || !strings.Contains(n.Error, "telegram:") || strings.Contains(n.Error, "secret") {
		t.Fatalf("exhaustion: %+v", n)
	}
	srv.forwardDue(context.Background())
	if telegramPosts != 3+slackMaxAttempts {
		t.Fatal("retried exhausted delivery")
	}

}

func TestLegacyNotificationMigration(t *testing.T) {
	_, st, _ := newHubWith(t, allowLoopback)
	host, _, _ := st.CreateServer("legacy", "test", time.Hour)
	for _, status := range []string{"delivered", "failed", "skipped", "pending"} {
		_, err := st.db.Exec(`INSERT INTO notifications(server_id,rid,at,received_at,kind,severity,title,status,attempts,next_try) VALUES(?,?,1,1,'agent','high','legacy',?,3,123)`, host.ID, status, status)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := st.migrateSlack(); err != nil {
		t.Fatal(err)
	}
	var slack, telegram int
	_ = st.db.QueryRow(`SELECT COUNT(*) FROM notification_deliveries WHERE provider='slack'`).Scan(&slack)
	_ = st.db.QueryRow(`SELECT COUNT(*) FROM notification_deliveries WHERE provider='telegram'`).Scan(&telegram)
	if slack != 4 || telegram != 1 {
		t.Fatalf("legacy migration: slack=%d telegram=%d", slack, telegram)
	}
	due := st.dueNotifications("slack", 50)
	if len(due) != 1 || due[0].Attempts != 3 || due[0].Status != "pending" {
		t.Fatalf("legacy retry state lost: %+v", due)
	}
}
