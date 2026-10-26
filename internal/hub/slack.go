package hub

// Notification delivery lives in the control center. Servers never hold a Slack webhook when
// they report to a hub: they queue notifications (agent posts, containment
// actions, incidents, maintenance windows…) and ship them with their sync.
// The hub stores each one, shows it in the console, and posts it to the
// fleet's channel with retries.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
	"github.com/Problem99-io/kodeblue/internal/blue/notify"
)

const (
	settingSlackWebhook = "slack_webhook"
	settingSlackMinSev  = "slack_min_severity"
	slackMaxAttempts    = 8
)

var sevRank = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

func (s *Store) migrateSlack() error {
	if _, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS notifications (id INTEGER PRIMARY KEY AUTOINCREMENT, server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  rid TEXT NOT NULL, at INTEGER NOT NULL, received_at INTEGER NOT NULL, kind TEXT NOT NULL, severity TEXT NOT NULL, title TEXT NOT NULL,
  body TEXT NOT NULL DEFAULT '', fields TEXT NOT NULL DEFAULT '{}', incident_id INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0, next_try INTEGER NOT NULL DEFAULT 0,
  error TEXT NOT NULL DEFAULT '', delivered_at INTEGER NOT NULL DEFAULT 0, UNIQUE(server_id, rid));
CREATE INDEX IF NOT EXISTS notifications_status ON notifications(status, next_try);
CREATE INDEX IF NOT EXISTS notifications_server ON notifications(server_id, id);
CREATE TABLE IF NOT EXISTS notification_deliveries (
  notification_id INTEGER NOT NULL REFERENCES notifications(id) ON DELETE CASCADE,
  provider TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0,
  next_try INTEGER NOT NULL DEFAULT 0, error TEXT NOT NULL DEFAULT '', delivered_at INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(notification_id, provider));
CREATE INDEX IF NOT EXISTS notification_deliveries_due ON notification_deliveries(provider,status,next_try);
INSERT OR IGNORE INTO notification_deliveries(notification_id,provider,status,attempts,next_try,error,delivered_at)
  SELECT id,'slack',status,attempts,next_try,error,delivered_at FROM notifications;
INSERT OR IGNORE INTO notification_deliveries(notification_id,provider)
  SELECT id,'telegram' FROM notifications WHERE status='pending';`); err != nil {
		return err
	}
	// Earlier hubs kept a "fleet default" webhook to hand to servers; it is
	// now the hub's own destination.
	if s.Setting(settingSlackWebhook) == "" {
		if old := s.Setting("fleet_slack_webhook"); old != "" {
			_ = s.SetSetting(settingSlackWebhook, old)
		}
	}
	_ = s.SetSetting("fleet_slack_webhook", "")
	return nil
}

// addNotification stores one notification from a server's sync. The server's
// own id is the dedupe key, so a re-sent batch is never posted twice.
func addNotification(tx *sql.Tx, server string, r hubproto.Record) (bool, error) {
	var n struct {
		Kind       string            `json:"kind"`
		Severity   string            `json:"severity"`
		Title      string            `json:"title"`
		Body       string            `json:"body"`
		Fields     map[string]string `json:"fields"`
		IncidentID int64             `json:"incident_id"`
	}
	if err := json.Unmarshal(r.Data, &n); err != nil || strings.TrimSpace(n.Title) == "" {
		return false, nil
	}
	if _, ok := sevRank[n.Severity]; !ok {
		n.Severity = "info"
	}
	if len(n.Fields) > 10 {
		n.Fields = nil
	}
	f, _ := json.Marshal(n.Fields)
	res, err := tx.Exec(`INSERT INTO notifications(server_id,rid,at,received_at,kind,severity,title,body,fields,incident_id) VALUES(?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(server_id,rid) DO NOTHING`, server, r.ID, r.UpdatedAt.Unix(), time.Now().Unix(), trim(n.Kind, 40), n.Severity, trim(n.Title, 300), trim(n.Body, 4000), string(f), n.IncidentID)
	if err != nil {
		return false, err
	}
	added, _ := res.RowsAffected()
	if added > 0 {
		id, err := res.LastInsertId()
		if err != nil {
			return false, err
		}
		if _, err := tx.Exec(`INSERT INTO notification_deliveries(notification_id,provider) VALUES(?,'slack'),(?,'telegram')`, id, id); err != nil {
			return false, err
		}
	}
	return added > 0, nil
}

type Notification struct {
	ID          int64             `json:"id"`
	ServerID    string            `json:"server_id"`
	ServerName  string            `json:"server_name"`
	At          time.Time         `json:"at"`
	Kind        string            `json:"kind"`
	Severity    string            `json:"severity"`
	Title       string            `json:"title"`
	Body        string            `json:"body,omitempty"`
	Fields      map[string]string `json:"fields,omitempty"`
	IncidentID  int64             `json:"incident_id,omitempty"`
	Status      string            `json:"status"` // pending | delivered | failed | skipped
	Attempts    int               `json:"attempts"`
	Error       string            `json:"error,omitempty"`
	DeliveredAt time.Time         `json:"delivered_at,omitempty"`
}

func (s *Store) Notifications(server string, limit int) []Notification {
	q := `SELECT n.id,n.server_id,s.name,n.at,n.kind,n.severity,n.title,n.body,n.fields,n.incident_id,n.status,n.attempts,n.error,n.delivered_at
FROM notifications n JOIN servers s ON s.id=n.server_id`
	args := []any{}
	if server != "" {
		q += ` WHERE n.server_id=?`
		args = append(args, server)
	}
	return s.notifications(q+` ORDER BY n.id DESC LIMIT ?`, append(args, limit)...)
}

func (s *Store) dueNotifications(provider string, limit int) []Notification {
	return s.notifications(`SELECT n.id,n.server_id,s.name,n.at,n.kind,n.severity,n.title,n.body,n.fields,n.incident_id,d.status,d.attempts,d.error,d.delivered_at
FROM notification_deliveries d JOIN notifications n ON n.id=d.notification_id JOIN servers s ON s.id=n.server_id
WHERE d.provider=? AND d.status='pending' AND d.next_try<=? ORDER BY n.id LIMIT ?`, provider, time.Now().Unix(), limit)
}

func (s *Store) notifications(q string, args ...any) []Notification {
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []Notification{}
	for rows.Next() {
		var n Notification
		var at, del int64
		var f string
		_ = rows.Scan(&n.ID, &n.ServerID, &n.ServerName, &at, &n.Kind, &n.Severity, &n.Title, &n.Body, &f, &n.IncidentID, &n.Status, &n.Attempts, &n.Error, &del)
		_ = json.Unmarshal([]byte(f), &n.Fields)
		n.At = time.Unix(at, 0)
		if del > 0 {
			n.DeliveredAt = time.Unix(del, 0)
		}
		out = append(out, n)
	}
	return out
}

func (s *Store) markNotification(provider string, id int64, status, errText string, attempts int, next time.Time) {
	tx, err := s.db.Begin()
	if err != nil {
		return
	}
	defer tx.Rollback()
	del := int64(0)
	if status == "delivered" {
		del = time.Now().Unix()
	}
	_, err = tx.Exec(`UPDATE notification_deliveries SET status=?,error=?,attempts=?,next_try=?,delivered_at=? WHERE notification_id=? AND provider=?`, status, trim(errText, 500), attempts, next.Unix(), del, id, provider)
	if err != nil {
		return
	}
	// Keep the notification history's summary, with independent retries per destination.
	_, err = tx.Exec(`UPDATE notifications SET
status=(SELECT CASE WHEN SUM(status='pending')>0 THEN 'pending' WHEN SUM(status='failed')>0 THEN 'failed' WHEN SUM(status='delivered')>0 THEN 'delivered' ELSE 'skipped' END FROM notification_deliveries WHERE notification_id=?),
attempts=(SELECT MAX(attempts) FROM notification_deliveries WHERE notification_id=?),
error=COALESCE((SELECT GROUP_CONCAT(provider || ': ' || error, '; ') FROM notification_deliveries WHERE notification_id=? AND error!='' AND status IN ('pending','failed')),''),
delivered_at=(SELECT MAX(delivered_at) FROM notification_deliveries WHERE notification_id=?) WHERE id=?`, id, id, id, id, id)
	if err == nil {
		_ = tx.Commit()
	}
}

// SlackSettings is what the console may see: never the webhook itself.
type SlackSettings struct {
	Configured  bool   `json:"configured"`
	MinSeverity string `json:"min_severity"`
}

func (s *Store) SlackSettings() SlackSettings {
	min := s.Setting(settingSlackMinSev)
	if min == "" {
		min = "info"
	}
	return SlackSettings{Configured: s.Setting(settingSlackWebhook) != "", MinSeverity: min}
}

// ValidateWebhook accepts an https URL (Slack incoming webhooks are
// https://hooks.slack.com/…), or loopback http for local testing.
func ValidateWebhook(u string) error {
	u = strings.TrimSpace(u)
	if notify.FromConfig(u, "") == nil || strings.ContainsAny(u, " \t\r\n") {
		return errors.New("webhook must be an https:// URL (e.g. https://hooks.slack.com/services/…)")
	}
	return nil
}

// slackTo is the hub's poster for a webhook, nil when it is invalid. It
// goes through the same guarded client as model endpoints (egress.go): an
// operator-set webhook must not reach the hub's loopback or metadata
// addresses, follow redirects to another host, or use an environment proxy.
func (s *Server) slackTo(hook string) *notify.Slack {
	sl := notify.FromConfig(hook, "")
	if sl != nil {
		sl.HTTP = s.models.client
	}
	return sl
}

func (s *Server) wakeSlack() {
	select {
	case s.slackWake <- struct{}{}:
	default:
	}
}

// NotificationForwarder posts stored notifications to configured destinations
// until ctx ends: at most one in flight, retries with backoff, and a final
// "failed" after slackMaxAttempts. The server name comes from the hub, not
// from the server's own data, so a server cannot post as another.
func (s *Server) NotificationForwarder(ctx context.Context) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		s.forwardDue(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.slackWake:
		}
	}
}

func (s *Server) forwardDue(ctx context.Context) {
	for _, provider := range []string{"slack", "telegram"} {
		for _, n := range s.st.dueNotifications(provider, 50) {
			if ctx.Err() != nil {
				return
			}
			var sender notify.Sender
			var minimum string
			if provider == "slack" {
				minimum = s.st.SlackSettings().MinSeverity
				if sl := s.slackTo(s.st.Setting(settingSlackWebhook)); sl != nil {
					sender = sl
				}
			} else {
				minimum = s.st.TelegramSettings().MinSeverity
				if tg := s.telegram(); tg != nil {
					sender = tg
				}
			}
			if sender == nil || sevRank[n.Severity] < sevRank[minimum] {
				s.st.markNotification(provider, n.ID, "skipped", "", n.Attempts, time.Time{})
				continue
			}
			cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
			err := sender.Send(cctx, notify.Message{Server: n.ServerName, Kind: n.Kind, Severity: n.Severity, Title: n.Title, Body: n.Body, Fields: n.Fields, IncidentID: n.IncidentID})
			cancel()
			if err == nil {
				s.st.markNotification(provider, n.ID, "delivered", "", n.Attempts+1, time.Time{})
				continue
			}
			attempts := n.Attempts + 1
			if attempts >= slackMaxAttempts {
				s.st.markNotification(provider, n.ID, "failed", err.Error(), attempts, time.Time{})
				s.log.Error("notification delivery failed for good", "provider", provider, "notification", n.ID, "error", err)
				continue
			}
			backoff := time.Duration(30<<min(attempts, 6)) * time.Second
			s.st.markNotification(provider, n.ID, "pending", err.Error(), attempts, time.Now().Add(backoff))
			s.log.Warn("notification delivery failed; will retry", "provider", provider, "notification", n.ID, "attempt", attempts, "error", err)
		}
	}
}

// ---- operator API ----

func (s *Server) slackRoutes() {
	s.telegramRoutes()
	s.mux.HandleFunc("GET /api/notifications", s.op(s.handleNotifications))
	s.mux.HandleFunc("GET /api/settings/slack", s.op(s.handleSlackGet))
	s.mux.HandleFunc("PUT /api/settings/slack", s.op(s.handleSlackPut))
	s.mux.HandleFunc("POST /api/settings/slack/test", s.op(s.handleSlackTest))
}

func (s *Server) handleNotifications(w http.ResponseWriter, r *http.Request, c *opCtx) {
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		fmt.Sscan(v, &limit)
	}
	limit = min(max(limit, 1), 1000)
	writeJSON(w, http.StatusOK, s.st.Notifications(r.URL.Query().Get("server_id"), limit))
}

func (s *Server) handleSlackGet(w http.ResponseWriter, r *http.Request, c *opCtx) {
	writeJSON(w, http.StatusOK, s.st.SlackSettings())
}

func (s *Server) handleSlackPut(w http.ResponseWriter, r *http.Request, c *opCtx) {
	var req struct {
		WebhookURL  *string `json:"webhook_url"`
		MinSeverity *string `json:"min_severity"`
	}
	if err := readJSON(w, r, 8<<10, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	if req.WebhookURL != nil {
		u := strings.TrimSpace(*req.WebhookURL)
		if u != "" {
			if err := ValidateWebhook(u); err != nil {
				writeErr(w, http.StatusBadRequest, err.Error())
				return
			}
		}
		_ = s.st.SetSetting(settingSlackWebhook, u)
		action := "slack.webhook_set"
		if u == "" {
			action = "slack.webhook_cleared"
		}
		s.st.Audit(c.user.Name, action, "", "", c.ip)
	}
	if req.MinSeverity != nil {
		if _, ok := sevRank[*req.MinSeverity]; !ok {
			writeErr(w, http.StatusBadRequest, "min_severity must be info, low, medium, high or critical")
			return
		}
		_ = s.st.SetSetting(settingSlackMinSev, *req.MinSeverity)
		s.st.Audit(c.user.Name, "slack.min_severity", "", *req.MinSeverity, c.ip)
	}
	writeJSON(w, http.StatusOK, s.st.SlackSettings())
}

func (s *Server) handleSlackTest(w http.ResponseWriter, r *http.Request, c *opCtx) {
	sl := s.slackTo(s.st.Setting(settingSlackWebhook))
	if sl == nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": "Slack is not configured"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	err := sl.Send(ctx, notify.Message{Server: "kodeblue hub", Kind: "test", Severity: "info", Title: "Test message from the kodeblue hub",
		Body: "Sent by " + c.user.Name + ". Server notifications will arrive in this channel."})
	s.st.Audit(c.user.Name, "slack.test", "", fmt.Sprint(err == nil), c.ip)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
