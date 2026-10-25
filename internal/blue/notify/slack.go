// Package notify sends one-way updates to a Slack channel through an incoming
// webhook. It is deliberately not a bot: nothing is read back from Slack.
//
// Text that reaches Slack may contain attacker-controlled host data (process
// names, log lines, key comments) relayed by a model, so everything is
// escaped: no links, no @channel/@here pings, no user mentions.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

// Message is one update.
type Message struct {
	Server   string
	Kind     string // incident_opened | incident_resolved | action | agent | needs_ack | …
	Severity string // info | low | medium | high | critical
	Title    string
	Body     string
	Fields   map[string]string
	// IncidentID links the update to a task on the hub (0 = none).
	IncidentID int64
}

// Slack posts to an incoming webhook.
type Slack struct {
	URL  string
	HTTP *http.Client
}

// FromConfig resolves the webhook from an inline URL or a file (preferred:
// the URL is a credential).
func FromConfig(url, file string) *Slack {
	url = strings.TrimSpace(url)
	if url == "" && file != "" {
		if b, err := os.ReadFile(file); err == nil {
			url = strings.TrimSpace(string(b))
		}
	}
	// https only — except loopback, which exists for local testing with a
	// mock receiver and never leaves the host.
	if !strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "http://127.0.0.1:") && !strings.HasPrefix(url, "http://localhost:") {
		return nil
	}
	return &Slack{URL: url, HTTP: &http.Client{Timeout: 15 * time.Second}}
}

var sevEmoji = map[string]string{"critical": ":rotating_light:", "high": ":red_circle:", "medium": ":large_orange_circle:", "low": ":large_yellow_circle:", "info": ":large_blue_circle:"}

var (
	mentionRe = regexp.MustCompile(`(?i)@(channel|here|everyone)`)
	urlRe     = regexp.MustCompile(`(?i)\b(https?|ftp)://`)
)

// Escape neutralises Slack mrkdwn control sequences in untrusted text.
func Escape(s string) string {
	s = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
	s = mentionRe.ReplaceAllString(s, "@\u200b$1")
	// Break auto-linking so nothing in a notification is clickable.
	s = urlRe.ReplaceAllStringFunc(s, func(m string) string { return strings.Replace(m, "://", "[:]//", 1) })
	return s
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// Send posts the message. Errors are returned, never retried forever.
func (s *Slack) Send(ctx context.Context, m Message) error {
	if s == nil {
		return nil
	}
	emoji := sevEmoji[m.Severity]
	if emoji == "" {
		emoji = ":white_circle:"
	}
	header := fmt.Sprintf("%s *[%s] %s* — %s", emoji, Escape(m.Server), strings.ToUpper(Escape(m.Severity)), Escape(clip(m.Title, 200)))
	blocks := []map[string]any{
		{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": header}},
	}
	if body := strings.TrimSpace(m.Body); body != "" {
		blocks = append(blocks, map[string]any{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": Escape(clip(body, 2800))}})
	}
	if len(m.Fields) > 0 {
		var fields []map[string]any
		for k, v := range m.Fields {
			if len(fields) == 10 {
				break
			}
			fields = append(fields, map[string]any{"type": "mrkdwn", "text": fmt.Sprintf("*%s*\n%s", Escape(k), Escape(clip(v, 200)))})
		}
		blocks = append(blocks, map[string]any{"type": "section", "fields": fields})
	}
	blocks = append(blocks, map[string]any{"type": "context", "elements": []map[string]any{{"type": "mrkdwn", "text": fmt.Sprintf("kodeblue · %s · %s", Escape(m.Kind), time.Now().UTC().Format("2006-01-02 15:04 UTC"))}}})
	payload, _ := json.Marshal(map[string]any{
		"text":   fmt.Sprintf("[%s] %s %s", m.Server, strings.ToUpper(m.Severity), Escape(clip(m.Title, 200))), // fallback for notifications
		"blocks": blocks,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode != 200 {
		return fmt.Errorf("slack webhook %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

// Async sends in the background with a bounded timeout.
func (s *Slack) Async(m Message, onErr func(error)) {
	if s == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := s.Send(ctx, m); err != nil && onErr != nil {
			onErr(err)
		}
	}()
}
