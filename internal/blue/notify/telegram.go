package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Telegram sends one-way updates through the Bot API. It never reads commands.
type Telegram struct {
	Token, ChatID string
	HTTP          *http.Client
}

var telegramTokenRE = regexp.MustCompile(`^[0-9]+:[A-Za-z0-9_-]+$`)
var telegramLinkRE = regexp.MustCompile(`(?i)\btg://`)
var telegramChatRE = regexp.MustCompile(`^(-?[1-9][0-9]*|@[A-Za-z][A-Za-z0-9_]{4,})$`)

func ValidateTelegramToken(token string) error {
	if !telegramTokenRE.MatchString(token) {
		return errors.New("Telegram bot token must have the form <bot ID>:<secret>")
	}
	return nil
}

func ValidateTelegramChat(chat string) error {
	if !telegramChatRE.MatchString(chat) {
		return errors.New("Telegram chat ID must be a nonzero numeric ID or @channelusername")
	}
	return nil
}

// TelegramFromConfig prefers an inline token, otherwise reading the secret file.
func TelegramFromConfig(token, file, chat, chatFile string) *Telegram {
	token, chat = strings.TrimSpace(token), strings.TrimSpace(chat)
	if chat == "" && chatFile != "" {
		if b, err := os.ReadFile(chatFile); err == nil {
			chat = strings.TrimSpace(string(b))
		}
	}
	if token == "" && file != "" {
		if b, err := os.ReadFile(file); err == nil {
			token = strings.TrimSpace(string(b))
		}
	}
	if ValidateTelegramToken(token) != nil || ValidateTelegramChat(chat) != nil {
		return nil
	}
	return &Telegram{Token: token, ChatID: chat, HTTP: &http.Client{Timeout: 15 * time.Second}}
}

// telegramText contains host data: no formatting, clickable URLs or mentions.
func telegramText(s string) string {
	s = strings.ToValidUTF8(s, "�")
	s = strings.ReplaceAll(s, "@", "@\u200b")
	s = urlRe.ReplaceAllStringFunc(s, func(v string) string { return strings.Replace(v, "://", "[:]//", 1) })
	s = telegramLinkRE.ReplaceAllString(s, "tg[:]//")
	// Break bare domain auto-links too (including t.me and www.example.com).
	return strings.ReplaceAll(s, ".", ".\u200b")
}

func telegramMessage(m Message) string {
	text := fmt.Sprintf("[%s] %s — %s\n\n%s", m.Server, strings.ToUpper(m.Severity), m.Title, m.Body)
	keys := make([]string, 0, len(m.Fields))
	for k := range m.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys[:min(len(keys), 10)] {
		text += "\n" + k + ": " + m.Fields[k]
	}
	text += "\n\nkodeblue · " + m.Kind
	// Telegram's 4096-character limit also counts UTF-16 surrogate pairs.
	var b strings.Builder
	units := 0
	for _, r := range telegramText(text) {
		n := 1
		if r > 0xffff {
			n = 2
		}
		if units+n > 4095 {
			b.WriteRune('…')
			break
		}
		b.WriteRune(r)
		units += n
	}
	return b.String()
}

func (s *Telegram) Send(ctx context.Context, m Message) error {
	if s == nil {
		return nil
	}
	if ValidateTelegramToken(s.Token) != nil || ValidateTelegramChat(s.ChatID) != nil {
		return errors.New("invalid Telegram configuration")
	}
	payload, _ := json.Marshal(map[string]any{
		"chat_id": s.ChatID, "text": telegramMessage(m),
		"link_preview_options": map[string]bool{"is_disabled": true},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.telegram.org/bot"+s.Token+"/sendMessage", bytes.NewReader(payload))
	if err != nil {
		return errors.New("could not create Telegram request")
	}
	req.Header.Set("Content-Type", "application/json")
	client := s.HTTP
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	// The credential is in the URL: never follow redirects or return raw errors.
	safe := *client
	safe.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := safe.Do(req)
	if err != nil {
		return errors.New("Telegram request failed (check connectivity and bot configuration)")
	}
	defer resp.Body.Close()
	var result struct {
		OK bool `json:"ok"`
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Telegram API returned HTTP %d", resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&result); err != nil || !result.OK {
		return errors.New("Telegram API rejected the message or returned an invalid response")
	}
	return nil
}

func (s *Telegram) Async(m Message, onErr func(error)) {
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
