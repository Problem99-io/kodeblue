package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf16"
)

// Telegram sends one-way updates through the Bot API. It never reads commands.
type Telegram struct {
	Token, ChatID string
	HTTP          *http.Client
}

var telegramTokenRE = regexp.MustCompile(`^[0-9]+:[A-Za-z0-9_-]+$`)
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
		} else if !os.IsNotExist(err) || chatFile != "/etc/kodeblue/telegram.chat" {
			slog.Warn("could not read Telegram chat file")
		}
	}
	if token == "" && file != "" {
		if b, err := os.ReadFile(file); err == nil {
			token = strings.TrimSpace(string(b))
		} else if !os.IsNotExist(err) || file != "/etc/kodeblue/telegram.token" {
			slog.Warn("could not read Telegram token file")
		}
	}
	if ValidateTelegramToken(token) != nil || ValidateTelegramChat(chat) != nil {
		if token != "" || chat != "" {
			slog.Warn("Telegram configuration is incomplete or invalid; delivery disabled")
		}
		return nil
	}
	return &Telegram{Token: token, ChatID: chat, HTTP: &http.Client{Timeout: 15 * time.Second}}
}

// Preserve copied indicators exactly. A pre entity prevents interpreting
// host strings as links, mentions or formatting; no invisible separators.
func telegramText(s string) string { return strings.ToValidUTF8(s, "�") }

type DeliveryError struct {
	Code        int
	Description string
	RetryAfter  time.Duration
}

func (e *DeliveryError) Error() string {
	return fmt.Sprintf("Telegram API HTTP %d: %s", e.Code, e.Description)
}
func (e *DeliveryError) Permanent() bool {
	return e.Code == 400 || e.Code == 401 || e.Code == 403 || e.Code == 404
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
	text := telegramMessage(m)
	payload, _ := json.Marshal(map[string]any{
		"chat_id": s.ChatID, "text": text,
		"entities":             []map[string]any{{"type": "pre", "offset": 0, "length": len(utf16.Encode([]rune(text)))}},
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
		OK          bool   `json:"ok"`
		Description string `json:"description"`
		Code        int    `json:"error_code"`
		Parameters  struct {
			Retry int `json:"retry_after"`
		} `json:"parameters"`
	}
	decodeErr := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&result)
	if resp.StatusCode != http.StatusOK || (decodeErr == nil && !result.OK) {
		code := resp.StatusCode
		if result.Code != 0 {
			code = result.Code
		}
		description := strings.ReplaceAll(strings.TrimSpace(result.Description), s.Token, "[redacted]")
		description = strings.Map(func(r rune) rune {
			if r < ' ' || r == 127 {
				return -1
			}
			return r
		}, description)
		if len([]rune(description)) > 256 {
			description = string([]rune(description)[:256])
		}
		if description == "" {
			description = "request rejected"
		}
		return &DeliveryError{Code: code, Description: description, RetryAfter: time.Duration(min(max(result.Parameters.Retry, 0), 86400)) * time.Second}
	}
	if decodeErr != nil {
		return errors.New("Telegram API returned an invalid response")
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
