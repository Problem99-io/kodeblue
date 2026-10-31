package notify

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

type telegramTransport func(*http.Request) (*http.Response, error)

func (f telegramTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestTelegramPayload(t *testing.T) {
	tg := TelegramFromConfig("123456:secret", "", "-100123456", "")
	tg.HTTP.Transport = telegramTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method != "POST" || r.URL.String() != "https://api.telegram.org/bot123456:secret/sendMessage" || r.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL)
		}
		var payload struct {
			ChatID   string `json:"chat_id"`
			Text     string `json:"text"`
			Entities []struct {
				Type           string
				Offset, Length int
			} `json:"entities"`
			ParseMode string `json:"parse_mode"`
			Preview   struct {
				Disabled bool `json:"is_disabled"`
			} `json:"link_preview_options"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if payload.ChatID != "-100123456" || payload.ParseMode != "" || !payload.Preview.Disabled {
			t.Fatalf("unsafe payload: %+v", payload)
		}
		for _, want := range []string{"[web-1] HIGH", "<b>attack</b>", "Incident: #3", "kodeblue"} {
			if !strings.Contains(payload.Text, want) {
				t.Errorf("missing %q in %q", want, payload.Text)
			}
		}
		if len(payload.Entities) != 1 || payload.Entities[0].Type != "pre" || payload.Entities[0].Offset != 0 || payload.Entities[0].Length != len(utf16.Encode([]rune(payload.Text))) {
			t.Fatal("missing copy-safe pre entity")
		}
		for _, indicator := range []string{"@everyone", "https://evil.example", "203.0.113.5", "/etc/cron.d/evil.sh", "root@host"} {
			if !strings.Contains(payload.Text, indicator) {
				t.Fatalf("indicator changed: %q", indicator)
			}
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"ok":true,"result":{}}`)), Header: make(http.Header)}, nil
	})
	err := tg.Send(context.Background(), Message{Server: "web-1", Severity: "high", Title: "<b>attack</b>", Body: "@everyone https://evil.example tg://user?id=1 t.me/evil 203.0.113.5 /etc/cron.d/evil.sh root@host 😀", Fields: map[string]string{"Incident": "#3"}})
	if err != nil {
		t.Fatal(err)
	}
}

func TestTelegramFailuresDoNotLeakToken(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		err        error
	}{
		{"network", "", 0, errors.New("https://api.telegram.org/bot123456:secret/sendMessage")},
		{"rate limit", `{"ok":false,"description":"123456:secret"}`, 429, nil},
		{"api error", `{"ok":false,"description":"123456:secret"}`, 200, nil},
		{"malformed", `123456:secret`, 200, nil},
		{"redirect", ``, 302, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tg := TelegramFromConfig("123456:secret", "", "-1", "")
			tg.HTTP.Transport = telegramTransport(func(*http.Request) (*http.Response, error) {
				if tc.err != nil {
					return nil, tc.err
				}
				return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.body)), Header: http.Header{"Location": []string{"https://evil.example/"}}}, nil
			})
			err := tg.Send(context.Background(), Message{Title: "test"})
			if err == nil || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "api.telegram.org") {
				t.Fatalf("unsafe error: %v", err)
			}
		})
	}
}

func TestTelegramConfigurationAndRouting(t *testing.T) {
	dir := t.TempDir()
	tokenFile, chatFile := filepath.Join(dir, "token"), filepath.Join(dir, "chat")
	if err := os.WriteFile(tokenFile, []byte("123456:secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(chatFile, []byte("-1001234\n"), 0600); err != nil {
		t.Fatal(err)
	}
	tg := TelegramFromConfig("", tokenFile, "", chatFile)
	if tg == nil || tg.Token != "123456:secret" || tg.ChatID != "-1001234" {
		t.Fatalf("file configuration: %+v", tg)
	}
	for _, token := range []string{"", "123:secret/../getUpdates", "123:secret?x=y", "https://evil.example", "123:secret\n"} {
		if ValidateTelegramToken(token) == nil {
			t.Errorf("accepted unsafe token %q", token)
		}
	}
	for _, chat := range []string{"", "0", "../sendMessage", "@x", "-1\n"} {
		if ValidateTelegramChat(chat) == nil {
			t.Errorf("accepted invalid chat %q", chat)
		}
	}
	if TelegramFromConfig("", filepath.Join(dir, "missing"), "-1", "") != nil {
		t.Fatal("missing token enabled Telegram")
	}
	if s := New(false, nil, "", "", false, tg); !Enabled(s) || ViaHub(s) {
		t.Fatal("standalone Telegram routing")
	}
	if s := New(true, &memQueue{}, "", "", false, tg); !ViaHub(s) {
		t.Fatal("hub routing")
	} else if _, ok := s.(*Outbox); !ok {
		t.Fatal("local Telegram used without direct=true")
	}
	if s := New(true, &memQueue{}, "", "", true, tg); !ViaHub(s) {
		t.Fatal("direct Telegram lost outbox")
	} else if _, ok := s.(multi); !ok {
		t.Fatal("direct Telegram missing")
	}
	if Enabled(New(false, nil, "", "", false, (*Telegram)(nil))) {
		t.Fatal("typed nil enabled Telegram")
	}
}

func TestTelegramUnicodeLimit(t *testing.T) {
	text := telegramMessage(Message{Server: "server", Title: strings.Repeat("🚨", 5000), Body: string([]byte{0xff})})
	if !utf8.ValidString(text) || len(utf16.Encode([]rune(text))) > 4096 || !strings.HasSuffix(text, "…") {
		t.Fatalf("invalid or oversized message (%d bytes)", len(text))
	}
}

func TestTelegramDescriptionsAndRetryPolicy(t *testing.T) {
	for _, code := range []int{400, 401, 403, 404, 429} {
		tg := TelegramFromConfig("123:secret", "", "-1", "")
		tg.HTTP.Transport = telegramTransport(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(`{"ok":false,"description":"chat not found 123:secret","parameters":{"retry_after":123}}`)), Header: make(http.Header)}, nil
		})
		err := tg.Send(context.Background(), Message{Body: "203.0.113.5 /etc/cron.d/evil.sh root@host"})
		var delivery *DeliveryError
		if !errors.As(err, &delivery) || !strings.Contains(err.Error(), "chat not found") || strings.Contains(err.Error(), "123:secret") || delivery.Permanent() != (code != 429) || delivery.RetryAfter != 123*time.Second {
			t.Fatalf("policy: %+v %v", delivery, err)
		}
	}
}
