package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// Exercise an actual TLS connection and the wire payload, without using a
// Telegram credential or sending incident text to an external service.
func TestTelegramHTTPSDelivery(t *testing.T) {
	received := make(chan map[string]json.RawMessage, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/bot123456:local-test/sendMessage" || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected Telegram wire request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var payload map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode wire payload: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		received <- payload
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":1}}`))
	}))
	defer server.Close()
	endpoint, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := server.Client()
	transport := client.Transport
	client.Transport = telegramTransport(func(r *http.Request) (*http.Response, error) {
		// Keep production endpoint construction under test; only the test's
		// transport routes its connection to the trusted local TLS receiver.
		if r.URL.Scheme != "https" || r.URL.Host != "api.telegram.org" {
			t.Errorf("unexpected production endpoint: %s://%s", r.URL.Scheme, r.URL.Host)
		}
		routed := r.Clone(r.Context())
		copyURL := *r.URL
		routed.URL = &copyURL
		routed.URL.Scheme, routed.URL.Host = endpoint.Scheme, endpoint.Host
		return transport.RoundTrip(routed)
	})
	tg := &Telegram{Token: "123456:local-test", ChatID: "-1001234", HTTP: client}
	if err := tg.Send(context.Background(), Message{Server: "local-test", Severity: "high", Title: "Local delivery check"}); err != nil {
		t.Fatal(err)
	}
	select {
	case payload := <-received:
		var chat, text string
		if err := json.Unmarshal(payload["chat_id"], &chat); err != nil || chat != "-1001234" {
			t.Fatalf("wire chat_id = %q, error %v", chat, err)
		}
		if err := json.Unmarshal(payload["text"], &text); err != nil || text == "" {
			t.Fatalf("wire text missing: %v", err)
		}
		if _, ok := payload["parse_mode"]; ok {
			t.Fatal("untrusted notification text must not enable formatting")
		}
	default:
		t.Fatal("Telegram receiver did not get a message")
	}
}
