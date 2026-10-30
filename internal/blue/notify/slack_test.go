package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEscapeNeutralisesInjection(t *testing.T) {
	in := "<!channel> @here click <https://evil.example/x|your bank> & see http://a.b"
	out := Escape(in)
	for _, bad := range []string{"<!channel>", "<https://", "@here", "http://"} {
		if strings.Contains(out, bad) {
			t.Errorf("escaped text still contains %q: %s", bad, out)
		}
	}
}

func TestSendPostsBlocks(t *testing.T) {
	var got map[string]any
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	s := &Slack{URL: srv.URL, HTTP: srv.Client()}
	if err := s.Send(context.Background(), Message{Server: "web-1", Kind: "action", Severity: "high", Title: "Blocked 198.51.100.7", Body: "brute force then success", Fields: map[string]string{"incident": "#3"}}); err != nil {
		t.Fatal(err)
	}
	if got["text"] == nil || len(got["blocks"].([]any)) < 3 {
		t.Fatalf("unexpected payload %v", got)
	}
}

func TestSlackTransportErrorRedactsWebhook(t *testing.T) {
	url := "https://hooks.slack.com/services/secret/webhook"
	s := &Slack{URL: url, HTTP: &http.Client{Transport: telegramTransport(func(*http.Request) (*http.Response, error) { return nil, fmt.Errorf("network failure for %s", url) })}}
	if err := s.Send(context.Background(), Message{}); err == nil || strings.Contains(err.Error(), url) || strings.Contains(err.Error(), "secret/webhook") {
		t.Fatalf("webhook exposed: %v", err)
	}
}

func TestSlackRedactsDifferentErrorURL(t *testing.T) {
	slack := FromConfig("https://hooks.slack.com/services/configured-secret", "")
	slack.HTTP = &http.Client{Transport: redactionTransport(func(r *http.Request) (*http.Response, error) {
		return nil, errors.New("failed at https://alternate.example/another-secret")
	})}
	err := slack.Send(context.Background(), Message{Title: "test"})
	if err == nil || strings.Contains(err.Error(), "alternate.example") || strings.Contains(err.Error(), "another-secret") {
		t.Fatalf("incomplete URL redaction: %v", err)
	}
}

type redactionTransport func(*http.Request) (*http.Response, error)

func (f redactionTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
