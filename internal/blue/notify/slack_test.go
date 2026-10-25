package notify

import (
	"context"
	"encoding/json"
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
