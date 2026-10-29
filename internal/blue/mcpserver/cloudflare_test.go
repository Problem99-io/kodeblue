package mcpserver

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/cloudflare"
	"github.com/Problem99-io/kodeblue/internal/blue/config"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

func TestCloudflareToolUsesAuthenticatedHubAndUntrustedOutput(t *testing.T) {
	key := "kbk_synthetic_server_key"
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/v1/cloudflare" || r.Header.Get("Authorization") != "Bearer "+key {
			t.Error("wrong hub authentication or route")
		}
		var q struct{ IP string }
		_ = json.NewDecoder(r.Body).Decode(&q)
		if q.IP != "" && q.IP != "192.0.2.1" {
			t.Error("lost queried IP")
		}
		io.WriteString(w, `{"configured":true,"zone_ids":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],"notes":["<script>hostile evidence</script>","`+key+`"]}`)
	}))
	defer hub.Close()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Server.StateDir = dir
	cfg.Hub.URL = hub.URL
	cfg.Hub.KeyFile = filepath.Join(dir, "hub.key")
	if err := os.WriteFile(cfg.Hub.KeyFile, []byte(key), 0600); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "kb.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s := New(cfg, st)
	var fn func(context.Context, json.RawMessage) (string, error)
	for _, tool := range s.tools {
		if tool.Name == "cloudflare_context" {
			fn = tool.Fn
		}
	}
	if fn == nil {
		t.Fatal("tool not registered")
	}
	text, err := fn(context.Background(), json.RawMessage(`{"ip":"192.0.2.1"}`))
	if err != nil || !strings.HasSuffix(text, cloudflareUntrusted) || !strings.Contains(text, "hostile evidence") || strings.Contains(text, key) {
		t.Fatalf("unsafe output: %q %v", text, err)
	}
}

func TestCloudflareHubErrorsAndInvalidQueriesDoNotJournal(t *testing.T) {
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(429)
		io.WriteString(w, `{"error":"Cloudflare lookup budget reached; wait a minute"}`)
	}))
	defer hub.Close()
	cfg := config.Default()
	dir := t.TempDir()
	cfg.Hub.URL = hub.URL
	cfg.Hub.KeyFile = filepath.Join(dir, "hub.key")
	_ = os.WriteFile(cfg.Hub.KeyFile, []byte("kbk_synthetic_server_key"), 0600)
	st, err := store.Open(filepath.Join(dir, "kb.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s := New(cfg, st)
	_, err = s.cloudflareViaHub(context.Background(), cloudflare.Query{})
	if err == nil || !strings.Contains(err.Error(), "wait a minute") {
		t.Fatalf("hub error lost: %v", err)
	}
	_, err = s.cloudflareContext(context.Background(), json.RawMessage(`{"ip":"not an IP"}`))
	if err == nil {
		t.Fatal("invalid query accepted")
	}
	if len(st.JournalSince(time.Now().Add(-time.Hour), 100)) != 0 {
		t.Fatal("lookups polluted security journal")
	}
}
