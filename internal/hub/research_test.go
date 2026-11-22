package hub

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
	"github.com/Problem99-io/kodeblue/internal/research"
)

func TestResearchPermissionsAndIngest(t *testing.T) {
	r, err := research.Open(t.TempDir(), research.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	_, st, ts := newHubWith(t, func(o *Options) { o.Research = r })
	a, tok, _ := st.CreateServer("gateway", "test", time.Hour)
	_, key, _ := st.Enroll(tok, "gateway", "test")
	_, tok2, _ := st.CreateServer("foreign", "test", time.Hour)
	_, foreign, _ := st.Enroll(tok2, "foreign", "test")
	client, csrf := signIn(t, st, ts)
	siteURL := ts.URL + "/api/research/sites/test"
	site := research.Site{Name: "Website", Timezone: "UTC", Origins: []string{"https://example.com"}, Servers: []string{a.ID}, BrowserEnabled: true}
	if code, _ := do(t, client, "PUT", siteURL, "", "", site); code != 403 {
		t.Fatal("missing CSRF accepted")
	}
	if code, b := do(t, client, "PUT", siteURL, "", csrf, site); code != 200 {
		t.Fatalf("site: %d %s", code, b)
	}
	batch := map[string]any{"events": []research.Event{{ID: "one", At: time.Now(), Kind: "request", Path: "/.env?token=secret", Method: "GET", Status: 404}}}
	path := ts.URL + hubproto.PathPrefix + "research/test"
	seen := st.GetServer(a.ID).LastSeen
	if code, _ := do(t, client, "POST", path, foreign, "", batch); code != 403 {
		t.Fatalf("foreign write: %d", code)
	}
	if code, b := do(t, client, "POST", path, key, "", batch); code != 200 {
		t.Fatalf("ingest: %d %s", code, b)
	}
	if !st.GetServer(a.ID).LastSeen.Equal(seen) {
		t.Fatal("passive ingest wrote control-plane Seen state")
	}
	if code, _ := do(t, &http.Client{}, "GET", siteURL+"/events", key, "", nil); code != 401 {
		t.Fatalf("server key gained read access: %d", code)
	}
	code, b := do(t, client, "GET", siteURL+"/events", "", "", nil)
	if code != 200 || bytes.Contains(b, []byte("token=secret")) || !bytes.Contains(b, []byte("enrolled_source_reported")) {
		t.Fatalf("unsafe evidence: %d %s", code, b)
	}
	if code, _ := do(t, client, "DELETE", siteURL, "", csrf, nil); code != 200 {
		t.Fatal("delete failed")
	}
	if code, _ := do(t, client, "POST", path, key, "", batch); code != 403 {
		t.Fatalf("deleted site write: %d", code)
	}
}

func TestResearchBrowserBoundaryAndConsoleAllow(t *testing.T) {
	r, err := research.Open(t.TempDir(), research.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	if err = r.PutSite(t.Context(), research.Site{ID: "test", Name: "Site", Timezone: "UTC", Origins: []string{"https://example.com"}, BrowserEnabled: true}); err != nil {
		t.Fatal(err)
	}
	s, _, _ := newHubWith(t, func(o *Options) { o.Research = r; o.ConsoleAllow = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")} })
	call := func(path, origin, body string) (int, []byte) {
		req, _ := http.NewRequest("POST", "http://hub"+path, bytes.NewBufferString(body))
		req.RemoteAddr = "203.0.113.9:1234"
		req.Header.Set("Origin", origin)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req)
		return w.Code, w.Body.Bytes()
	}
	good, _ := json.Marshal(map[string]any{"events": []research.Event{{ID: "one", At: time.Now(), Kind: "pageview", Path: "/"}}})
	if code, _ := call("/collect/research/test", "https://evil.example", string(good)); code != 403 {
		t.Fatalf("origin: %d", code)
	}
	if code, b := call("/collect/research/test", "https://example.com", string(good)); code != 200 {
		t.Fatalf("public collection behind console allow: %d %s", code, b)
	}
	if code, _ := call("/api/research/sites/test", "https://example.com", string(good)); code != 404 {
		t.Fatal("console allow bypass")
	}
	forged, _ := json.Marshal(map[string]any{"events": []research.Event{{ID: "forged", At: time.Now(), Kind: "pageview", PeerIP: "203.0.113.5"}}})
	if code, _ := call("/collect/research/test", "https://example.com", string(forged)); code != 400 {
		t.Fatal("browser forged trusted context")
	}
	if code, _ := call("/collect/research/test", "https://example.com", string(good)+"{}"); code != 400 {
		t.Fatal("trailing JSON accepted")
	}
}

func TestResearchDisabledDoesNotOpenStoreOrInvokeAgent(t *testing.T) {
	_, st, ts := newHub(t)
	client, _ := signIn(t, st, ts)
	code, b := do(t, client, "GET", ts.URL+"/api/research", "", "", nil)
	if code != 200 || !bytes.Contains(b, []byte(`"enabled":false`)) {
		t.Fatalf("disabled: %d %s", code, b)
	}
	if code, _ = do(t, client, "POST", ts.URL+"/collect/research/anything", "", "", map[string]any{}); code != 404 {
		t.Fatal("collector enabled by default")
	}
}
