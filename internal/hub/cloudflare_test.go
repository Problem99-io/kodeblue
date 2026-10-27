package hub

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/cloudflare"
)

type cloudflareTransport func(*http.Request) (*http.Response, error)

func (f cloudflareTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestCloudflareSettingsStayOnHubAndAreServerScoped(t *testing.T) {
	s, st, ts := newHub(t)
	a, token, _ := st.CreateServer("one", "test", time.Hour)
	_, key, _ := st.Enroll(token, "one", "test")
	b, otherToken, _ := st.CreateServer("two", "test", time.Hour)
	_, otherKey, _ := st.Enroll(otherToken, "two", "test")
	client, csrf := signIn(t, st, ts)
	zone := strings.Repeat("a", 32)
	secret := "synthetic-cloudflare-secret-token"
	path := ts.URL + "/api/servers/" + a.ID + "/cloudflare"
	if code, _ := do(t, &http.Client{}, "GET", path, "", "", nil); code != 401 {
		t.Fatal("settings lack authentication")
	}
	if code, _ := do(t, client, "PUT", path, "", "", map[string]any{"api_token": secret}); code != 403 {
		t.Fatal("settings lack CSRF protection")
	}
	code, body := do(t, client, "PUT", path, "", csrf, map[string]any{"api_token": secret, "zone_ids": []string{zone}})
	if code != 200 || strings.Contains(string(body), secret) {
		t.Fatalf("settings leaked or failed: %d %s", code, body)
	}
	_, body = do(t, client, "GET", path, "", "", nil)
	if strings.Contains(string(body), secret) || !strings.Contains(string(body), zone) {
		t.Fatalf("unsafe settings: %s", body)
	}
	_, _ = do(t, client, "PUT", path, "", csrf, map[string]any{"zone_ids": []string{zone}})
	if st.Setting("cloudflare.token."+a.ID) != secret {
		t.Fatal("blank update lost token")
	}
	calls := 0
	s.models.client = &http.Client{Transport: cloudflareTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.String() != cloudflare.Endpoint || r.Header.Get("Authorization") != "Bearer "+secret {
			t.Error("wrong provider endpoint or token")
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"data":{"viewer":{"zones":[{}]}}}`))}, nil
	})}
	q := map[string]any{"zone_id": zone, "ip": "192.0.2.1", "hours": 1}
	if code, _ := do(t, ts.Client(), "POST", ts.URL+cloudflare.HubPath, otherKey, "", q); code != 400 || calls != 0 {
		t.Fatal("another server queried this server's zone")
	}
	if code, _ := do(t, ts.Client(), "POST", ts.URL+cloudflare.HubPath, key, "", q); code != 200 || calls != 2 {
		t.Fatalf("authorized query: %d calls=%d", code, calls)
	}
	_, body = do(t, ts.Client(), "POST", ts.URL+cloudflare.HubPath, otherKey, "", map[string]any{})
	if strings.Contains(string(body), zone) || strings.Contains(string(body), secret) {
		t.Fatal("metadata leaked across servers")
	}
	_ = b
	if err := st.DeleteServer(a.ID); err != nil {
		t.Fatal(err)
	}
	if st.Setting("cloudflare.token."+a.ID) != "" {
		t.Fatal("deleted server retained Cloudflare credential")
	}
}

func TestCloudflareLookupBudgetAndRevocation(t *testing.T) {
	s, st, ts := newHub(t)
	a, token, _ := st.CreateServer("one", "test", time.Hour)
	_, key, _ := st.Enroll(token, "one", "test")
	zone := strings.Repeat("a", 32)
	_ = st.SetSetting("cloudflare.token."+a.ID, "synthetic-cloudflare-secret-token")
	_ = st.SetSetting("cloudflare.zones."+a.ID, zone)
	s.models.client = &http.Client{Transport: cloudflareTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"data":{"viewer":{"zones":[{}]}}}`))}, nil
	})}
	for i := 0; i < 11; i++ {
		code, _ := do(t, ts.Client(), "POST", ts.URL+cloudflare.HubPath, key, "", map[string]any{"ip": "192.0.2.1"})
		want := 200
		if i == 10 {
			want = 429
		}
		if code != want {
			t.Fatalf("lookup %d: %d", i, code)
		}
	}
	_, _ = st.db.Exec(`UPDATE servers SET revoked=1 WHERE id=?`, a.ID)
	if code, _ := do(t, ts.Client(), "POST", ts.URL+cloudflare.HubPath, key, "", map[string]any{}); code != 401 {
		t.Fatal("revoked server retained access")
	}
}
