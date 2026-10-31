package hub

import (
	"encoding/json"
	"fmt"
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
	code, body := do(t, client, "PUT", path, "", csrf, map[string]any{"api_token": secret, "zone_ids": []string{zone}, "zone_labels": map[string]string{zone: "example.test"}})
	if code != 200 || strings.Contains(string(body), secret) {
		t.Fatalf("settings leaked or failed: %d %s", code, body)
	}
	_, body = do(t, client, "GET", path, "", "", nil)
	if strings.Contains(string(body), secret) || !strings.Contains(string(body), zone) || !strings.Contains(string(body), "example.test") {
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
	for i := 0; i < 6; i++ {
		code, _ := do(t, ts.Client(), "POST", ts.URL+cloudflare.HubPath, key, "", map[string]any{"ip": "192.0.2.1"})
		want := 200
		if i == 5 {
			want = 429
		}
		if code != want {
			t.Fatalf("lookup %d: %d", i, code)
		}
	}
	if err := st.Revoke(a.ID); err != nil {
		t.Fatal(err)
	}
	if st.cloudflareSettings(a.ID).Configured || st.Setting("cloudflare.token."+a.ID) != "" || len(st.cloudflareSettings(a.ID).Zones) != 0 {
		t.Fatal("revoked server retained credentials")
	}
	if code, _ := do(t, ts.Client(), "POST", ts.URL+cloudflare.HubPath, key, "", map[string]any{}); code != 401 {
		t.Fatal("revoked server retained access")
	}
}

func TestCloudflareBudgetsAreIndependentAndRefundTransient(t *testing.T) {
	s, st, ts := newHub(t)
	zone := strings.Repeat("a", 32)
	keys := []string{}
	for _, name := range []string{"one", "two"} {
		host, token, _ := st.CreateServer(name, "test", time.Hour)
		_, key, _ := st.Enroll(token, name, "test")
		keys = append(keys, key)
		_ = st.SetSetting("cloudflare.token."+host.ID, "synthetic-cloudflare-secret-token")
		_ = st.SetSetting("cloudflare.zones."+host.ID, zone)
	}
	status := 200
	s.models.client = &http.Client{Transport: cloudflareTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(`{"data":{"viewer":{"zones":[{}]}}}`))}, nil
	})}
	query := map[string]any{"ip": "192.0.2.1"}
	for i := 0; i < 5; i++ {
		if code, _ := do(t, ts.Client(), "POST", ts.URL+cloudflare.HubPath, keys[0], "", query); code != 200 {
			t.Fatalf("first server: %d", code)
		}
	}
	if code, _ := do(t, ts.Client(), "POST", ts.URL+cloudflare.HubPath, keys[0], "", query); code != 429 {
		t.Fatal("per-server limit missing")
	}
	if code, _ := do(t, ts.Client(), "POST", ts.URL+cloudflare.HubPath, keys[1], "", query); code != 200 {
		t.Fatalf("another server starved: %d", code)
	}
	for _, upstream := range []int{429, 503} {
		status = upstream
		for i := 0; i < 7; i++ {
			if code, _ := do(t, ts.Client(), "POST", ts.URL+cloudflare.HubPath, keys[1], "", query); code != 502 {
				t.Fatalf("transient reservation not refunded: upstream=%d hub=%d", upstream, code)
			}
		}
	}
	status = 200
	if code, _ := do(t, ts.Client(), "POST", ts.URL+cloudflare.HubPath, keys[1], "", query); code != 200 {
		t.Fatalf("server remained rate limited: %d", code)
	}
}

func TestCloudflarePartialDataKeepsBudgetAnd429RetainsGlobal(t *testing.T) {
	for _, status := range []int{429, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			s, st, ts := newHub(t)
			host, token, _ := st.CreateServer("host", "test", time.Hour)
			_, key, _ := st.Enroll(token, "host", "test")
			_ = st.SetSetting("cloudflare.token."+host.ID, "synthetic-cloudflare-secret-token")
			_ = st.SetSetting("cloudflare.zones."+host.ID, strings.Repeat("a", 32))
			calls := 0
			s.models.client = &http.Client{Transport: cloudflareTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				var request struct{ Query string }
				_ = json.NewDecoder(r.Body).Decode(&request)
				code := 200
				if strings.Contains(request.Query, "BotContext") {
					code = status
				}
				return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(`{"data":{"viewer":{"zones":[{}]}}}`))}, nil
			})}
			for i := 0; i < 40; i++ {
				code, _ := do(t, ts.Client(), "POST", ts.URL+cloudflare.HubPath, key, "", map[string]any{"ip": "192.0.2.1"})
				want := 429
				if i < 5 {
					want = 200
				}
				if code != want {
					t.Fatalf("lookup %d code=%d want=%d", i, code, want)
				}
			}
			if calls != 10 {
				t.Fatalf("partial responses bypassed budget: %d calls", calls)
			}
		})
	}
	s, st, ts := newHub(t)
	host, token, _ := st.CreateServer("rate", "test", time.Hour)
	_, key, _ := st.Enroll(token, "rate", "test")
	_ = st.SetSetting("cloudflare.token."+host.ID, "synthetic-cloudflare-secret-token")
	_ = st.SetSetting("cloudflare.zones."+host.ID, strings.Repeat("a", 32))
	calls := 0
	s.models.client = &http.Client{Transport: cloudflareTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 429, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	})}
	for i := 0; i < 40; i++ {
		code, _ := do(t, ts.Client(), "POST", ts.URL+cloudflare.HubPath, key, "", map[string]any{"ip": "192.0.2.1"})
		want := 429
		if i < 25 {
			want = 502
		}
		if code != want {
			t.Fatalf("rate-limit lookup %d code=%d", i, code)
		}
	}
	if calls != 25 {
		t.Fatalf("429 global budget bypassed: %d", calls)
	}
}
