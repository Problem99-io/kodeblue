package cloudflare

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"unicode/utf8"
)

const testZone = "0123456789abcdef0123456789abcdef"
const testToken = "synthetic-token-for-cloudflare-tests"
const eventsJSON = `{"data":{"viewer":{"zones":[{"firewallEventsAdaptive":[{"action":"managed_challenge","source":"botFight","clientIP":"192.0.2.1","clientAsn":"64500","userAgent":"<script>untrusted</script>"}]}]}}}`

type routeTransport func(*http.Request) (*http.Response, error)

func (f routeTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func tlsClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	u, _ := url.Parse(server.URL)
	client := server.Client()
	transport := client.Transport
	client.Transport = routeTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != Endpoint || r.Method != "POST" || r.Header.Get("Authorization") != "Bearer "+testToken {
			t.Error("unexpected Cloudflare endpoint, method or authentication")
		}
		r = r.Clone(r.Context())
		copyURL := *r.URL
		r.URL = &copyURL
		r.URL.Scheme = u.Scheme
		r.URL.Host = u.Host
		return transport.RoundTrip(r)
	})
	return &Client{Token: testToken, HTTP: client}
}

func TestLookupTLSFiltersAndOptionalBotData(t *testing.T) {
	calls := 0
	client := tlsClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		var q struct {
			Query     string
			Variables struct {
				Zone   string
				Filter map[string]any
			}
		}
		if json.NewDecoder(r.Body).Decode(&q) != nil || q.Variables.Zone != testZone || q.Variables.Filter["clientIP"] != "192.0.2.1" || q.Variables.Filter["datetime_geq"] == nil {
			t.Error("missing bounded IP/zone/time variables")
		}
		if strings.Contains(q.Query, "BotContext") {
			io.WriteString(w, `{"data":{"viewer":{"zones":[{"httpRequestsAdaptiveGroups":[{"count":4,"dimensions":{"botScore":0,"botManagementDecision":"notComputed"}}]}]}}}`)
		} else {
			io.WriteString(w, eventsJSON)
		}
	})
	result, err := client.Lookup(context.Background(), Query{IP: "192.0.2.1"}, []string{testZone})
	if err != nil || calls != 2 || len(result.Events) != 1 || len(result.Bots) != 1 || *result.Bots[0].Dimensions.BotScore != 0 {
		t.Fatalf("lookup: %+v %v calls=%d", result, err, calls)
	}
	if !strings.Contains(strings.Join(result.Notes, " "), "not computed") || result.Events[0].UserAgent != "<script>untrusted</script>" {
		t.Fatal("lost unknown-score semantics or host evidence")
	}
}

func TestUnavailableBotScoresKeepSecurityEvidence(t *testing.T) {
	client := tlsClient(t, func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		if strings.Contains(string(data), "BotContext") {
			w.WriteHeader(403)
			io.WriteString(w, testToken)
		} else {
			io.WriteString(w, eventsJSON)
		}
	})
	result, err := client.Lookup(context.Background(), Query{IP: "192.0.2.1"}, []string{testZone})
	if err != nil || len(result.Events) != 1 || len(result.Bots) != 0 || !strings.Contains(strings.Join(result.Notes, " "), "unavailable") {
		t.Fatalf("missing fallback: %+v %v", result, err)
	}
}

func TestLookupRejectsBadScopeAndInputBeforeHTTP(t *testing.T) {
	client := tlsClient(t, func(http.ResponseWriter, *http.Request) { t.Fatal("invalid query reached network") })
	for _, q := range []Query{{IP: "https://evil.example"}, {IP: "192.0.2.1", ZoneID: strings.Repeat("a", 32)}, {IP: "192.0.2.1", Hours: 25}} {
		if _, err := client.Lookup(context.Background(), q, []string{testZone}); err == nil {
			t.Fatalf("accepted %+v", q)
		}
	}
	result, err := client.Lookup(context.Background(), Query{}, []string{testZone})
	if err != nil || !result.Configured || len(result.Zones) != 1 {
		t.Fatalf("metadata: %+v %v", result, err)
	}
}

func TestProviderErrorsNeverExposeCredentials(t *testing.T) {
	for _, body := range []string{"not JSON " + testToken, `{"errors":[{"message":"` + testToken + `"}]}`, `{"data":{"viewer":{"zones":[]}}}`, strings.Repeat("x", (2<<20)+1)} {
		t.Run(body[:min(20, len(body))], func(t *testing.T) {
			client := tlsClient(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, body) })
			_, err := client.Lookup(context.Background(), Query{IP: "192.0.2.1"}, []string{testZone})
			if err == nil || strings.Contains(err.Error(), testToken) {
				t.Fatalf("unsafe error: %v", err)
			}
		})
	}
}

func TestCredentialEchoAndRedirectAreSafe(t *testing.T) {
	t.Run("escaped echo", func(t *testing.T) {
		client := tlsClient(t, func(w http.ResponseWriter, r *http.Request) {
			data, _ := io.ReadAll(r.Body)
			if strings.Contains(string(data), "BotContext") {
				w.WriteHeader(403)
				return
			}
			escaped := strings.ReplaceAll(testToken, "s", `\u0073`)
			io.WriteString(w, strings.ReplaceAll(eventsJSON, "<script>untrusted</script>", escaped))
		})
		result, err := client.Lookup(context.Background(), Query{IP: "192.0.2.1"}, []string{testZone})
		if err != nil || strings.Contains(result.Events[0].UserAgent, testToken) || !strings.Contains(result.Events[0].UserAgent, "redacted") {
			t.Fatalf("echo: %+v %v", result, err)
		}
	})
	t.Run("redirect", func(t *testing.T) {
		calls := 0
		client := tlsClient(t, func(w http.ResponseWriter, r *http.Request) {
			calls++
			http.Redirect(w, r, "https://elsewhere.invalid/token", http.StatusFound)
		})
		_, err := client.Lookup(context.Background(), Query{IP: "192.0.2.1"}, []string{testZone})
		if err == nil || calls != 1 {
			t.Fatalf("redirect followed: %d %v", calls, err)
		}
	})
}

func TestCloudflareBoundsStripInvisibleCharacters(t *testing.T) {
	input := "/etc/" + string(rune(0x200b)) + "passwd" + string(rune(0x202e)) + string(rune(0xe0001)) + "\n"
	if got := bound(input, 256); got != "/etc/passwd" {
		t.Fatalf("invisible data survived: %q", got)
	}
	if len([]rune(bound(strings.Repeat("a", 300), 256))) != 256 {
		t.Fatal("field cap missing")
	}
}

func TestRedactionAfterInvisibleNormalization(t *testing.T) {
	echoed := testToken[:10] + "\u200b" + testToken[10:]
	client := tlsClient(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, strings.ReplaceAll(eventsJSON, "<script>untrusted</script>", echoed))
	})
	result, err := client.Lookup(context.Background(), Query{IP: "192.0.2.1"}, []string{testZone})
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(result)
	if strings.Contains(string(data), testToken) || !strings.Contains(string(data), "[redacted]") {
		t.Fatalf("echoed credential not redacted: %s", data)
	}
	if got := bound("a\ufe0f\U000e0100\u2028\u2029b", 256); got != "ab" {
		t.Fatalf("invisible characters survived: %q", got)
	}
}

func TestSanitizeRedactsBeforeRuneTruncation(t *testing.T) {
	secret := "synthetic-server-token"
	text := strings.Replace(secret, "server", "ser\u200bver", 1) + strings.Repeat("界", 600)
	clean := Sanitize(text, secret, 512)
	if !utf8.ValidString(clean) || strings.Contains(clean, secret) || !strings.HasPrefix(clean, "[redacted]") || len([]rune(clean)) != 512 {
		t.Fatalf("unsafe normalized text: %q", clean)
	}
}
