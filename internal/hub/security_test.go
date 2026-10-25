package hub

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// signIn logs alice in on a fresh client and returns it with the CSRF token.
func signIn(t *testing.T, st *Store, ts *httptest.Server) (*http.Client, string) {
	t.Helper()
	_ = st.AddUser("alice", "correct horse battery")
	jar, _ := cookiejar.New(nil)
	c := ts.Client()
	c.Jar = jar
	code, b := do(t, c, "POST", ts.URL+"/api/login", "", "", map[string]string{"name": "alice", "password": "correct horse battery"})
	if code != 200 {
		t.Fatalf("login: %d %s", code, b)
	}
	var me struct {
		CSRF string `json:"csrf"`
	}
	_ = json.Unmarshal(b, &me)
	return c, me.CSRF
}

func TestSameOrigin(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		same bool
	}{
		{"https://api.example.com", "https://api.example.com/v2", true},
		{"https://api.example.com", "https://API.example.com:443/x", true},
		{"http://10.0.0.5:8000", "http://10.0.0.5:8000/gateway", true},
		{"https://api.example.com", "https://evil.example.net", false},
		{"https://api.example.com", "http://api.example.com", false},
		{"https://api.example.com", "https://api.example.com:8443", false},
		{"http://10.0.0.5:8000", "http://10.0.0.5:8001", false},
		{"https://api.example.com", "https://api.example.com.evil.net", false},
		{"", "", false},
	} {
		if got := sameOrigin(tc.a, tc.b); got != tc.same {
			t.Errorf("sameOrigin(%q, %q) = %v", tc.a, tc.b, got)
		}
	}
}

// A stored key is hidden from operators, so it must never follow a
// connection to a host an operator picks.
func TestConnectionKeyStaysWithItsHost(t *testing.T) {
	_, st, ts := newHub(t)
	c, csrf := signIn(t, st, ts)
	post := func(path string, body any) (int, []byte) { return do(t, c, "POST", ts.URL+path, "", csrf, body) }
	put := func(path string, body any) (int, []byte) { return do(t, c, "PUT", ts.URL+path, "", csrf, body) }
	if code, b := post("/api/settings/connections", map[string]any{"kind": "openai-compatible", "name": "Gateway", "base_url": "https://models.example.com", "api_key": "sk-secret"}); code != 200 {
		t.Fatalf("add: %d %s", code, b)
	}
	key := func() string { conn, _ := st.Connection("gateway"); return conn.APIKey }
	url := func() string { conn, _ := st.Connection("gateway"); return conn.BaseURL }

	for _, moved := range []string{"https://attacker.example.net", "http://models.example.com", "https://models.example.com:8443"} {
		code, b := put("/api/settings/connections/gateway", map[string]any{"name": "Gateway", "base_url": moved})
		if code != 400 || !strings.Contains(string(b), "API key again") {
			t.Fatalf("move to %s without a key: %d %s", moved, code, b)
		}
		if key() != "sk-secret" || url() != "https://models.example.com" {
			t.Fatalf("a refused move changed the connection: %q %q", url(), key())
		}
	}
	// A path change on the same host keeps the key.
	if code, b := put("/api/settings/connections/gateway", map[string]any{"name": "Gateway", "base_url": "https://models.example.com/gateway"}); code != 200 {
		t.Fatalf("path change: %d %s", code, b)
	}
	if key() != "sk-secret" || url() != "https://models.example.com/gateway" {
		t.Fatalf("after path change: %q %q", url(), key())
	}
	// A move with a new key, or with the key cleared, is fine.
	if code, b := put("/api/settings/connections/gateway", map[string]any{"name": "Gateway", "base_url": "https://other.example.com", "api_key": "sk-new"}); code != 200 || key() != "sk-new" {
		t.Fatalf("move with a new key: %d %s %q", code, b, key())
	}
	if code, b := put("/api/settings/connections/gateway", map[string]any{"name": "Gateway", "base_url": "https://third.example.com", "clear_key": true}); code != 200 || key() != "" {
		t.Fatalf("move clearing the key: %d %s %q", code, b, key())
	}

	var refused, moves int
	for _, e := range st.AuditLog(100) {
		switch {
		case e.Action == "settings.connection_edit_refused":
			refused++
		case e.Action == "settings.connection_edit" && strings.Contains(e.Detail, " -> "):
			moves++
		}
	}
	if refused != 3 || moves != 3 {
		t.Fatalf("audit: %d refused, %d URL changes logged", refused, moves)
	}
}

func TestLimiterReserveIsAtomic(t *testing.T) {
	l := newLimiter(8, time.Minute)
	var got atomic.Int32
	var wg sync.WaitGroup
	for range 200 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if l.Reserve("k") != nil {
				got.Add(1)
			}
		}()
	}
	wg.Wait()
	if got.Load() != 8 {
		t.Fatalf("%d of 200 concurrent reservations passed a limit of 8", got.Load())
	}
	// Refund gives an attempt back; refunding twice gives back one.
	l2 := newLimiter(2, time.Minute)
	r := l2.Reserve("a", "b")
	l2.Reserve("a")
	if l2.Reserve("a") != nil {
		t.Fatal("limit not reached")
	}
	r.Refund()
	r.Refund()
	if l2.Reserve("a") == nil || l2.Reserve("a") != nil {
		t.Fatal("refund did not free exactly one attempt")
	}
	// A reservation blocked on one key counts against none.
	if l2.Reserve("a", "c") != nil || len(l2.hits["c"]) != 0 {
		t.Fatal("a refused reservation was counted")
	}
}

func TestThrottleKey(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.7":            "203.0.113.7",
		"2001:db8:1:2:aaaa::1":   "2001:db8:1:2::/64",
		"2001:db8:1:2:bbbb::999": "2001:db8:1:2::/64",
		"::ffff:203.0.113.7":     "::ffff:203.0.113.7",
	} {
		if got := throttleKey(netip.MustParseAddr(in), "x"); got != want {
			t.Errorf("throttleKey(%s) = %s, want %s", in, got, want)
		}
	}
	if throttleKey(netip.Addr{}, "fallback") != "fallback" {
		t.Error("invalid address must use the fallback")
	}
}

// loginAs posts a sign-in, optionally as a client behind the trusted proxy.
func loginAs(t *testing.T, ts *httptest.Server, name, pw, xff string) int {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"name": name, "password": pw})
	req, _ := http.NewRequest("POST", ts.URL+"/api/login", strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Error(err)
		return 0
	}
	resp.Body.Close()
	return resp.StatusCode
}

// A burst of concurrent sign-ins gets no more password checks than the
// limit: the attempt is counted before the hash runs.
func TestConcurrentLoginsAreThrottled(t *testing.T) {
	s, st, ts := newHub(t)
	// One check slot per allowed attempt: on a small runner under -race the
	// default NumCPU/2 slots would answer some reserved attempts 503 (and
	// refund them), which is the bound working, not the throttle failing.
	s.hashCheck = make(chan struct{}, loginMaxPerAddr)
	_ = st.AddUser("alice", "correct horse battery")
	var mu sync.Mutex
	codes := map[int]int{}
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			code := loginAs(t, ts, "alice", "wrong password!!", "")
			mu.Lock()
			codes[code]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	if codes[401] != loginMaxPerAddr || codes[429] != 50-loginMaxPerAddr {
		t.Fatalf("50 concurrent bad sign-ins: %v (exactly %d may be checked)", codes, loginMaxPerAddr)
	}
	if code := loginAs(t, ts, "alice", "correct horse battery", ""); code != 429 {
		t.Fatalf("right password after the burst: %d", code)
	}
}

// Guesses spread over many addresses still stop at the per-user limit.
func TestLoginLimitPerUser(t *testing.T) {
	s, st, ts := newHubWith(t, func(o *Options) { o.BehindProxy = true })
	// Small limits: every checked guess is a full PBKDF2 run.
	s.login.max, s.loginUser.max = 2, 4
	_ = st.AddUser("alice", "correct horse battery")
	checked := 0
	for i := range s.loginUser.max + 3 {
		if code := loginAs(t, ts, "alice", "wrong password!!", fmt.Sprintf("198.51.100.%d", i+1)); code == 401 {
			checked++
		}
	}
	if checked != s.loginUser.max {
		t.Fatalf("%d guesses checked across addresses, want %d", checked, s.loginUser.max)
	}
	if code := loginAs(t, ts, "alice", "correct horse battery", "192.0.2.50"); code != 429 {
		t.Fatalf("per-user limit not applied from a new address: %d", code)
	}
	// Another user is unaffected; a success does not use up the budget.
	_ = st.AddUser("bob", "another long password")
	for range s.login.max + 2 {
		if code := loginAs(t, ts, "bob", "another long password", "192.0.2.60"); code != 200 {
			t.Fatalf("good sign-in for bob: %d", code)
		}
	}
}

// When every password check slot is busy, a sign-in waits briefly, then
// gets 503 without counting; the rest of the hub keeps answering.
func TestLoginHashWorkIsBounded(t *testing.T) {
	s, st, ts := newHub(t)
	_ = st.AddUser("alice", "correct horse battery")
	for range cap(s.hashCheck) {
		s.hashCheck <- struct{}{}
	}
	start := time.Now()
	if code, _ := do(t, ts.Client(), "GET", ts.URL+"/healthz", "", "", nil); code != 200 || time.Since(start) > time.Second {
		t.Fatalf("healthz while sign-ins are saturated: %d after %s", code, time.Since(start))
	}
	if code := loginAs(t, ts, "alice", "correct horse battery", ""); code != 503 {
		t.Fatalf("sign-in with no free slot: %d", code)
	}
	if len(s.login.hits) != 0 || len(s.loginUser.hits) != 0 {
		t.Fatal("a sign-in that never ran was counted")
	}
	for range cap(s.hashCheck) {
		<-s.hashCheck
	}
	if code := loginAs(t, ts, "alice", "correct horse battery", ""); code != 200 {
		t.Fatalf("sign-in after the slots freed: %d", code)
	}
}

func TestCSRFWrongTokenRefused(t *testing.T) {
	_, st, ts := newHub(t)
	c, csrf := signIn(t, st, ts)
	wrong := []byte(csrf)
	wrong[len(wrong)-1] ^= 1
	if code, _ := do(t, c, "POST", ts.URL+"/api/servers", "", string(wrong), map[string]string{"name": "x"}); code != 403 {
		t.Fatalf("one-bit-off CSRF token: %d", code)
	}
	if code, _ := do(t, c, "POST", ts.URL+"/api/servers", "", csrf+"x", map[string]string{"name": "x"}); code != 403 {
		t.Fatalf("longer CSRF token: %d", code)
	}
}

func TestEndpointAddrPolicy(t *testing.T) {
	for _, a := range []string{"127.0.0.1", "127.8.9.10", "::1", "169.254.169.254", "169.254.0.1", "fe80::1", "fd00:ec2::254",
		"0.0.0.0", "::", "::ffff:127.0.0.1", "::ffff:169.254.169.254", "64:ff9b::a9fe:a9fe", "100.100.100.200", "224.0.0.1"} {
		if endpointAddrErr(netip.MustParseAddr(a), nil) == nil {
			t.Errorf("%s allowed", a)
		}
	}
	// Private LANs are where self-hosted gateways live.
	for _, a := range []string{"10.0.0.5", "172.16.3.4", "192.168.1.20", "100.64.1.2", "fd12:3456::1", "8.8.8.8", "2001:db8::1"} {
		if err := endpointAddrErr(netip.MustParseAddr(a), nil); err != nil {
			t.Errorf("%s refused: %v", a, err)
		}
	}
	if endpointAddrErr(netip.MustParseAddr("127.0.0.1"), loopbackProxies) != nil {
		t.Error("--endpoint-allow did not allow loopback")
	}
}

// The hub's own model requests (connection test, catalog) must not reach
// its loopback or metadata addresses, and must not follow redirects away.
func TestModelFetchSSRF(t *testing.T) {
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{"data":[{"id":"m"}]}`))
	}))
	defer target.Close()

	_, st, ts := newHub(t)
	c, csrf := signIn(t, st, ts)
	post := func(path string, body any) (int, []byte) { return do(t, c, "POST", ts.URL+path, "", csrf, body) }
	for i, u := range []string{target.URL, "http://169.254.169.254", "http://[fd00:ec2::254]", "http://0.0.0.0:1"} {
		code, b := post("/api/settings/connections", map[string]any{"kind": "openai-compatible", "name": fmt.Sprintf("c%d", i), "base_url": u, "api_key": "sk-x"})
		if code != 200 {
			t.Fatalf("add %s: %d %s", u, code, b)
		}
		_, b = post(fmt.Sprintf("/api/settings/connections/c%d/test", i), nil)
		if !strings.Contains(string(b), `"ok":false`) || !strings.Contains(string(b), "the hub does not connect to") {
			t.Fatalf("test of %s: %s", u, b)
		}
	}
	_, b := do(t, c, "GET", ts.URL+"/api/settings/models", "", "", nil)
	if !strings.Contains(string(b), "loopback") {
		t.Fatalf("catalog: %s", b)
	}
	if hits.Load() != 0 {
		t.Fatalf("the loopback endpoint was reached %d times", hits.Load())
	}

	// Allowed explicitly, a redirect to another host is still refused, and
	// the key never goes there.
	var leaked atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			leaked.Add(1)
		}
		hits.Add(1)
	}))
	defer other.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/v1/models", http.StatusFound)
	}))
	defer redirector.Close()
	_, st2, ts2 := newHubWith(t, func(o *Options) { o.EndpointAllow = loopbackProxies })
	c2, csrf2 := signIn(t, st2, ts2)
	if code, b := do(t, c2, "POST", ts2.URL+"/api/settings/connections", "", csrf2, map[string]any{"kind": "openai-compatible", "name": "r", "base_url": redirector.URL, "api_key": "sk-x"}); code != 200 {
		t.Fatalf("add redirector: %d %s", code, b)
	}
	_, b = do(t, c2, "POST", ts2.URL+"/api/settings/connections/r/test", "", csrf2, nil)
	if !strings.Contains(string(b), "redirected to another host") || hits.Load() != 0 || leaked.Load() != 0 {
		t.Fatalf("redirect: %s (other host hit %d times)", b, hits.Load())
	}
}

// A webhook on the hub's own loopback is refused like a model endpoint: the
// test button must not become a way to read local services.
func TestSlackWebhookCannotReachLoopback(t *testing.T) {
	var hits atomic.Int32
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("local secret"))
	}))
	defer local.Close()
	_, st, ts := newHub(t)
	c, csrf := signIn(t, st, ts)
	if code, b := do(t, c, "PUT", ts.URL+"/api/settings/slack", "", csrf, map[string]any{"webhook_url": local.URL + "/x"}); code != 200 {
		t.Fatalf("put: %d %s", code, b)
	}
	_, b := do(t, c, "POST", ts.URL+"/api/settings/slack/test", "", csrf, map[string]any{})
	if !strings.Contains(string(b), "the hub does not connect to the loopback address") || strings.Contains(string(b), "local secret") || hits.Load() != 0 {
		t.Fatalf("loopback webhook: %s (hits %d)", b, hits.Load())
	}
}

// A browser the user signed in from before is exempt from the per-user
// limit, so guesses from elsewhere cannot lock that operator out.
func TestKnownDeviceSkipsUserLockout(t *testing.T) {
	s, st, ts := newHubWith(t, func(o *Options) { o.BehindProxy = true })
	s.loginUser.max = 3
	_ = st.AddUser("alice", "correct horse battery")
	post := func(c *http.Client, pw, xff string) int {
		t.Helper()
		b, _ := json.Marshal(map[string]string{"name": "alice", "password": pw})
		req, _ := http.NewRequest("POST", ts.URL+"/api/login", strings.NewReader(string(b)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", xff)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	// Separate clients: ts.Client() is one shared client.
	jar, _ := cookiejar.New(nil)
	laptop := &http.Client{Transport: ts.Client().Transport, Jar: jar}
	other := &http.Client{Transport: ts.Client().Transport}
	if code := post(laptop, "correct horse battery", "192.0.2.10"); code != 200 {
		t.Fatalf("first sign-in: %d", code)
	}
	// An attacker locks the name from several addresses.
	for i := range 4 {
		post(other, "wrong password!!", fmt.Sprintf("198.51.100.%d", i+1))
	}
	if code := post(other, "correct horse battery", "192.0.2.20"); code != 429 {
		t.Fatalf("new browser while the name is locked: %d", code)
	}
	if code := post(laptop, "correct horse battery", "192.0.2.30"); code != 200 {
		t.Fatalf("known browser while the name is locked: %d", code)
	}
	// With every shared check slot busy (a flood), the known browser still
	// gets its own slot; a new browser gets 503.
	for range cap(s.hashCheck) {
		s.hashCheck <- struct{}{}
	}
	if code := post(other, "correct horse battery", "192.0.2.40"); code != 503 && code != 429 {
		t.Fatalf("new browser during a flood: %d", code)
	}
	if code := post(laptop, "correct horse battery", "192.0.2.50"); code != 200 {
		t.Fatalf("known browser during a flood: %d", code)
	}
	for range cap(s.hashCheck) {
		<-s.hashCheck
	}
	// The cookie is bound to its user name and cannot be forged.
	if s.knownDevice(&http.Request{Header: http.Header{"Cookie": {s.deviceCookieName() + "=" + s.deviceToken("alice")}}}, "bob") {
		t.Fatal("alice's device cookie counted for bob")
	}
	if s.knownDevice(&http.Request{Header: http.Header{"Cookie": {s.deviceCookieName() + "=YWxpY2U.forged"}}}, "alice") {
		t.Fatal("forged device cookie accepted")
	}
	// The signing key survives a restart (it is in the database).
	s2 := NewServer(s.opt, st, s.log)
	if s2.deviceToken("alice") != s.deviceToken("alice") {
		t.Fatal("device key changed across restart")
	}
}

// An installer published after the hub started is picked up.
func TestDistPublishedAfterStart(t *testing.T) {
	s := distHub(t, nil)
	if s.dist().script != nil {
		t.Fatal("no installer yet")
	}
	_ = os.WriteFile(filepath.Join(s.opt.DistDir, "install.sh"), []byte(testInstaller), 0o644)
	if s.dist().script == nil {
		t.Fatal("installer published after start not served")
	}
}

// Every state-changing operator route needs the CSRF header, including
// routes added later: the list is read from this package's source.
func TestEveryOperatorWriteNeedsCSRF(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	re := regexp.MustCompile(`HandleFunc\("(POST|PUT|PATCH|DELETE) (/api/[^"]+)"`)
	var routes [][2]string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, _ := os.ReadFile(f)
		for _, m := range re.FindAllStringSubmatch(string(b), -1) {
			if m[2] != "/api/login" {
				routes = append(routes, [2]string{m[1], regexp.MustCompile(`\{[^}]+\}`).ReplaceAllString(m[2], "x")})
			}
		}
	}
	if len(routes) < 15 {
		t.Fatalf("found only %d operator write routes: %v", len(routes), routes)
	}
	_, st, ts := newHub(t)
	c, csrf := signIn(t, st, ts)
	for _, rt := range routes {
		if code, b := do(t, c, rt[0], ts.URL+rt[1], "", "", map[string]string{}); code != 403 {
			t.Errorf("%s %s without CSRF: %d %s", rt[0], rt[1], code, b)
		}
		if code, _ := do(t, c, rt[0], ts.URL+rt[1], "", csrf+"0", map[string]string{}); code != 403 {
			t.Errorf("%s %s with a wrong CSRF token: %d", rt[0], rt[1], code)
		}
	}
	// Including the vulnerability route that arrived with #25.
	if !slices.ContainsFunc(routes, func(r [2]string) bool { return strings.Contains(r[1], "/vulnerabilities/") }) {
		t.Fatal("vulnerability route not found")
	}
}
