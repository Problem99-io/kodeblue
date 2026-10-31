package hub

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
)

// The War room tests are independent of optional notification integrations.
type warTransport func(*http.Request) (*http.Response, error)

func (f warTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func warFinding(id, ip string, incident int64) hubproto.Record {
	data, _ := json.Marshal(map[string]any{"id": id, "title": "SSH login", "detail": "Authenticated connection from an unknown source", "severity": "high", "rule": "auth.new_login_source", "status": "incident", "incident_id": incident, "created_at": time.Now().Add(-time.Hour), "updated_at": time.Now(), "occurrences": 3, "evidence": map[string]string{"ip": ip, "user": "root", "time": time.Now().Add(-2 * time.Hour).Format(time.RFC3339)}})
	return hubproto.Record{Kind: "finding", ID: id, UpdatedAt: time.Now(), Data: data}
}

func TestWarSourceExtractionAndPublicAddresses(t *testing.T) {
	data := json.RawMessage(`{"evidence":{"ip":"::ffff:8.8.8.8","source_ip":"8.8.8.8:443","client_ip":"[2606:4700:4700::1111]:443","remote_ip":"https://evil.example/8.8.4.4","log_line":"1.1.1.1","destination_ip":"9.9.9.9"},"value":"{\"source_ip\":\"8.8.4.4\",\"destination_ip\":\"1.0.0.1\"}"}`)
	ips := findingSources(data)
	if len(ips) != 3 {
		t.Fatalf("wrong source fields: %v", ips)
	}
	for _, raw := range []string{"127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "192.0.2.1", "198.51.100.1", "203.0.113.1", "198.18.0.1", "255.255.255.255", "224.0.0.1", "::1", "fd00::1", "fe80::1", "2001:db8::1", "64:ff9b::a00:1", "4000::1", "2002:0a00:0001::", "3fff::1", "192.88.99.1"} {
		if publicSource(netip.MustParseAddr(raw)) {
			t.Errorf("non-public IP eligible for lookup: %s", raw)
		}
	}
	for _, raw := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"} {
		if !publicSource(netip.MustParseAddr(raw)) {
			t.Errorf("public IP rejected: %s", raw)
		}
	}
	if len(findingSources(json.RawMessage(`{"evidence":{"ip":"8.8.8.8, 1.1.1.1"}}`))) != 0 {
		t.Fatal("accepted spoofable list/header")
	}
}

func TestWarIndexLinksContextAndRetainsOnlyExistingFindings(t *testing.T) {
	_, st, _ := newHubWith(t, allowLoopback)
	a, _, _ := st.CreateServer("web-1", "test", time.Hour)
	b, _, _ := st.CreateServer("web-2", "test", time.Hour)
	incident := hubproto.Record{Kind: "incident", ID: "7", UpdatedAt: time.Now(), Data: json.RawMessage(`{"id":7,"title":"Suspected compromise","status":"investigating","summary":"Review the SSH session"}`)}
	req := &hubproto.SyncRequest{Records: []hubproto.Record{warFinding("1", "8.8.8.8", 7), warFinding("2", "10.1.2.3", 0), incident}}
	for i := 0; i < 2; i++ {
		if err := st.ApplySync(a.ID, req); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.ApplySync(b.ID, &hubproto.SyncRequest{Records: []hubproto.Record{warFinding("1", "1.1.1.1", 7)}}); err != nil {
		t.Fatal(err)
	}
	sources, truncated, err := st.warSources(time.Now().Add(-24*time.Hour), a.ID)
	if err != nil || truncated || len(sources) != 2 {
		t.Fatalf("sources=%+v truncated=%v err=%v", sources, truncated, err)
	}
	for _, src := range sources {
		if len(src.Events) != 1 {
			t.Fatalf("duplicate findings: %+v", src)
		}
		e := src.Events[0]
		if e.ServerName != "web-1" || e.Evidence["user"] != "root" || e.Occurrences != 3 {
			t.Fatalf("context missing: %+v", e)
		}
		if src.IP == "8.8.8.8" && (e.IncidentTitle != "Suspected compromise" || e.Context != "Review the SSH session" || src.Status != "pending") {
			t.Fatalf("incident join: %+v", src)
		}
		if src.IP == "10.1.2.3" && (src.Public || src.Status != "private") {
			t.Fatalf("private classification: %+v", src)
		}
	}
	other, _, err := st.warSources(time.Now().Add(-24*time.Hour), b.ID)
	if err != nil || len(other) != 1 || other[0].Events[0].IncidentTitle != "" {
		t.Fatalf("cross-server incident join: %+v %v", other, err)
	}
	// A finding update changes its source without leaving an old association.
	if err := st.ApplySync(a.ID, &hubproto.SyncRequest{Records: []hubproto.Record{warFinding("1", "8.8.4.4", 7)}}); err != nil {
		t.Fatal(err)
	}
	var count int
	_ = st.db.QueryRow(`SELECT COUNT(*) FROM war_events WHERE ip='8.8.8.8'`).Scan(&count)
	if count != 0 {
		t.Fatal("stale IP after finding update")
	}
	if _, err := st.db.Exec(`DELETE FROM records WHERE server_id=? AND kind='finding'`, a.ID); err != nil {
		t.Fatal(err)
	}
	sources, _, err = st.warSources(time.Time{}, a.ID)
	if err != nil || len(sources) != 0 {
		t.Fatalf("deleted finding still mapped: %+v %v", sources, err)
	}
	// Existing records can be indexed when upgrading an earlier hub.
	_, _ = st.db.Exec(`DELETE FROM war_events`)
	_ = st.SetSetting("war_index_v1", "")
	if err := st.backfillWarRoom(); err != nil {
		t.Fatal(err)
	}
	sources, _, err = st.warSources(time.Time{}, b.ID)
	if err != nil || len(sources) != 1 {
		t.Fatalf("backfill failed: %+v %v", sources, err)
	}
}

func TestWarLookupCacheQuotaAndPrivacy(t *testing.T) {
	srv, st, _ := newHubWith(t, allowLoopback)
	host, _, _ := st.CreateServer("web-1", "test", time.Hour)
	_ = st.SetSetting("war_enabled", "true")
	_ = st.SetSetting("war_api_key", "provider-secret")
	if err := st.ApplySync(host.ID, &hubproto.SyncRequest{Records: []hubproto.Record{warFinding("1", "8.8.8.8", 0), warFinding("2", "10.0.0.1", 0)}}); err != nil {
		t.Fatal(err)
	}
	calls := 0
	code := 200
	srv.models.client = &http.Client{Transport: warTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.String() != "https://api.ipapi.is/" || r.Method != "POST" {
			t.Fatalf("unsafe lookup destination: %s", r.URL)
		}
		var body map[string]string
		if json.NewDecoder(r.Body).Decode(&body) != nil || body["q"] != "8.8.8.8" || body["key"] != "provider-secret" || len(body) != 2 {
			t.Fatalf("lookup leaks event data: %+v", body)
		}
		return &http.Response{StatusCode: code, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"ip":"8.8.8.8","company":{"name":"Google","type":"business"},"asn":{"asn":15169,"org":"Google","type":"hosting"},"is_datacenter":true,"location":{"city":"Mountain View","country":"United States","latitude":37.4,"longitude":-122.1}}`))}, nil
	})}
	srv.enrichNext(context.Background())
	srv.enrichNext(context.Background())
	if calls != 1 {
		t.Fatalf("cache/private protection failed: calls=%d", calls)
	}
	sources, _, err := st.warSources(time.Time{}, host.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, src := range sources {
		if src.Public && (src.Status != "ready" || src.Intel.Provider != "Google" || src.Intel.Type != "hosting" || src.Intel.Latitude == nil) {
			t.Fatalf("missing enrichment: %+v", src)
		}
	}
	_, _ = st.db.Exec(`UPDATE war_sources SET next_try=0 WHERE public=1`)
	_ = st.SetSetting("war_enabled", "false")
	srv.enrichNext(context.Background())
	if calls != 1 {
		t.Fatal("disabled lookup still sent")
	}
	_ = st.SetSetting("war_enabled", "true")
	code = 429
	srv.enrichNext(context.Background())
	srv.enrichNext(context.Background())
	if calls != 2 || st.warSettings()["used_today"] != 2 || st.warSettings()["paused_until"] == "" {
		t.Fatalf("quota not honored: calls=%d settings=%v", calls, st.warSettings())
	}
	var raw string
	_ = st.db.QueryRow(`SELECT data FROM war_sources WHERE ip='8.8.8.8'`).Scan(&raw)
	if !strings.Contains(raw, "Google") {
		t.Fatal("transient outage erased cached location")
	}
}

func TestWarAnonymousAndHostileProviderResponses(t *testing.T) {
	srv, _, _ := newHubWith(t, allowLoopback)
	for _, tc := range []struct{ name, body, status string }{
		{"anonymous", `{"ip":"8.8.8.8","company":"Google","asn":"AS15169 Google","city":"Mountain View","country":"United States","lat":37.4,"lon":-122.1}`, "ready"},
		{"no coordinates", `{"ip":"8.8.8.8","company":null,"asn":null,"lat":null,"lon":null}`, "unlocated"},
		{"bad coordinates", `{"ip":"8.8.8.8","lat":999,"lon":3}`, "unlocated"},
		{"malformed", `<script>provider-secret</script>`, "error"},
		{"wrong IP", `{"ip":"1.1.1.1","lat":2,"lon":3}`, "error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv.models.client = &http.Client{Transport: warTransport(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			})}
			intel, status, _, err := srv.lookupSource(context.Background(), "8.8.8.8")
			if tc.status == "error" {
				if err == nil || strings.Contains(err.Error(), "provider-secret") {
					t.Fatalf("unsafe/missing error: %v", err)
				}
			} else if err != nil || status != tc.status {
				t.Fatalf("intel=%+v status=%s err=%v", intel, status, err)
			}
			if tc.name == "anonymous" && intel.Type != "unknown" {
				t.Fatal("invented anonymous network classification")
			}
		})
	}
}

func TestWarRoomAccessAndSettings(t *testing.T) {
	_, st, ts := newHubWith(t, allowLoopback)
	if code, _ := do(t, ts.Client(), "GET", ts.URL+"/api/war-room", "", "", nil); code != 401 {
		t.Fatalf("anonymous map access: %d", code)
	}
	_ = st.AddUser("alice", "correct horse battery")
	jar, _ := cookiejar.New(nil)
	c := ts.Client()
	c.Jar = jar
	_, body := do(t, c, "POST", ts.URL+"/api/login", "", "", map[string]string{"name": "alice", "password": "correct horse battery"})
	var auth struct {
		CSRF string `json:"csrf"`
	}
	_ = json.Unmarshal(body, &auth)
	if code, _ := do(t, c, "PUT", ts.URL+"/api/settings/war-room", "", "", map[string]any{"api_key": "secret"}); code != 403 {
		t.Fatalf("settings missing CSRF: %d", code)
	}
	if code, body := do(t, c, "PUT", ts.URL+"/api/settings/war-room", "", auth.CSRF, map[string]any{"api_key": "provider-secret", "enabled": false}); code != 200 || strings.Contains(string(body), "provider-secret") || st.Setting("war_enabled") != "false" {
		t.Fatalf("settings: %d %s", code, body)
	}
	_, body = do(t, c, "GET", ts.URL+"/api/settings/war-room", "", "", nil)
	if strings.Contains(string(body), "provider-secret") {
		t.Fatal("API key disclosed")
	}
	if code, _ := do(t, c, "GET", ts.URL+"/api/war-room?hours=9999", "", "", nil); code != 400 {
		t.Fatalf("unbounded time range: %d", code)
	}
	if code, body := do(t, c, "GET", ts.URL+"/api/war-room?hours=24", "", "", nil); code != 200 || !strings.Contains(string(body), `"sources":[]`) {
		t.Fatalf("empty map: %d %s", code, body)
	}
}

func TestWarOptInAndPinOff(t *testing.T) {
	srv, st, _ := newHubWith(t, allowLoopback)
	if st.warSettings()["enabled"] != false {
		t.Fatal("enrichment must default off")
	}
	host, _, _ := st.CreateServer("host", "test", time.Hour)
	_ = st.ApplySync(host.ID, &hubproto.SyncRequest{Records: []hubproto.Record{warFinding("1", "8.8.8.8", 0)}})
	srv.models.client = &http.Client{Transport: warTransport(func(r *http.Request) (*http.Response, error) { t.Fatal("unexpected external request"); return nil, nil })}
	srv.enrichNext(context.Background())
	_ = st.SetSetting("war_enabled", "true")
	srv.opt.DisableIPEnrichment = true
	srv.enrichNext(context.Background())
	if srv.warSettings()["enabled"] != false {
		t.Fatal("pin-off bypassed")
	}
}
func TestWarOverviewBoundsContext(t *testing.T) {
	_, st, _ := newHubWith(t, allowLoopback)
	host, _, _ := st.CreateServer("host", "test", time.Hour)
	f := warFinding("1", "8.8.8.8", 1)
	var data map[string]any
	_ = json.Unmarshal(f.Data, &data)
	data["detail"] = strings.Repeat("x", 4000)
	f.Data, _ = json.Marshal(data)
	_ = st.ApplySync(host.ID, &hubproto.SyncRequest{Records: []hubproto.Record{f, {Kind: "incident", ID: "1", UpdatedAt: time.Now(), Data: json.RawMessage(`{"summary":"sensitive full context"}`)}}})
	sources, _, err := st.warSourcesView(time.Time{}, host.ID, true)
	if err != nil || len(sources) != 1 || len(sources[0].Events[0].Detail) > 256 || sources[0].Events[0].Context != "" {
		t.Fatalf("unbounded overview: %+v %v", sources, err)
	}
}
func TestWarAnonymousOmitsKey(t *testing.T) {
	srv, _, _ := newHubWith(t, allowLoopback)
	srv.models.client = &http.Client{Transport: warTransport(func(r *http.Request) (*http.Response, error) {
		var payload map[string]string
		_ = json.NewDecoder(r.Body).Decode(&payload)
		if _, ok := payload["key"]; ok {
			t.Fatal("empty key was sent")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"ip":"8.8.8.8"}`))}, nil
	})}
	_, _, _, err := srv.lookupSource(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
}

func TestWarBackfillPlanUsesRowid(t *testing.T) {
	_, st, _ := newHubWith(t, allowLoopback)
	rows, err := st.db.Query(`EXPLAIN QUERY PLAN `+warBackfillQuery, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		plan += detail
	}
	if strings.Contains(plan, "TEMP B-TREE") || !strings.Contains(plan, "INTEGER PRIMARY KEY") {
		t.Fatalf("nonlinear backfill plan: %s", plan)
	}
}

func TestWarPinnedPutRejectsEnable(t *testing.T) {
	srv, st, ts := newHubWith(t, allowLoopback)
	srv.opt.DisableIPEnrichment = true
	client, csrf := signIn(t, st, ts)
	if code, _ := do(t, client, "PUT", ts.URL+"/api/settings/war-room", "", csrf, map[string]any{"enabled": true}); code != 403 {
		t.Fatalf("pin off bypassed: %d", code)
	}
	if st.Setting("war_enabled") == "true" {
		t.Fatal("pinned setting persisted enable")
	}
}
func TestWarWorkerConsentAndDisableCancellation(t *testing.T) {
	srv, st, _ := newHubWith(t, allowLoopback)
	host, _, _ := st.CreateServer("host", "test", time.Hour)
	_ = st.ApplySync(host.ID, &hubproto.SyncRequest{Records: []hubproto.Record{warFinding("1", "8.8.8.8", 0)}})
	started, canceled := make(chan struct{}, 1), make(chan struct{}, 1)
	var calls atomic.Int32
	srv.models.client = &http.Client{Transport: warTransport(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		started <- struct{}{}
		<-r.Context().Done()
		canceled <- struct{}{}
		return nil, r.Context().Err()
	})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv.StartWarRoom(ctx)
	srv.war.mu.Lock()
	running := srv.war.running
	srv.war.mu.Unlock()
	if running || calls.Load() != 0 {
		t.Fatal("worker started without consent")
	}
	_ = st.SetSetting("war_enabled", "true")
	srv.startWarEnrichment()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("consented worker did not start")
	}
	_ = st.SetSetting("war_enabled", "false")
	srv.startWarEnrichment()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("disable did not cancel in-flight lookup")
	}
	cancel()
	deadline := time.Now().Add(time.Second)
	for {
		srv.war.mu.Lock()
		running = srv.war.running
		srv.war.mu.Unlock()
		if !running {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("disabled worker did not stop")
		}
		time.Sleep(time.Millisecond)
	}
	srv.enrichNext(context.Background())
	if calls.Load() != 1 {
		t.Fatal("disabled worker made another lookup")
	}
}
func TestWarFailureBackoffAndUnlocatedCache(t *testing.T) {
	srv, st, _ := newHubWith(t, allowLoopback)
	host, _, _ := st.CreateServer("host", "test", time.Hour)
	_ = st.ApplySync(host.ID, &hubproto.SyncRequest{Records: []hubproto.Record{warFinding("1", "8.8.8.8", 0)}})
	_ = st.SetSetting("war_enabled", "true")
	calls, status := 0, 503
	srv.models.client = &http.Client{Transport: warTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(`{"ip":"8.8.8.8"}`))}, nil
	})}
	for i := 0; i < 3; i++ {
		before := time.Now()
		srv.enrichNext(context.Background())
		until, _ := strconv.ParseInt(st.Setting("war_pause_until"), 10, 64)
		delay := time.Unix(until, 0).Sub(before)
		want := time.Minute * time.Duration(1<<i)
		if delay < want-time.Second || delay > want+time.Second {
			t.Fatalf("failure %d pause %v want %v", i, delay, want)
		}
		srv.enrichNext(context.Background())
		if calls != i+1 {
			t.Fatal("pause ignored")
		}
		_ = st.SetSetting("war_pause_until", "0")
		_, _ = st.db.Exec(`UPDATE war_sources SET next_try=0`)
	}
	status = 200
	srv.enrichNext(context.Background())
	var next int64
	var state string
	_ = st.db.QueryRow(`SELECT status,next_try FROM war_sources WHERE ip='8.8.8.8'`).Scan(&state, &next)
	if state != "unlocated" || time.Until(time.Unix(next, 0)) < 7*24*time.Hour-time.Minute || st.Setting("war_failure_streak") != "0" {
		t.Fatalf("cache/backoff reset: %s %d", state, next)
	}
	srv.enrichNext(context.Background())
	if calls != 4 {
		t.Fatal("unlocated cache re-queried")
	}
}
func TestWarBackfillSerializesRetention(t *testing.T) {
	_, st, _ := newHubWith(t, allowLoopback)
	host, _, _ := st.CreateServer("host", "test", time.Hour)
	records := []hubproto.Record{}
	for i := 0; i < 600; i++ {
		r := warFinding(strconv.Itoa(i), "8.8.8.8", 0)
		r.UpdatedAt = time.Now().Add(-100 * 24 * time.Hour)
		records = append(records, r)
	}
	if err := st.ApplySync(host.ID, &hubproto.SyncRequest{Records: records}); err != nil {
		t.Fatal(err)
	}
	_, _ = st.db.Exec(`DELETE FROM war_events`)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := st.backfillWarRoom(); err != nil {
			t.Error(err)
		}
	}()
	go func() { defer wg.Done(); st.Prune(90 * 24 * time.Hour) }()
	wg.Wait()
	var n int
	_ = st.db.QueryRow(`SELECT COUNT(*) FROM war_events`).Scan(&n)
	if n != 0 {
		t.Fatalf("retained %d orphan associations", n)
	}
}
func TestWarOverviewShowsLoadOnlyForAdditionalContext(t *testing.T) {
	_, st, _ := newHubWith(t, allowLoopback)
	host, _, _ := st.CreateServer("host", "test", time.Hour)
	_ = st.ApplySync(host.ID, &hubproto.SyncRequest{Records: []hubproto.Record{warFinding("1", "8.8.8.8", 0)}})
	sources, _, err := st.warSourcesView(time.Time{}, host.ID, true)
	if err != nil || sources[0].Events[0].HasMore {
		t.Fatalf("empty expansion advertised: %+v %v", sources, err)
	}
}
