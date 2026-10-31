package hub

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
	"github.com/Problem99-io/kodeblue/internal/research"
)

func TestInvestigationGrantScopeLifecycleAndQueryBudget(t *testing.T) {
	researchStore, err := research.Open(t.TempDir(), research.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer researchStore.Close()
	_, st, ts := newHubWith(t, func(o *Options) { o.Research = researchStore })
	client, csrf := signIn(t, st, ts)
	makeSource := func(name string) (string, string) {
		srv, tok, e := st.CreateServer(name, "test", time.Hour)
		if e != nil {
			t.Fatal(e)
		}
		_, key, e := st.Enroll(tok, name, "test")
		if e != nil {
			t.Fatal(e)
		}
		if e = st.ApplySync(srv.ID, &hubproto.SyncRequest{Status: hubproto.Status{SupportsInvestigator: true, AcceptsMessages: true, ModelsEnabled: true}}); e != nil {
			t.Fatal(e)
		}
		return srv.ID, key
	}
	worker, key := makeSource("worker")
	linked, linkedKey := makeSource("linked")
	foreign, _ := makeSource("foreign")
	if err = st.ApplySync(linked, &hubproto.SyncRequest{Records: []hubproto.Record{{Kind: "incident", ID: "9", UpdatedAt: time.Now(), Data: json.RawMessage(`{"title":"linked evidence","summary":"bounded summary","api_token":"never-surface"}`)}}}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Now().UTC()
	if err = researchStore.PutSite(ctx, research.Site{ID: "website", Name: "website", Timezone: "UTC", Servers: []string{worker, linked}}); err != nil {
		t.Fatal(err)
	}
	if err = researchStore.PutSite(ctx, research.Site{ID: "other", Name: "other", Timezone: "UTC", Servers: []string{worker, foreign}}); err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{worker, linked} {
		_, err = researchStore.Ingest(ctx, "website", source, false, []research.Event{{ID: source, At: now, Kind: "request", Path: "/test", Method: "GET", Status: 200}}, now)
		if err != nil {
			t.Fatal(err)
		}
	}
	_, _ = researchStore.Ingest(ctx, "other", worker, false, []research.Event{{ID: "private-other-site", At: now, Kind: "request", Path: "/private-other-site", Method: "GET", Status: 200}}, now)
	url := ts.URL + "/api/research/sites/website/investigate"
	req := map[string]any{"server_id": worker, "date": now.Format("2006-01-02"), "question": "Compare source evidence"}
	if code, _ := do(t, client, "POST", url, "", "", req); code != 403 {
		t.Fatal("admission bypassed CSRF")
	}
	code, body := do(t, client, "POST", url, "", csrf, req)
	var job Message
	_ = json.Unmarshal(body, &job)
	if code != 200 || job.Command != hubproto.CommandInvestigate || job.ID <= 0 {
		t.Fatalf("job %d %s", code, body)
	}
	if code, _ = do(t, client, "POST", url, "", csrf, req); code != 409 {
		t.Fatal("parallel worker job accepted")
	}
	broker := ts.URL + hubproto.PathPrefix + fmt.Sprintf("research-job/%d", job.ID)
	query := map[string]any{"view": "evidence", "after": 0}
	if code, _ = do(t, &http.Client{}, "POST", broker, key, "", query); code != 403 {
		t.Fatal("queued job granted evidence before delivery")
	}
	if got := st.TakeQueued(worker); len(got) != 1 {
		t.Fatal(got)
	}
	if code, _ = do(t, &http.Client{}, "POST", broker, linkedKey, "", query); code != 403 {
		t.Fatal("linked source acquired assigned worker grant")
	}
	if code, _ = do(t, &http.Client{}, "POST", broker, "", "", query); code != 401 {
		t.Fatal("unauthenticated evidence")
	}
	_, _ = researchStore.Ingest(ctx, "website", worker, false, []research.Event{{ID: "after-admission", At: now, Kind: "request", Path: "/later", Method: "GET", Status: 200}}, now)
	code, body = do(t, &http.Client{}, "POST", broker, key, "", query)
	var page research.Page
	_ = json.Unmarshal(body, &page)
	if code != 200 || len(page.Observations) != 2 || strings.Contains(string(body), "private-other-site") || strings.Contains(string(body), "after-admission") {
		t.Fatalf("scope leak: %d %s", code, body)
	}
	code, body = do(t, &http.Client{}, "POST", broker, key, "", map[string]any{"view": "sources"})
	if code != 200 || !strings.Contains(string(body), "linked evidence") || strings.Contains(string(body), "never-surface") {
		t.Fatalf("source context: %d %s", code, body)
	}
	for i := 0; i < 22; i++ {
		if code, body = do(t, &http.Client{}, "POST", broker, key, "", map[string]any{"view": "overview"}); code != 200 {
			t.Fatalf("read %d: %d %s", i, code, body)
		}
	}
	if code, _ = do(t, &http.Client{}, "POST", broker, key, "", query); code != 429 {
		t.Fatal("query budget bypassed")
	}
	if err = st.Reply(worker, job.ID, hubproto.MessageReply{Status: "done", Text: "INCONCLUSIVE"}); err != nil {
		t.Fatal(err)
	}
	if code, _ = do(t, &http.Client{}, "POST", broker, key, "", query); code != 403 {
		t.Fatal("finished job retained evidence access")
	}
	code, body = do(t, client, "POST", url, "", csrf, req)
	_ = json.Unmarshal(body, &job)
	if code != 200 {
		t.Fatalf("second admission %s", body)
	}
	st.TakeQueued(worker)
	if err = researchStore.PutSite(ctx, research.Site{ID: "website", Name: "website", Timezone: "UTC", Servers: []string{linked}}); err != nil {
		t.Fatal(err)
	}
	broker = ts.URL + hubproto.PathPrefix + fmt.Sprintf("research-job/%d", job.ID)
	if code, _ = do(t, &http.Client{}, "POST", broker, key, "", query); code != 403 {
		t.Fatal("removed worker kept site grant")
	}
}

func TestInvestigationRejectsLegacyWorkersAndExpiredGrants(t *testing.T) {
	researchStore, err := research.Open(t.TempDir(), research.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer researchStore.Close()
	_, st, ts := newHubWith(t, func(o *Options) { o.Research = researchStore })
	client, csrf := signIn(t, st, ts)
	srv, tok, _ := st.CreateServer("legacy", "test", time.Hour)
	_, key, _ := st.Enroll(tok, "legacy", "test")
	_ = researchStore.PutSite(context.Background(), research.Site{ID: "website", Name: "website", Timezone: "UTC", Servers: []string{srv.ID}})
	req := map[string]any{"server_id": srv.ID, "date": time.Now().UTC().Format("2006-01-02"), "question": "daily report"}
	url := ts.URL + "/api/research/sites/website/investigate"
	if code, _ := do(t, client, "POST", url, "", csrf, req); code != 409 {
		t.Fatal("legacy worker admitted")
	}
	_ = st.ApplySync(srv.ID, &hubproto.SyncRequest{Status: hubproto.Status{SupportsInvestigator: true, AcceptsMessages: true, ModelsEnabled: true}})
	code, body := do(t, client, "POST", url, "", csrf, req)
	var job Message
	_ = json.Unmarshal(body, &job)
	if code != 200 {
		t.Fatalf("job %s", body)
	}
	st.TakeQueued(srv.ID)
	_, _ = st.db.Exec("UPDATE research_jobs SET expires=? WHERE message_id=?", time.Now().Add(-time.Second).Unix(), job.ID)
	if code, _ = do(t, &http.Client{}, "POST", ts.URL+hubproto.PathPrefix+fmt.Sprintf("research-job/%d", job.ID), key, "", map[string]any{"view": "overview"}); code != 403 {
		t.Fatal("expired grant accepted")
	}
}

func TestInvestigatorSettingsDoNotBreakLegacyAgentsOrShareUnusedKeys(t *testing.T) {
	_, st, _ := newHub(t)
	srv, tok, _ := st.CreateServer("mixed-version-worker", "test", time.Hour)
	_, _, _ = st.Enroll(tok, "worker", "test")
	if err := st.setConnections([]hubproto.Connection{{ID: "research", Kind: "openai-compatible", BaseURL: "https://model.example", APIKey: "synthetic-research-only"}}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetFleetAgentSettings(AgentSettings{Models: map[string]hubproto.ModelRef{hubproto.RoleDefault: {Model: "existing-default"}, hubproto.RoleInvestigator: {Connection: "research", Model: "research-model"}}, Instructions: map[string]string{hubproto.RoleInvestigator: "Research-only instruction", hubproto.RoleReviewer: "Keep reviewing"}}); err != nil {
		t.Fatal(err)
	}
	legacy := st.EffectiveSettings(srv.ID)
	if _, ok := legacy.Models[hubproto.RoleInvestigator]; ok || len(legacy.Connections) != 0 || legacy.Instructions[hubproto.RoleInvestigator] != "" || legacy.Models[hubproto.RoleDefault].Model != "existing-default" || legacy.Instructions[hubproto.RoleReviewer] != "Keep reviewing" {
		t.Fatalf("legacy settings %+v", legacy)
	}
	_ = st.ApplySync(srv.ID, &hubproto.SyncRequest{Status: hubproto.Status{SupportsInvestigator: true}})
	modern := st.EffectiveSettings(srv.ID)
	if modern.Models[hubproto.RoleInvestigator].Model != "research-model" || len(modern.Connections) != 1 || modern.Connections[0].APIKey != "synthetic-research-only" || modern.Instructions[hubproto.RoleInvestigator] == "" {
		t.Fatalf("new role not delivered %+v", modern)
	}
}
