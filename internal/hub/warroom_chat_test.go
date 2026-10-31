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
)

func nativeFixture(t *testing.T) *autoFixture {
	f := newAutoFixture(t)
	f.server.opt.Research = nil // Native conversations must work without analytics.
	if err := f.store.ApplySync(f.worker, &hubproto.SyncRequest{Status: hubproto.Status{SupportsWarRoom: true, SupportsInvestigator: true, AcceptsMessages: true, ModelsEnabled: true}, Records: []hubproto.Record{
		{Kind: "incident", ID: "51", UpdatedAt: f.now, Data: json.RawMessage(`{"id":51,"title":"Unexpected cache connection","kind":"incident","status":"needs_human","summary":"Unexplained outbound peer; inspect workload evidence","api_token":"never-return-this"}`)},
		{Kind: "finding", ID: "71", UpdatedAt: f.now, Data: json.RawMessage(`{"id":71,"title":"cache listener","detail":"Unexpected peer from the cache process","pid":149,"container":"cache","api_token":"never-return-this"}`)},
		{Kind: "service", ID: "cache", UpdatedAt: f.now.Add(-48 * time.Hour), Data: json.RawMessage(`{"name":"cache","container":"cache","port":6379,"status":"running"}`)},
	}}); err != nil {
		t.Fatal(err)
	}
	return f
}
func nativeStart(t *testing.T, f *autoFixture) researchCouncil {
	t.Helper()
	code, b := do(t, f.client, "POST", f.http.URL+"/api/warroom/conversations", "", f.csrf, map[string]any{"lead": f.worker, "participants": []map[string]string{{"server_id": f.worker, "role": "responder"}, {"server_id": f.worker, "role": "reviewer"}}, "case": map[string]string{"server_id": f.worker, "id": "51"}, "question": "Assess this cache service case, including benign alternatives."})
	if code != 200 {
		t.Fatalf("native start %d %s", code, b)
	}
	var room researchCouncil
	_ = json.Unmarshal(b, &room)
	return room
}
func TestNativeWarRoomNeedsNoWebsiteAndUsesScopedInfrastructureEvidence(t *testing.T) {
	f := nativeFixture(t)
	ctx := context.Background()
	const key = "kbk_native_fixture_key"
	_, _ = f.store.db.Exec("UPDATE servers SET key_hash=? WHERE id=?", Hash(key), f.worker)
	room := nativeStart(t, f)
	if !room.Native || room.Anchor == nil || room.Anchor.ID != "51" || len(room.Servers) != 1 || room.Participants[0].Role != "responder" {
		t.Fatalf("lost native context: %+v", room)
	}
	f.server.researchCouncilTick(ctx)
	room = councilRoom(t, f, room.ID)
	code, b := do(t, &http.Client{}, "GET", f.http.URL+hubproto.PathMessages+"?wait=0", key, "", nil)
	var delivery hubproto.MessagesResponse
	_ = json.Unmarshal(b, &delivery)
	if code != 200 || len(delivery.Messages) != 1 || delivery.Messages[0].CouncilRole != "investigator" {
		t.Fatalf("native delivery %d %s", code, b)
	}
	broker := fmt.Sprintf("%s%sresearch-job/%d", f.http.URL, hubproto.PathPrefix, room.Inflight)
	code, b = do(t, &http.Client{}, "POST", broker, key, "", map[string]any{"view": "overview"})
	if code != 200 || !strings.Contains(string(b), "KodeBlue infrastructure") || strings.Contains(string(b), "sensitive_requests") || strings.Contains(string(b), "enrollments") {
		t.Fatalf("analytics still required or private binding leaked: %d %s", code, b)
	}
	code, b = do(t, &http.Client{}, "POST", broker, key, "", map[string]any{"view": "sources"})
	if code != 200 || !strings.Contains(string(b), "Unexpected cache connection") || !strings.Contains(string(b), "6379") || !strings.Contains(string(b), "cache") || strings.Contains(string(b), "never-return-this") {
		t.Fatalf("native records failed: %d %s", code, b)
	}
	code, b = do(t, &http.Client{}, "POST", broker, key, "", map[string]any{"view": "traffic"})
	if code != 200 || !strings.Contains(string(b), "No traffic analytics configured") {
		t.Fatalf("optional data blocked core case %d %s", code, b)
	}
	councilReply(t, f, room.Inflight, "Opening: ask Responder about the workload and Reviewer about alternative explanations.")
	f.server.researchCouncilTick(ctx)
	f.server.researchCouncilTick(ctx)
	room = councilRoom(t, f, room.ID)
	code, b = do(t, &http.Client{}, "GET", f.http.URL+hubproto.PathMessages+"?wait=0", key, "", nil)
	_ = json.Unmarshal(b, &delivery)
	if code != 200 || len(delivery.Messages) != 1 || delivery.Messages[0].CouncilRole != "responder" {
		t.Fatalf("not the configured responder turn %d %s", code, b)
	}
}
func TestNativeWarRoomEnrollmentRotationWithdrawsTheCaseGrant(t *testing.T) {
	f := nativeFixture(t)
	ctx := context.Background()
	room := nativeStart(t, f)
	f.server.researchCouncilTick(ctx)
	room = councilRoom(t, f, room.ID)
	f.store.TakeQueued(f.worker)
	const replacement = "kbk_replacement_fixture"
	_, _ = f.store.db.Exec("UPDATE servers SET key_hash=? WHERE id=?", Hash(replacement), f.worker)
	code, b := do(t, &http.Client{}, "POST", fmt.Sprintf("%s%sresearch-job/%d", f.http.URL, hubproto.PathPrefix, room.Inflight), replacement, "", map[string]any{"view": "overview"})
	if code != 403 {
		t.Fatalf("new enrollment inherited previous grant: %d %s", code, b)
	}
	if _, err := f.server.councilSite(ctx, room); err == nil {
		t.Fatal("new enrollment inherited next turns")
	}
}
func TestNativeWarRoomAdmissionAndSummaryBoundaries(t *testing.T) {
	f := nativeFixture(t)
	url := f.http.URL + "/api/warroom/conversations"
	if code, _ := do(t, f.client, "POST", url, "", "", map[string]any{}); code != 403 {
		t.Fatal("missing CSRF accepted")
	}
	if code, _ := do(t, f.client, "POST", url, "", f.csrf, map[string]any{"lead": f.worker, "participants": []map[string]string{{"server_id": f.worker, "role": "root-shell"}}, "question": "test"}); code != 400 {
		t.Fatal("arbitrary role admitted")
	}
	if code, _ := do(t, f.client, "POST", url, "", f.csrf, map[string]any{"lead": f.worker, "case": map[string]string{"server_id": f.worker, "id": "999"}, "question": "test"}); code != 400 {
		t.Fatal("nonexistent case admitted")
	}
	room := nativeStart(t, f)
	code, b := do(t, f.client, "GET", url+"?server_id="+f.worker+"&case_id=51", "", "", nil)
	if code != 200 || !strings.Contains(string(b), room.ID) || strings.Contains(string(b), "enrollments") {
		t.Fatalf("native list %d %s", code, b)
	}
}

func TestNativeWarRoomOptionalCollectorFailureDoesNotBlockCoreCase(t *testing.T) {
	f := nativeFixture(t)
	f.server.opt.Research = f.research
	_ = f.research.Close()
	room := nativeStart(t, f)
	f.server.researchCouncilTick(context.Background())
	room = councilRoom(t, f, room.ID)
	if room.Status != "active" || room.Inflight == 0 {
		t.Fatalf("optional collector failure blocked native case: %+v", room)
	}
}

func TestTrafficCollectorDeletionCannotDeleteANativeDiscussion(t *testing.T) {
	f := nativeFixture(t)
	room := nativeStart(t, f)
	f.server.opt.Research = f.research
	site, err := f.research.Site(context.Background(), "website")
	if err != nil {
		t.Fatal(err)
	}
	site.ID = room.Site
	if err = f.research.PutSite(context.Background(), site); err != nil {
		t.Fatal(err)
	}
	code, b := do(t, f.client, "DELETE", f.http.URL+"/api/research/sites/"+site.ID, "", f.csrf, nil)
	if code != 200 {
		t.Fatalf("collector deletion %d %s", code, b)
	}
	if _, err = readCouncil(context.Background(), f.store.db, room.ID); err != nil {
		t.Fatal("optional collector deletion erased native investigation")
	}
}
