package hub

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
	"github.com/Problem99-io/kodeblue/internal/research"
)

func startCouncil(t *testing.T, f *autoFixture, participants []string) researchCouncil {
	t.Helper()
	code, b := do(t, f.client, "POST", f.http.URL+"/api/research/sites/website/councils", "", f.csrf, map[string]any{"lead": f.worker, "participants": participants, "date": f.now.Format("2006-01-02"), "question": "Which attack vectors are evidenced, and what remains unknown?"})
	if code != 200 {
		t.Fatalf("start %d %s", code, b)
	}
	var room researchCouncil
	if json.Unmarshal(b, &room) != nil {
		t.Fatal(string(b))
	}
	return room
}
func councilRoom(t *testing.T, f *autoFixture, id string) researchCouncil {
	t.Helper()
	room, err := readCouncil(context.Background(), f.store.db, id)
	if err != nil {
		t.Fatal(err)
	}
	return room
}
func councilReply(t *testing.T, f *autoFixture, id int64, text string) {
	t.Helper()
	jobs := f.store.messages("WHERE id=?", id)
	if len(jobs) != 1 {
		t.Fatal("missing job")
	}
	f.store.TakeQueued(jobs[0].ServerID)
	if err := f.store.Reply(jobs[0].ServerID, id, hubproto.MessageReply{Status: "done", Text: text}); err != nil {
		t.Fatal(err)
	}
}
func councilInput(t *testing.T, f *autoFixture, id string, body any) {
	t.Helper()
	code, b := do(t, f.client, "POST", f.http.URL+"/api/research/sites/website/councils/"+id, "", f.csrf, body)
	if code != 200 {
		t.Fatalf("input %d %s", code, b)
	}
}
func TestCouncilTurnsAreSerialDurableAndAdminMessagesReachNextTurn(t *testing.T) {
	f := newAutoFixture(t)
	ctx := context.Background()
	room := startCouncil(t, f, []string{f.worker})
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); f.server.researchCouncilTick(ctx) }()
	}
	wg.Wait()
	room = councilRoom(t, f, room.ID)
	if room.Inflight == 0 || len(f.jobs()) != 1 {
		t.Fatalf("parallel admission %+v", room)
	}
	f.server.researchCouncilTick(ctx)
	if len(f.jobs()) != 1 {
		t.Fatal("talked while another turn ran")
	}
	councilInput(t, f, room.ID, map[string]any{"text": "Check whether maintenance explains the burst."})
	councilReply(t, f, room.Inflight, "Opening: distinguish maintenance from reconnaissance.")
	f.server.researchCouncilTick(ctx)
	f.server.researchCouncilTick(ctx)
	room = councilRoom(t, f, room.ID)
	if room.Phase != 1 || len(f.jobs()) != 2 {
		t.Fatal("source not next")
	}
	var raw string
	var sourceOnly bool
	if err := f.store.db.QueryRow("SELECT overview,source_only FROM research_jobs WHERE message_id=?", room.Inflight).Scan(&raw, &sourceOnly); err != nil {
		t.Fatal(err)
	}
	if !sourceOnly || !strings.Contains(raw, "maintenance explains") {
		t.Fatalf("next turn lost context: %s", raw)
	}
	councilReply(t, f, room.Inflight, `{"kind":"pass","note":"","evidence":[],"addresses":[]}`)
	f.server.researchCouncilTick(ctx)
	// A new Server instance shares only durable control state, not a memory queue.
	restarted := NewServer(f.server.opt, f.store, f.server.log)
	restarted.researchCouncilTick(ctx)
	room = councilRoom(t, f, room.ID)
	if room.Phase != 2 || room.Inflight == 0 {
		t.Fatal("conclusion did not resume")
	}
	councilInput(t, f, room.ID, map[string]any{"text": "Also distinguish an attempted probe from a compromise."})
	councilReply(t, f, room.Inflight, "Conclusion: no confirmed compromise; missing workload evidence.")
	restarted.researchCouncilTick(ctx)
	room = councilRoom(t, f, room.ID)
	if room.Round != 2 || room.Phase != 0 || room.Status != "active" {
		t.Fatalf("late admin message lost: %+v", room)
	}
	restarted.researchCouncilTick(ctx)
	room = councilRoom(t, f, room.ID)
	if err := f.store.db.QueryRow("SELECT overview FROM research_jobs WHERE message_id=?", room.Inflight).Scan(&raw); err != nil || !strings.Contains(raw, "attempted probe") {
		t.Fatal("follow-up not in context")
	}
}
func TestCouncilSourceOnlyEvidenceAndCitationGate(t *testing.T) {
	f := newAutoFixture(t)
	ctx := context.Background()
	srv, tok, err := f.store.CreateServer("other-source", "test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = f.store.Enroll(tok, "other", "test")
	if err != nil {
		t.Fatal(err)
	}
	_ = f.store.ApplySync(srv.ID, &hubproto.SyncRequest{Status: hubproto.Status{SupportsInvestigator: true, AcceptsMessages: true, ModelsEnabled: true}})
	_ = f.research.PutSite(ctx, research.Site{ID: "website", Name: "Website", Timezone: "UTC", Servers: []string{f.worker, srv.ID}, BrowserEnabled: true, Origins: []string{"https://example.com"}})
	for _, source := range []string{f.worker, srv.ID, "browser"} {
		_, err = f.research.Ingest(ctx, "website", source, source == "browser", []research.Event{{ID: source, At: f.now, Kind: map[bool]string{true: "pageview", false: "request"}[source == "browser"], Path: "/"}}, f.now)
		if err != nil {
			t.Fatal(err)
		}
	}
	const key = "kbk_test-council-source-key"
	_, _ = f.store.db.Exec("UPDATE servers SET key_hash=? WHERE id=?", Hash(key), f.worker)
	room := startCouncil(t, f, []string{f.worker})
	f.server.researchCouncilTick(ctx)
	room = councilRoom(t, f, room.ID)
	councilReply(t, f, room.Inflight, "Opening: need source facts.")
	f.server.researchCouncilTick(ctx)
	f.server.researchCouncilTick(ctx)
	room = councilRoom(t, f, room.ID)
	pollCode, pollBody := do(t, &http.Client{}, "GET", f.http.URL+hubproto.PathMessages+"?wait=0", key, "", nil)
	var delivered hubproto.MessagesResponse
	_ = json.Unmarshal(pollBody, &delivered)
	if pollCode != 200 || len(delivered.Messages) != 1 || delivered.Messages[0].CouncilPhase != "source" {
		t.Fatalf("missing native phase: %d %s", pollCode, pollBody)
	}
	code, b := do(t, &http.Client{}, "POST", fmt.Sprintf("%s%sresearch-job/%d", f.http.URL, hubproto.PathPrefix, room.Inflight), key, "", map[string]any{"view": "evidence"})
	var page research.Page
	_ = json.Unmarshal(b, &page)
	if code != 200 || len(page.Observations) != 1 || page.Observations[0].Source != f.worker {
		t.Fatalf("source leaked: %d %s", code, b)
	}
	ref := fmt.Sprintf("event:%d", page.Observations[0].Sequence)
	councilReply(t, f, room.Inflight, fmt.Sprintf(`{"kind":"answer","note":"One received source request is recorded; no outcome is established.","evidence":[%q],"addresses":[2]}`, ref))
	f.server.researchCouncilTick(ctx)
	room = councilRoom(t, f, room.ID)
	last := room.Entries[len(room.Entries)-1]
	if last.Kind != "answer" || len(last.Evidence) != 1 {
		t.Fatalf("valid contribution rejected: %+v", last)
	}
	tx, err := f.store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	room.Inflight = last.Job
	if _, why := f.server.councilContribution(ctx, tx, room, `{"kind":"evidence","note":"invented","evidence":["event:999999"]}`); !strings.Contains(why, "not read") {
		t.Fatalf("invented citation accepted: %s", why)
	}
	repeated := fmt.Sprintf(`{"kind":"evidence","note":"same citations, new wording","evidence":[%q]}`, ref)
	if _, why := f.server.councilContribution(ctx, tx, room, repeated); !strings.Contains(why, "already contributed") {
		t.Fatalf("repeated evidence accepted: %s", why)
	}
	if _, why := f.server.councilContribution(ctx, tx, room, `{"kind":"pass"}`); !strings.Contains(why, "nothing new") {
		t.Fatal("PASS failed")
	}
}
func TestCouncilPauseEndCSRFAndScopeChange(t *testing.T) {
	f := newAutoFixture(t)
	ctx := context.Background()
	url := f.http.URL + "/api/research/sites/website/councils"
	if code, _ := do(t, f.client, "POST", url, "", "", map[string]any{}); code != 403 {
		t.Fatal("missing CSRF accepted")
	}
	room := startCouncil(t, f, nil)
	if code, _ := do(t, f.client, "POST", url, "", f.csrf, map[string]any{"lead": f.worker, "date": f.now.Format("2006-01-02"), "question": "another"}); code != 409 {
		t.Fatal("second active case accepted")
	}
	councilInput(t, f, room.ID, map[string]any{"action": "pause"})
	f.server.researchCouncilTick(ctx)
	if len(f.jobs()) != 0 {
		t.Fatal("paused case dispatched")
	}
	councilInput(t, f, room.ID, map[string]any{"action": "resume"})
	f.server.researchCouncilTick(ctx)
	room = councilRoom(t, f, room.ID)
	councilInput(t, f, room.ID, map[string]any{"action": "end"})
	f.server.researchCouncilTick(ctx)
	if jobs := f.jobs(); len(jobs) != 1 || jobs[0].Status != "refused" {
		t.Fatal("end did not withdraw queued job")
	}
	room = startCouncil(t, f, nil)
	site, _ := f.research.Site(ctx, "website")
	site.Timezone = "Asia/Jerusalem"
	_ = f.research.PutSite(ctx, site)
	f.server.researchCouncilTick(ctx)
	room = councilRoom(t, f, room.ID)
	if room.Status != "paused" || !strings.Contains(room.Error, "Scope changed") {
		t.Fatal("changed scope dispatched")
	}
}

func TestCouncilPauseDuringConclusionDoesNotRepeatTheConclusion(t *testing.T) {
	f := newAutoFixture(t)
	ctx := context.Background()
	room := startCouncil(t, f, nil)
	f.server.researchCouncilTick(ctx)
	room = councilRoom(t, f, room.ID)
	councilReply(t, f, room.Inflight, "Opening")
	f.server.researchCouncilTick(ctx)
	f.server.researchCouncilTick(ctx)
	room = councilRoom(t, f, room.ID)
	councilInput(t, f, room.ID, map[string]any{"action": "pause"})
	councilReply(t, f, room.Inflight, "Conclusion with explicit unknown vectors")
	f.server.researchCouncilTick(ctx)
	room = councilRoom(t, f, room.ID)
	if room.Status != "complete" {
		t.Fatalf("completed paused conclusion became resumable: %+v", room)
	}
	f.server.researchCouncilTick(ctx)
	if len(f.jobs()) != 2 {
		t.Fatal("conclusion was repeated")
	}
}

func TestCouncilBoundedChatCannotStrandAnOversizedModelReply(t *testing.T) {
	room := researchCouncil{}
	if err := room.add("admin", "admin", strings.Repeat("<", 1900), 0); err == nil {
		t.Fatal("oversized escaped admin text accepted")
	}
	if err := room.add("Investigator", "conclusion", strings.Repeat("<😀", 15000), 91); err != nil {
		t.Fatal(err)
	}
	entry := room.Entries[0]
	entry.Evidence = []string{strings.Repeat("a", 180), strings.Repeat("b", 180)}
	entry.Worker = "srv_fixture"
	boundCouncilEntry(&entry)
	data, err := json.Marshal(entry)
	if err != nil || len(data) > 2400 || !utf8.ValidString(entry.Text) || !strings.Contains(entry.Text, "[excerpt]") {
		t.Fatalf("unbounded or invalid chat entry: bytes=%d err=%v", len(data), err)
	}
}
func TestCouncilEndedDispatchedTurnFinishesWithoutReopening(t *testing.T) {
	f := newAutoFixture(t)
	ctx := context.Background()
	room := startCouncil(t, f, nil)
	f.server.researchCouncilTick(ctx)
	room = councilRoom(t, f, room.ID)
	f.store.TakeQueued(f.worker)
	councilInput(t, f, room.ID, map[string]any{"action": "end"})
	if err := f.store.Reply(f.worker, room.Inflight, hubproto.MessageReply{Status: "failed", Text: "Stopped by admin"}); err != nil {
		t.Fatal(err)
	}
	f.server.researchCouncilTick(ctx)
	room = councilRoom(t, f, room.ID)
	if room.Status != "ended" || room.Inflight != 0 || len(room.Entries) != 2 {
		t.Fatalf("ended room reopened or lost final gap: %+v", room)
	}
	f.server.researchCouncilTick(ctx)
	if len(f.jobs()) != 1 {
		t.Fatal("ended case admitted a new turn")
	}
}
