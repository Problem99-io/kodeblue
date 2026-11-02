package hub

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
	"github.com/Problem99-io/kodeblue/internal/blue/respond"
)

// A block one server made reaches every other server that takes shared
// blocks, once per version of the list: never back to the server that made
// it, never a private address, an undone block, a block that was itself
// shared, or a revoked server's; and nothing while operators turned sharing
// off.
func TestSharedBlocksRelayed(t *testing.T) {
	s, st, ts := newHub(t)
	c := ts.Client()
	enroll := func(name string) (string, string) {
		srv, tok, err := st.CreateServer(name, "test", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		code, body := do(t, c, "POST", ts.URL+hubproto.PathEnroll, "", "", hubproto.EnrollRequest{Token: tok})
		if code != 200 {
			t.Fatalf("enroll %s: %d %s", name, code, body)
		}
		var er hubproto.EnrollResponse
		_ = json.Unmarshal(body, &er)
		return srv.ID, er.APIKey
	}
	webID, webKey := enroll("web-1")
	_, dbKey := enroll("db-1")
	oldID, oldKey := enroll("old-1")

	now := time.Now()
	action := func(id, ip, status, by string, at time.Time) hubproto.Record {
		rec := respond.Record{Request: respond.Request{ID: id, Action: "block_ip", Params: map[string]string{"ip": ip}, RequestedBy: by,
			Justification: "SSH brute force: 400 failed logins in 5 minutes"}, Status: status, DoneAt: at}
		b, _ := json.Marshal(rec)
		return hubproto.Record{Kind: "action", ID: id, UpdatedAt: now, Data: b}
	}
	sync := func(key, version string, accepts bool, recs ...hubproto.Record) *hubproto.SharedBlocks {
		t.Helper()
		req := hubproto.SyncRequest{Status: hubproto.Status{Name: "x", AcceptsSharedBlocks: accepts, SharedBlocksVersion: version}, Records: recs}
		code, body := do(t, c, "POST", ts.URL+hubproto.PathSync, key, "", req)
		if code != 200 {
			t.Fatalf("sync: %d %s", code, body)
		}
		var resp hubproto.SyncResponse
		_ = json.Unmarshal(body, &resp)
		return resp.SharedBlocks
	}
	sync(webKey, "", false,
		action("act_1", "203.0.113.7", "done", "agent", now.Add(-time.Hour)),
		action("act_2", "10.0.0.8", "done", "rule:cr-ssh", now.Add(-time.Hour)),
		action("act_3", "198.51.100.9", "undone", "agent", now.Add(-time.Hour)),
		action("act_4", "203.0.113.20", "done", "fleet", now.Add(-time.Hour)),
		action("act_5", "203.0.113.30", "done", "agent", now.Add(-10*24*time.Hour)),
		action("act_6", "::ffff:203.0.113.40", "done", "agent+hub:alice+operator", now.Add(-2*time.Hour)))
	sync(oldKey, "", false, action("act_1", "203.0.113.99", "done", "agent", now.Add(-time.Hour)))
	if err := st.Revoke(oldID); err != nil {
		t.Fatal(err)
	}

	got := sync(dbKey, "", true)
	if got == nil || len(got.Blocks) != 2 {
		t.Fatalf("db-1 got %+v", got)
	}
	if b := got.Blocks[0]; b.IP != "203.0.113.7" || b.Server != "web-1" || !strings.HasPrefix(b.ID, "sb_") || b.ID == "act_1" || !strings.Contains(b.Why, "brute force") {
		t.Fatalf("newest block: %+v", b)
	}
	if got.Blocks[1].IP != "203.0.113.40" {
		t.Fatalf("mapped address: %+v", got.Blocks[1])
	}
	if again := sync(dbKey, got.Version, true); again != nil {
		t.Fatalf("the same list sent again: %+v", again)
	}
	if mine := s.SharedBlocksFor(webID); len(mine.Blocks) != 0 {
		t.Fatalf("web-1 got its own blocks back: %+v", mine.Blocks)
	}
	if sb := sync(dbKey, "", false); sb != nil {
		t.Fatal("a server that does not take shared blocks got them")
	}

	// Turned off: the next list is empty, which withdraws what was shared.
	cl, csrf := signIn(t, st, ts)
	code, body := do(t, cl, "PUT", ts.URL+"/api/settings/shared-blocks", "", csrf, map[string]bool{"enabled": false})
	if code != 200 || !strings.Contains(string(body), `"enabled":false`) {
		t.Fatalf("turn off: %d %s", code, body)
	}
	if off := sync(dbKey, got.Version, true); off == nil || len(off.Blocks) != 0 || off.Version == got.Version {
		t.Fatalf("after turning sharing off: %+v", off)
	}
	code, body = do(t, cl, "PUT", ts.URL+"/api/settings/shared-blocks", "", csrf, map[string]bool{"enabled": true})
	if code != 200 || !strings.Contains(string(body), `"203.0.113.7"`) {
		t.Fatalf("turn on: %d %s", code, body)
	}
	found := false
	for _, a := range st.AuditLog(20) {
		found = found || (a.Action == "shared_blocks.off" && a.Actor == "alice")
	}
	if !found {
		t.Fatal("turning sharing off was not audited")
	}
	if code, _ := do(t, cl, "PUT", ts.URL+"/api/settings/shared-blocks", "", csrf, map[string]string{}); code != 400 {
		t.Fatalf("no value: %d", code)
	}
}

// The list is bounded, and one address blocked on two servers is shared
// once, under the first block (so its id stays the same).
func TestSharedBlocksBoundedAndDeduplicated(t *testing.T) {
	s, st, _ := newHub(t)
	now := time.Now()
	var ids []string
	for _, name := range []string{"a", "b", "c"} {
		srv, _, err := st.CreateServer(name, "test", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.db.Exec(`UPDATE servers SET key_hash=? WHERE id=?`, "k"+name, srv.ID); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, srv.ID)
	}
	var recs []hubproto.Record
	for i := range hubproto.MaxSharedBlocks + 20 {
		rec := respond.Record{Request: respond.Request{ID: fmt.Sprint("act_", i), Action: "block_ip", Params: map[string]string{"ip": fmt.Sprintf("203.0.%d.%d", i/250, i%250+1)}, RequestedBy: "agent"},
			Status: "done", DoneAt: now.Add(-time.Duration(i) * time.Minute)}
		b, _ := json.Marshal(rec)
		recs = append(recs, hubproto.Record{Kind: "action", ID: rec.ID, UpdatedAt: now, Data: b})
	}
	if err := st.ApplySync(ids[0], &hubproto.SyncRequest{Records: recs}); err != nil {
		t.Fatal(err)
	}
	// b blocked the newest of a's addresses later, and one of its own.
	later := respond.Record{Request: respond.Request{ID: "act_9", Action: "block_ip", Params: map[string]string{"ip": "203.0.0.1"}, RequestedBy: "agent"}, Status: "done", DoneAt: now.Add(time.Second)}
	own := respond.Record{Request: respond.Request{ID: "act_10", Action: "block_ip", Params: map[string]string{"ip": "192.0.2.50"}, RequestedBy: "agent"}, Status: "done", DoneAt: now}
	b1, _ := json.Marshal(later)
	b2, _ := json.Marshal(own)
	if err := st.ApplySync(ids[1], &hubproto.SyncRequest{Records: []hubproto.Record{{Kind: "action", ID: "act_9", UpdatedAt: now, Data: b1}, {Kind: "action", ID: "act_10", UpdatedAt: now, Data: b2}}}); err != nil {
		t.Fatal(err)
	}
	got := s.SharedBlocksFor(ids[2]).Blocks
	if len(got) != hubproto.MaxSharedBlocks {
		t.Fatalf("%d blocks, want %d", len(got), hubproto.MaxSharedBlocks)
	}
	seen := map[string]bool{}
	for _, b := range got {
		if seen[b.IP] {
			t.Fatalf("%s shared twice", b.IP)
		}
		seen[b.IP] = true
		if b.IP == "203.0.0.1" && (b.Server != "a" || b.ID != sharedBlockID(ids[0], "act_0")) {
			t.Fatalf("the address both blocked: %+v", b)
		}
	}
	if !seen["192.0.2.50"] {
		t.Fatal("b's own block is missing")
	}
}
