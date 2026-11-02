package hub

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
)

func TestPresenceAlerts(t *testing.T) {
	srv, st, ts := newHubWith(t, allowLoopback)
	mock := &slackMock{}
	slack := httptest.NewServer(mock)
	defer slack.Close()
	_ = st.SetSetting(settingSlackWebhook, slack.URL)
	host, tok, _ := st.CreateServer("web-1", "test", time.Hour)
	_, body := do(t, ts.Client(), "POST", ts.URL+hubproto.PathEnroll, "", "", hubproto.EnrollRequest{Token: tok})
	var er hubproto.EnrollResponse
	_ = json.Unmarshal(body, &er)
	syncNow := func(recs ...hubproto.Record) {
		t.Helper()
		if code, b := do(t, ts.Client(), "POST", ts.URL+hubproto.PathSync, er.APIKey, "", hubproto.SyncRequest{Records: recs}); code != 200 {
			t.Fatalf("sync: %d %s", code, b)
		}
	}
	syncNow()
	seen := st.GetServer(host.ID).LastSeen
	longAgo := seen.Add(-time.Hour)

	// A server cannot store the hub's notification first to suppress it.
	forged := note(fmt.Sprintf("%soffline-%d", hubNotePrefix, seen.Unix()), "info", "all fine")
	syncNow(forged)
	if n := st.Notifications(host.ID, 10); len(n) != 0 {
		t.Fatalf("a server stored a hub notification id: %+v", n)
	}
	seen = st.GetServer(host.ID).LastSeen

	// Silence shorter than the limit, or while the hub itself was down, is not offline.
	if srv.checkPresence(longAgo, seen.Add(offlineAfter-time.Second)) {
		t.Fatal("offline before the limit")
	}
	if srv.checkPresence(seen.Add(time.Hour), seen.Add(time.Hour+time.Minute)) {
		t.Fatal("a hub restart reported a server offline at once")
	}

	// Offline is posted once.
	if !srv.checkPresence(longAgo, seen.Add(3*time.Minute)) {
		t.Fatal("no offline notification")
	}
	if srv.checkPresence(longAgo, seen.Add(10*time.Minute)) {
		t.Fatal("offline posted twice")
	}
	srv.forwardDue(context.Background())
	if mock.count() != 1 || !strings.Contains(mock.posts[0], "stopped reporting") || !strings.Contains(mock.posts[0], "[web-1]") {
		t.Fatalf("posts %v", mock.posts)
	}

	// It survives a hub restart (the state is in the database) and the
	// return is posted once.
	srv2 := NewServer(srv.opt, st, srv.log)
	syncNow()
	if !srv2.checkPresence(longAgo, time.Now()) {
		t.Fatal("no back-online notification")
	}
	if srv2.checkPresence(longAgo, time.Now()) {
		t.Fatal("back online posted twice")
	}
	list := st.Notifications(host.ID, 10)
	if len(list) != 2 || list[0].Kind != "server_online" || list[1].Kind != "server_offline" || list[1].Severity != "high" {
		t.Fatalf("notifications %+v", list)
	}

	// A revoked server is not watched.
	_ = st.Revoke(host.ID)
	if srv.checkPresence(longAgo, time.Now().Add(time.Hour)) {
		t.Fatal("revoked server reported offline")
	}
}

func TestStalledHeartbeat(t *testing.T) {
	srv, st, ts := newHub(t)
	host, tok, _ := st.CreateServer("web-1", "test", time.Hour)
	_, body := do(t, ts.Client(), "POST", ts.URL+hubproto.PathEnroll, "", "", hubproto.EnrollRequest{Token: tok})
	var er hubproto.EnrollResponse
	_ = json.Unmarshal(body, &er)
	syncWith := func(phase string, hb time.Time, sweep int) {
		t.Helper()
		st := hubproto.Status{Phase: phase, Heartbeat: hb.UTC().Format(time.RFC3339), SweepSeconds: sweep}
		if code, b := do(t, ts.Client(), "POST", ts.URL+hubproto.PathSync, er.APIKey, "", hubproto.SyncRequest{Status: st}); code != 200 {
			t.Fatalf("sync: %d %s", code, b)
		}
	}
	// unchangedFor backdates when the hub saw the heartbeat change.
	unchangedFor := func(d time.Duration) {
		t.Helper()
		if _, err := st.db.Exec(`UPDATE servers SET hb_changed=? WHERE id=?`, time.Now().Add(-d).Unix(), host.ID); err != nil {
			t.Fatal(err)
		}
	}
	started := time.Now().Add(-2 * time.Hour)
	// The server's clock is an hour behind: what counts is that the
	// heartbeat changes, timed on the hub's clock.
	skewed := time.Now().Add(-time.Hour)
	syncWith("watching", skewed, 60)
	if srv.checkPresence(started, time.Now()) {
		t.Fatal("a heartbeat from a server with a slow clock was reported")
	}
	syncWith("watching", skewed.Add(time.Minute), 60)
	unchangedFor(10 * time.Minute)
	if srv.checkPresence(started, time.Now()) {
		t.Fatal("reported within the limit")
	}
	// Learning sweeps can take long: no alert.
	unchangedFor(time.Hour)
	syncWith("learning", skewed.Add(time.Minute), 60)
	if srv.checkPresence(started, time.Now()) {
		t.Fatal("reported while learning")
	}
	// A server that sweeps every 30 minutes gets longer.
	syncWith("watching", skewed.Add(time.Minute), 1800)
	unchangedFor(40 * time.Minute)
	if srv.checkPresence(started, time.Now()) {
		t.Fatal("a server sweeping every 30 minutes reported after 40")
	}
	// Syncing with a heartbeat that stopped changing: reported once.
	syncWith("watching", skewed.Add(time.Minute), 60)
	unchangedFor(25 * time.Minute)
	if !srv.checkPresence(started, time.Now()) {
		t.Fatal("stalled heartbeat not reported")
	}
	syncWith("watching", skewed.Add(time.Minute), 60)
	if srv.checkPresence(started, time.Now()) {
		t.Fatal("stalled heartbeat reported twice")
	}
	// It changes again: no alert.
	syncWith("watching", skewed.Add(2*time.Minute), 60)
	if srv.checkPresence(started, time.Now()) {
		t.Fatal("reported after the heartbeat changed")
	}
	if n := st.Notifications(host.ID, 10); len(n) != 1 || n[0].Kind != "server_stalled" {
		t.Fatalf("notifications %+v", n)
	}
	// Not counted for the time the hub itself was not running.
	unchangedFor(time.Hour)
	if srv.checkPresence(time.Now().Add(-time.Minute), time.Now()) {
		t.Fatal("reported right after a hub start")
	}
}

func TestSpan(t *testing.T) {
	for d, want := range map[time.Duration]string{30 * time.Second: "1 minute", 3 * time.Minute: "3 minutes", 5 * time.Hour: "5 hours", 72 * time.Hour: "3 days"} {
		if got := span(d); got != want {
			t.Errorf("span(%v) = %q, want %q", d, got, want)
		}
	}
}
