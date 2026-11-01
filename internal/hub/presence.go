package hub

// A kodeblue that stops syncing cannot report it: someone with root on the
// server stops it first, and a host that is down or cut off says nothing
// either. The hub notices the silence instead and posts it like any other
// notification, then posts again when the server comes back.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
)

// offlineAfter is how long without a sync makes a server offline (servers
// sync every 15 s). The console uses the same limit.
const offlineAfter = 2 * time.Minute

// stalledAfter is how long the heartbeat a syncing server reports may stay
// unchanged, at least. kodeblue writes it on every sweep and its watchdog
// restarts it 10 minutes past a missed one, so a server that keeps syncing
// with an unchanged heartbeat is not running its watch loop: syncs sent by
// something else with its key, such as root after stopping kodeblue. The hub
// times this on its own clock (Host.HeartbeatChanged), so a server's clock
// being off does not matter.
const stalledAfter = 20 * time.Minute

// stallLimit is stalledAfter, or longer for a server that sweeps rarely.
func stallLimit(st hubproto.Status) time.Duration {
	return max(stalledAfter, 2*time.Duration(st.SweepSeconds)*time.Second+10*time.Minute)
}

// hubNotePrefix marks notification ids the hub writes itself. Servers may
// not use it, so a server cannot store one first to suppress the hub's.
const hubNotePrefix = "hub:"

// PresenceWatcher checks every server's last sync until ctx ends.
func (s *Server) PresenceWatcher(ctx context.Context) {
	started := time.Now()
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if s.checkPresence(started, time.Now()) {
			s.wakeSlack()
		}
	}
}

// checkPresence posts a server going offline and coming back, once each,
// and reports whether it added a notification. A server is not counted
// silent for the time the hub itself was not running (started), so a hub
// restart does not report the whole fleet offline.
func (s *Server) checkPresence(started, now time.Time) bool {
	alerted := s.st.offlineAlerts()
	added := false
	for _, srv := range s.st.Servers() {
		if srv.Revoked || !srv.Enrolled || srv.LastSeen.IsZero() {
			continue
		}
		since := alerted[srv.ID]
		quiet := now.Sub(srv.LastSeen)
		switch {
		case since == 0 && now.Sub(later(srv.LastSeen, started)) >= offlineAfter:
			added = s.st.presenceNote(srv.ID, srv.LastSeen.Unix(), map[string]any{
				"kind": "server_offline", "severity": "high", "title": "kodeblue stopped reporting",
				"body": fmt.Sprintf("No sync from this server for %s. The host may be down or cut off, or kodeblue was stopped on it. "+
					"Stopping kodeblue is the first thing someone with root on the server would do, so check it if this was not planned.", span(quiet)),
				"fields": map[string]string{"Last sync": srv.LastSeen.UTC().Format("2006-01-02 15:04 UTC"), "Last address": srv.LastIP},
			}) || added
		case since != 0 && quiet < offlineAfter:
			added = s.st.presenceNote(srv.ID, 0, map[string]any{
				"kind": "server_online", "severity": "high", "title": "kodeblue is reporting again",
				"body": fmt.Sprintf("Back after %s without a sync. If nobody rebooted the server or restarted kodeblue, check journalctl -u kodeblue on it and its incidents for what happened in the gap.",
					span(now.Sub(time.Unix(since, 0)))),
				"fields": map[string]string{"Offline since": time.Unix(since, 0).UTC().Format("2006-01-02 15:04 UTC"), "Address": srv.LastIP},
			}) || added
		}
		var st hubproto.Status
		_ = json.Unmarshal(srv.Status, &st)
		if same := now.Sub(later(srv.HeartbeatChanged, started)); quiet < offlineAfter && st.Phase != "learning" && st.Heartbeat != "" &&
			!srv.HeartbeatChanged.IsZero() && same >= stallLimit(st) {
			every := "about a minute"
			if n := st.SweepSeconds; n > 0 && n < 120 {
				every = fmt.Sprintf("%d seconds", n)
			} else if n > 0 {
				every = span(time.Duration(n) * time.Second)
			}
			added = s.st.stallNote(srv.ID, srv.HeartbeatChanged.Unix(), map[string]any{
				"kind": "server_stalled", "severity": "high", "title": "kodeblue syncs, but its watch loop is not running",
				"body": fmt.Sprintf("This server keeps syncing, but the heartbeat it reports has not changed for %s. kodeblue writes it on every sweep (every %s here) and restarts itself when it stops, "+
					"so these syncs may not come from kodeblue: someone with root there can send them with its hub key after stopping it. Check the server, and revoke its key if in doubt.", span(same), every),
				"fields": map[string]string{"Heartbeat": st.Heartbeat, "Unchanged since": srv.HeartbeatChanged.UTC().Format("2006-01-02 15:04 UTC"), "Address": srv.LastIP},
			}) || added
		}
	}
	return added
}

// stallNote posts a stalled heartbeat once per stall (since: when the hub
// last saw the heartbeat change).
func (s *Store) stallNote(server string, since int64, note map[string]any) bool {
	tx, err := s.db.Begin()
	if err != nil {
		return false
	}
	defer tx.Rollback()
	added, err := addHubNotification(tx, server, fmt.Sprintf("%sstalled-%d", hubNotePrefix, since), note)
	return err == nil && tx.Commit() == nil && added
}

func later(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// span is a rough length of time for a notification: "3 minutes", "5 hours".
func span(d time.Duration) string {
	m := int(d.Round(time.Minute) / time.Minute)
	switch {
	case m <= 1:
		return "1 minute"
	case m < 120:
		return fmt.Sprintf("%d minutes", m)
	case m < 48*60:
		return fmt.Sprintf("%d hours", m/60)
	}
	return fmt.Sprintf("%d days", m/(24*60))
}

// offlineAlerts maps each server reported offline to the last sync before it.
func (s *Store) offlineAlerts() map[string]int64 {
	out := map[string]int64{}
	rows, err := s.db.Query(`SELECT id, offline_since FROM servers WHERE offline_since>0`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var at int64
		_ = rows.Scan(&id, &at)
		out[id] = at
	}
	return out
}

// presenceNote records a server going offline (since is its last sync) or
// coming back (since 0) together with the notification, so each change is
// posted exactly once, also across hub restarts.
func (s *Store) presenceNote(server string, since int64, note map[string]any) bool {
	tx, err := s.db.Begin()
	if err != nil {
		return false
	}
	defer tx.Rollback()
	var was int64
	if err := tx.QueryRow(`SELECT offline_since FROM servers WHERE id=?`, server).Scan(&was); err != nil || (was == 0) == (since == 0) {
		return false // already recorded, or the server is gone
	}
	rid := fmt.Sprintf("%soffline-%d", hubNotePrefix, since)
	if since == 0 {
		rid = fmt.Sprintf("%sonline-%d", hubNotePrefix, was)
	}
	added, err := addHubNotification(tx, server, rid, note)
	if err != nil {
		return false
	}
	if _, err := tx.Exec(`UPDATE servers SET offline_since=? WHERE id=?`, since, server); err != nil {
		return false
	}
	return tx.Commit() == nil && added
}

func addHubNotification(tx *sql.Tx, server, rid string, note map[string]any) (bool, error) {
	b, err := json.Marshal(note)
	if err != nil {
		return false, err
	}
	return addNotification(tx, server, hubproto.Record{Kind: "notification", ID: rid, UpdatedAt: time.Now(), Data: b})
}

func isHubNote(rid string) bool { return strings.HasPrefix(rid, hubNotePrefix) }
