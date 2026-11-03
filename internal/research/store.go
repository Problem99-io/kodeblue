package research

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// Store deliberately uses its own database and short rollback-journal
// transactions. One third of MaxBytes is allocated to DB pages; the rest is
// reserved for rollback/maintenance headroom. No large VACUUM or disk sorts.
type Store struct {
	db     *sql.DB
	path   string
	limits Limits
	mu     sync.Mutex
}

func Open(dir string, limits Limits) (*Store, error) {
	if limits.MaxBytes < 3<<20 || limits.MaxEvents < 1 || limits.MaxSiteEvents < 1 || limits.MaxBuckets < 1 || limits.DetailTTL < time.Hour || limits.SummaryTTL < limits.DetailTTL {
		return nil, errors.New("invalid research limits")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "research.db")
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(DELETE)&_pragma=busy_timeout(1000)&_pragma=foreign_keys(1)&_pragma=temp_store(MEMORY)&_pragma=cache_size(-2048)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, path: path, limits: limits}
	failed := true
	defer func() {
		if failed {
			db.Close()
		}
	}()
	var mode string
	if err = db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil || mode != "delete" {
		return nil, errors.New("research requires rollback journal mode")
	}
	if _, err = db.Exec("PRAGMA auto_vacuum=INCREMENTAL"); err != nil {
		return nil, err
	}
	var pageSize int64
	if err = db.QueryRow("PRAGMA page_size").Scan(&pageSize); err != nil {
		return nil, err
	}
	var pages int64
	if err = db.QueryRow("PRAGMA page_count").Scan(&pages); err != nil {
		return nil, err
	}
	maxPages := limits.MaxBytes / 3 / pageSize
	if pages > maxPages {
		return nil, ErrCapacity
	}
	if _, err = db.Exec(fmt.Sprintf("PRAGMA max_page_count=%d", maxPages)); err != nil {
		return nil, err
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS sites(id TEXT PRIMARY KEY,data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY,site TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,source TEXT NOT NULL,event_id TEXT NOT NULL,at INTEGER NOT NULL,ingested INTEGER NOT NULL,kind TEXT NOT NULL,data TEXT NOT NULL,UNIQUE(site,source,event_id));
CREATE INDEX IF NOT EXISTS events_site_seq ON events(site,seq);
CREATE INDEX IF NOT EXISTS events_ingested ON events(ingested);
CREATE INDEX IF NOT EXISTS events_evict ON events((source='browser') DESC,seq);
CREATE INDEX IF NOT EXISTS events_site_evict ON events(site,(source='browser') DESC,seq);
CREATE TABLE IF NOT EXISTS receipts(site TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,source TEXT NOT NULL,event_id TEXT NOT NULL,ingested INTEGER NOT NULL,PRIMARY KEY(site,source,event_id));
CREATE INDEX IF NOT EXISTS receipts_age ON receipts(ingested);
CREATE INDEX IF NOT EXISTS receipts_source ON receipts(source);
CREATE TABLE IF NOT EXISTS buckets(site TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,hour INTEGER NOT NULL,source TEXT NOT NULL,kind TEXT NOT NULL,category TEXT NOT NULL,status INTEGER NOT NULL,name TEXT NOT NULL,n INTEGER NOT NULL,PRIMARY KEY(site,hour,source,kind,category,status,name));
CREATE INDEX IF NOT EXISTS buckets_hour ON buckets(hour);
CREATE TABLE IF NOT EXISTS coverage(site TEXT PRIMARY KEY REFERENCES sites(id) ON DELETE CASCADE,evicted INTEGER NOT NULL DEFAULT 0,summary_evicted INTEGER NOT NULL DEFAULT 0,rejected INTEGER NOT NULL DEFAULT 0,accepted INTEGER NOT NULL DEFAULT 0,last_at INTEGER NOT NULL DEFAULT 0);`)
	if err != nil {
		return nil, err
	}
	if err = os.Chmod(path, 0600); err != nil {
		return nil, err
	}
	failed = false
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) PutSite(ctx context.Context, site Site) error {
	if !idPattern.MatchString(site.ID) || len(site.Name) > 100 || len(site.Servers) > 32 || len(site.Origins) > 8 || len(site.BrowserPaths) > 32 {
		return ErrInvalid
	}
	if _, err := time.LoadLocation(site.Timezone); err != nil {
		return ErrInvalid
	}
	site.Name = clean(site.Name, 100)
	if site.Name == "" {
		return ErrInvalid
	}
	for _, server := range site.Servers {
		if !idPattern.MatchString(server) {
			return ErrInvalid
		}
	}
	for _, origin := range site.Origins {
		if !validOrigin(origin) {
			return ErrInvalid
		}
	}
	for _, path := range site.BrowserPaths {
		normalized, err := NormalizePath(path)
		if err != nil || path == "" || len(path) > 100 || normalized != path {
			return ErrInvalid
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sites WHERE id<>?", site.ID).Scan(&n); err != nil {
		return err
	}
	if n >= 64 {
		return ErrCapacity
	}
	b, _ := json.Marshal(site)
	_, err := s.db.ExecContext(ctx, "INSERT INTO sites(id,data) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data", site.ID, string(b))
	return storageError(err)
}

func (s *Store) Site(ctx context.Context, id string) (Site, error) {
	var site Site
	var b string
	err := s.db.QueryRowContext(ctx, "SELECT data FROM sites WHERE id=?", id).Scan(&b)
	if err == nil {
		err = json.Unmarshal([]byte(b), &site)
	}
	return site, err
}

func (s *Store) Sites(ctx context.Context) ([]Site, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT data FROM sites ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Site{}
	for rows.Next() {
		var b string
		var site Site
		if err = rows.Scan(&b); err != nil {
			return nil, err
		}
		if err = json.Unmarshal([]byte(b), &site); err != nil {
			return nil, err
		}
		out = append(out, site)
	}
	return out, rows.Err()
}

func (s *Store) DeleteSite(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.ExecContext(ctx, "DELETE FROM sites WHERE id=?", id)
	return err
}

type Receipt struct {
	Accepted      int  `json:"accepted"`
	Duplicates    int  `json:"duplicates"`
	DetailEvicted int  `json:"detail_evicted"`
	Stored        bool `json:"stored"`
}

// Ingest commits before returning a stored receipt. Browser source IDs are
// assigned by the HTTP adapter; agent sources are bound to enrolled credentials.
func (s *Store) Ingest(ctx context.Context, siteID, source string, browser bool, events []Event, now time.Time) (Receipt, error) {
	var result Receipt
	if len(events) == 0 || len(events) > 32 {
		return result, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	site, err := s.Site(ctx, siteID)
	if err != nil {
		return result, ErrScope
	}
	allowed := browser && site.BrowserEnabled && source == "browser"
	if !browser {
		for _, id := range site.Servers {
			allowed = allowed || source == id
		}
	}
	if !allowed {
		return result, ErrScope
	}
	for i := range events {
		events[i], err = validate(events[i], browser, now, s.limits.DetailTTL)
		if err != nil {
			_, _ = s.db.ExecContext(ctx, "INSERT INTO coverage(site,rejected) VALUES(?,1) ON CONFLICT(site) DO UPDATE SET rejected=rejected+1", siteID)
			return result, err
		}
		if browser {
			known := events[i].Path == "/"
			for _, path := range site.BrowserPaths {
				known = known || events[i].Path == path
			}
			if !known {
				events[i].Path = "/:other"
			}
		}
	}
	if bytes, _ := s.PhysicalBytes(); bytes > s.limits.MaxBytes/2 {
		return result, ErrCapacity
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	if err = s.pruneTx(ctx, tx, now); err != nil {
		return result, storageError(err)
	}
	var receipts int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM receipts").Scan(&receipts); err != nil {
		return result, err
	}
	var browserReceipts int
	if browser {
		if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM receipts WHERE source='browser'").Scan(&browserReceipts); err != nil {
			return result, err
		}
	}
	// Reject rather than discard recent idempotency keys and double-count retries.
	for _, e := range events {
		res, x := tx.ExecContext(ctx, "INSERT INTO receipts(site,source,event_id,ingested) VALUES(?,?,?,?) ON CONFLICT DO NOTHING", siteID, source, e.ID, now.Unix())
		if x != nil {
			return result, storageError(x)
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			result.Duplicates++
			continue
		}
		receipts++
		if receipts > s.limits.MaxEvents*4 {
			return result, ErrCapacity
		}
		if browser {
			browserReceipts++
			if browserReceipts > s.limits.MaxEvents*3 {
				return result, ErrCapacity
			}
		}
		b, _ := json.Marshal(e)
		_, err = tx.ExecContext(ctx, "INSERT INTO events(site,source,event_id,at,ingested,kind,data) VALUES(?,?,?,?,?,?,?)", siteID, source, e.ID, e.At.Unix(), now.Unix(), e.Kind, string(b))
		if err != nil {
			return result, storageError(err)
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO buckets(site,hour,source,kind,category,status,name,n) VALUES(?,?,?,?,?,?,?,1) ON CONFLICT(site,hour,source,kind,category,status,name) DO UPDATE SET n=n+1`, siteID, e.At.Truncate(15*time.Minute).Unix(), source, e.Kind, category(e.Path), e.Status/100, e.Name)
		if err != nil {
			return result, storageError(err)
		}
		result.Accepted++
	}
	lastAt := int64(0)
	if result.Accepted > 0 {
		lastAt = now.Unix()
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO coverage(site,accepted,last_at) VALUES(?,?,?) ON CONFLICT(site) DO UPDATE SET accepted=accepted+excluded.accepted,last_at=max(last_at,excluded.last_at)", siteID, result.Accepted, lastAt)
	if err != nil {
		return result, err
	}
	result.DetailEvicted, err = s.capEvents(ctx, tx, siteID)
	if err != nil {
		return result, err
	}
	if err = s.capGlobalEvents(ctx, tx); err != nil {
		return result, err
	}
	if err = s.capBuckets(ctx, tx); err != nil {
		return result, err
	}
	if err = tx.Commit(); err != nil {
		return result, storageError(err)
	}
	result.Stored = true
	return result, nil
}

func (s *Store) capEvents(ctx context.Context, tx *sql.Tx, site string) (int, error) {
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE site=?", site).Scan(&count); err != nil {
		return 0, err
	}
	if count <= s.limits.MaxSiteEvents {
		return 0, nil
	}
	n := count - s.limits.MaxSiteEvents
	if _, err := tx.ExecContext(ctx, "DELETE FROM events WHERE seq IN(SELECT seq FROM events WHERE site=? ORDER BY (source='browser') DESC,seq LIMIT ?)", site, n); err != nil {
		return 0, err
	}
	_, err := tx.ExecContext(ctx, "UPDATE coverage SET evicted=evicted+? WHERE site=?", n, site)
	return n, err
}

func (s *Store) capGlobalEvents(ctx context.Context, tx *sql.Tx) error {
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM events").Scan(&count); err != nil {
		return err
	}
	if count <= s.limits.MaxEvents {
		return nil
	}
	rows, err := tx.QueryContext(ctx, "SELECT site,COUNT(*) FROM (SELECT site FROM events ORDER BY (source='browser') DESC,seq LIMIT ?) GROUP BY site", count-s.limits.MaxEvents)
	if err != nil {
		return err
	}
	lost := map[string]int{}
	for rows.Next() {
		var site string
		var n int
		if err = rows.Scan(&site, &n); err != nil {
			rows.Close()
			return err
		}
		lost[site] = n
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM events WHERE seq IN (SELECT seq FROM events ORDER BY (source='browser') DESC,seq LIMIT ?)", count-s.limits.MaxEvents); err != nil {
		return err
	}
	for site, n := range lost {
		if _, err = tx.ExecContext(ctx, "UPDATE coverage SET evicted=evicted+? WHERE site=?", n, site); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) capBuckets(ctx context.Context, tx *sql.Tx) error {
	var n int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM buckets").Scan(&n); err != nil {
		return err
	}
	if n <= s.limits.MaxBuckets {
		return nil
	}
	// A fixed number of dimensions and a global cap prevent URL/UA cardinality bloat.
	rows, err := tx.QueryContext(ctx, "SELECT site,COUNT(*) FROM (SELECT site FROM buckets ORDER BY hour,site,source,kind,category,status,name LIMIT ?) GROUP BY site", n-s.limits.MaxBuckets)
	if err != nil {
		return err
	}
	lost := map[string]int{}
	for rows.Next() {
		var site string
		var c int
		if err = rows.Scan(&site, &c); err != nil {
			rows.Close()
			return err
		}
		lost[site] = c
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "DELETE FROM buckets WHERE rowid IN(SELECT rowid FROM buckets ORDER BY hour,site,source,kind,category,status,name LIMIT ?)", n-s.limits.MaxBuckets)
	if err != nil {
		return err
	}
	for site, c := range lost {
		if _, err = tx.ExecContext(ctx, "UPDATE coverage SET summary_evicted=summary_evicted+? WHERE site=?", c, site); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) pruneTx(ctx context.Context, tx *sql.Tx, now time.Time) error {
	for _, q := range []struct {
		sql string
		cut int64
	}{
		{"DELETE FROM events WHERE ingested<?", now.Add(-s.limits.DetailTTL).Unix()},
		{"DELETE FROM receipts WHERE ingested<?", now.Add(-s.limits.DetailTTL - 5*time.Minute).Unix()},
		{"DELETE FROM buckets WHERE hour<?", now.Add(-s.limits.SummaryTTL).Truncate(time.Hour).Unix()},
	} {
		if _, err := tx.ExecContext(ctx, q.sql, q.cut); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) Maintain(ctx context.Context, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = s.pruneTx(ctx, tx, now); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, "PRAGMA incremental_vacuum(128)")
	return err
}

func (s *Store) PhysicalBytes() (int64, error) {
	var total int64
	for _, suffix := range []string{"", "-journal", "-wal", "-shm"} {
		st, err := os.Stat(s.path + suffix)
		if err != nil && !os.IsNotExist(err) {
			return 0, err
		}
		if err == nil {
			total += st.Size()
		}
	}
	return total, nil
}

func storageError(err error) error {
	if err != nil && strings.Contains(err.Error(), "SQLITE_FULL") {
		return ErrCapacity
	}
	return err
}
