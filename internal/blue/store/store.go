// Package store is kodeblue's durable state: the learned baseline, findings,
// incidents, allow rules ("defs"), agent-authored monitors, and the token/cost
// ledger. It is SQLite in WAL mode because two processes write it: the daemon
// and the MCP tool server that the engine spawns for the agents.
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
	// pricing (USD per million input/output tokens) prices calls whose
	// endpoint reports no cost; unpriced is set when such a call had to be
	// recorded at $0.
	pricing  [2]float64
	unpriced atomic.Bool
}

// Open opens (and migrates) the store at path.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(wal)&_pragma=synchronous(normal)&_pragma=busy_timeout(10000)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	_ = os.Chmod(path, 0o600)
	keepOwner(path)
	return s, nil
}

// keepOwner: when root runs the CLI (sudo kodeblue ack …), SQLite may create
// the -wal/-shm files as root, which would lock the daemon out of its own
// database. Hand them to the database file's owner.
func keepOwner(path string) {
	if os.Geteuid() != 0 {
		return
	}
	st, err := os.Stat(path)
	if err != nil {
		return
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || sys.Uid == 0 {
		return
	}
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		_ = os.Chown(p, int(sys.Uid), int(sys.Gid))
	}
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS cloudflare_lookups (at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS cloudflare_lookups_at ON cloudflare_lookups(at);
CREATE TABLE IF NOT EXISTS cloudflare_budget (id INTEGER PRIMARY KEY CHECK(id=1), bucket INTEGER NOT NULL, n INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS baseline (
  id TEXT PRIMARY KEY, collector TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL DEFAULT '',
  attrs TEXT NOT NULL DEFAULT '{}', first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
  seen INTEGER NOT NULL DEFAULT 1, source TEXT NOT NULL DEFAULT 'learned', note TEXT NOT NULL DEFAULT '');
CREATE INDEX IF NOT EXISTS baseline_collector ON baseline(collector);
CREATE TABLE IF NOT EXISTS collector_runs (collector TEXT PRIMARY KEY, runs INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT, fingerprint TEXT NOT NULL, collector TEXT NOT NULL, rule TEXT NOT NULL,
  severity TEXT NOT NULL, title TEXT NOT NULL, detail TEXT NOT NULL, evidence TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'new', verdict TEXT NOT NULL DEFAULT '', verdict_reason TEXT NOT NULL DEFAULT '',
  incident_id INTEGER, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, occurrences INTEGER NOT NULL DEFAULT 1);
CREATE INDEX IF NOT EXISTS findings_fp ON findings(fingerprint);
CREATE INDEX IF NOT EXISTS findings_status ON findings(status);
CREATE TABLE IF NOT EXISTS incidents (
  id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, severity TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open',
  verdict TEXT NOT NULL DEFAULT '', summary TEXT NOT NULL DEFAULT '', report TEXT NOT NULL DEFAULT '',
  session_id TEXT NOT NULL DEFAULT '', run_id TEXT NOT NULL DEFAULT '', kind TEXT NOT NULL DEFAULT 'incident',
  cost_usd REAL NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS allow_rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT, collector TEXT NOT NULL, key_pattern TEXT NOT NULL, value_pattern TEXT NOT NULL DEFAULT '',
  rule TEXT NOT NULL DEFAULT '', reason TEXT NOT NULL, created_by TEXT NOT NULL, expires_at INTEGER NOT NULL DEFAULT 0,
  hits INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, disabled INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS monitors (
  id TEXT PRIMARY KEY, spec TEXT NOT NULL, created_by TEXT NOT NULL, created_at INTEGER NOT NULL,
  last_run INTEGER NOT NULL DEFAULT 0, last_ok INTEGER NOT NULL DEFAULT 1, last_output TEXT NOT NULL DEFAULT '',
  fails INTEGER NOT NULL DEFAULT 0, runs INTEGER NOT NULL DEFAULT 0, disabled INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS ledger (
  id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, purpose TEXT NOT NULL, model TEXT NOT NULL,
  input_tokens INTEGER NOT NULL, output_tokens INTEGER NOT NULL, cached_tokens INTEGER NOT NULL DEFAULT 0, cost_usd REAL NOT NULL);
CREATE TABLE IF NOT EXISTS journal (id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL);
`)
	if err != nil {
		return err
	}
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS outbox (id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, kind TEXT NOT NULL,
  severity TEXT NOT NULL, title TEXT NOT NULL, body TEXT NOT NULL DEFAULT '', fields TEXT NOT NULL DEFAULT '{}', incident_id INTEGER NOT NULL DEFAULT 0,
  synced INTEGER NOT NULL DEFAULT 0)`); err != nil {
		return err
	}
	if _, err := s.db.Exec(vulnSchema); err != nil {
		return err
	}
	if _, err := s.db.Exec(ruleSchema); err != nil {
		return err
	}
	// Columns added after the first release.
	for _, col := range []string{
		`ALTER TABLE incidents ADD COLUMN self_eval TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE incidents ADD COLUMN confidence REAL NOT NULL DEFAULT 0`,
	} {
		if _, err := s.db.Exec(col); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			return err
		}
	}
	if err := s.addItemColumns(); err != nil {
		return err
	}
	_, err = s.db.Exec(`
CREATE INDEX IF NOT EXISTS findings_item_id ON findings(item_id);
CREATE INDEX IF NOT EXISTS findings_item_key ON findings(item_key);
CREATE INDEX IF NOT EXISTS findings_updated ON findings(updated_at);
CREATE INDEX IF NOT EXISTS journal_at ON journal(at);
CREATE INDEX IF NOT EXISTS ledger_at ON ledger(at);
`)
	return err
}

// migrateHook runs inside the item-column migration, between the ALTERs and
// the backfill (tests use it to fail there).
var migrateHook func(*sql.Tx) error

// addItemColumns adds the sensor item a finding is about as columns
// ItemUnsettled can use an index on (it used to scan the evidence JSON of
// every finding), and fills them in from that JSON for older findings. All
// of it is one transaction: a crash halfway must not leave the columns in
// place but empty, which would make every older finding look settled.
func (s *Store) addItemColumns() error {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('findings') WHERE name IN ('item_id','item_key')`).Scan(&n); err != nil {
		return err
	}
	if n == 2 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{
		`ALTER TABLE findings ADD COLUMN item_id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE findings ADD COLUMN item_key TEXT NOT NULL DEFAULT ''`,
	} {
		if _, err := tx.Exec(q); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			return err
		}
	}
	if migrateHook != nil {
		if err := migrateHook(tx); err != nil {
			return err
		}
	}
	for _, q := range []string{
		`UPDATE findings SET item_id=COALESCE(json_extract(evidence,'$._item_id'),'') WHERE json_valid(evidence)`,
		`UPDATE findings SET item_key=substr(item_id,instr(item_id,'|')+1) WHERE instr(item_id,'|')>0`,
	} {
		if _, err := tx.Exec(q); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ---- kv ----

// LearnerPendingKey is set (to the time) while learning has collected the
// baseline but its learner session and vulnerability assessment wait for a
// model; detection already watches the server meanwhile.
const LearnerPendingKey = "learner_pending"

// AssessmentPendingKey is set (to the time) while the vulnerability
// assessment after a learner that ran is still to do: it failed (a
// provider's limit, a dropped connection) and is retried on its own.
const AssessmentPendingKey = "assessment_pending"

// BaselineProgressKey holds "done/total" baseline sweeps while the learning
// phase collects them, and BaselineETAKey when the last one is due. A
// restart mid-baseline resumes from them; both are cleared once it is done.
const (
	BaselineProgressKey = "baseline_progress"
	BaselineETAKey      = "baseline_eta"
)

// BaselineProgress is the baseline sweeps done and planned, and when the last
// is due (RFC 3339); total is 0 outside the baseline.
func (s *Store) BaselineProgress() (done, total int, eta string) {
	if _, err := fmt.Sscanf(s.Get(BaselineProgressKey), "%d/%d", &done, &total); err != nil || total <= 0 || done < 0 || done > total {
		return 0, 0, ""
	}
	return done, total, s.Get(BaselineETAKey)
}

// SetBaselineProgress records done of total baseline sweeps, the last due at
// eta; total 0 clears the progress.
func (s *Store) SetBaselineProgress(done, total int, eta time.Time) {
	if total <= 0 {
		_ = s.Set(BaselineProgressKey, "")
		_ = s.Set(BaselineETAKey, "")
		return
	}
	_ = s.Set(BaselineProgressKey, fmt.Sprintf("%d/%d", done, total))
	_ = s.Set(BaselineETAKey, eta.UTC().Format(time.RFC3339))
}

func (s *Store) Get(k string) string {
	var v string
	_ = s.db.QueryRow(`SELECT v FROM kv WHERE k=?`, k).Scan(&v)
	return v
}

func (s *Store) Set(k, v string) error {
	_, err := s.db.Exec(`INSERT INTO kv(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, k, v)
	return err
}

// Journal records an auditable action (who changed the defs, and why).
func (s *Store) Journal(actor, action, detail string) {
	_, _ = s.db.Exec(`INSERT INTO journal(at,actor,action,detail) VALUES(?,?,?,?)`, time.Now().Unix(), actor, action, detail)
}

type JournalEntry struct {
	ID     int64     `json:"id"`
	At     time.Time `json:"at"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	Detail string    `json:"detail"`
}

func (s *Store) JournalSince(t time.Time, limit int) []JournalEntry {
	return s.journal(`WHERE at>=? ORDER BY id DESC LIMIT ?`, t.Unix(), limit)
}

// JournalAfter returns entries with id > after, oldest first (hub sync).
func (s *Store) JournalAfter(after int64, limit int) []JournalEntry {
	return s.journal(`WHERE id>? ORDER BY id LIMIT ?`, after, limit)
}

func (s *Store) journal(where string, args ...any) []JournalEntry {
	rows, err := s.db.Query(`SELECT id,at,actor,action,detail FROM journal `+where, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []JournalEntry
	for rows.Next() {
		var at int64
		var e JournalEntry
		_ = rows.Scan(&e.ID, &at, &e.Actor, &e.Action, &e.Detail)
		e.At = time.Unix(at, 0)
		out = append(out, e)
	}
	return out
}

// ---- baseline ----

type BaselineItem struct {
	ID        string            `json:"id"`
	Collector string            `json:"collector"`
	Key       string            `json:"key"`
	Value     string            `json:"value,omitempty"`
	Attrs     map[string]string `json:"attrs,omitempty"`
	FirstSeen time.Time         `json:"first_seen"`
	LastSeen  time.Time         `json:"last_seen"`
	Seen      int               `json:"seen"`
	Source    string            `json:"source"`
	Note      string            `json:"note,omitempty"`
}

// Baseline loads every baseline item into memory, keyed by ID.
func (s *Store) Baseline() (map[string]*BaselineItem, error) {
	rows, err := s.db.Query(`SELECT id,collector,key,value,attrs,first_seen,last_seen,seen,source,note FROM baseline`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]*BaselineItem{}
	for rows.Next() {
		var b BaselineItem
		var attrs string
		var fs, ls int64
		if err := rows.Scan(&b.ID, &b.Collector, &b.Key, &b.Value, &attrs, &fs, &ls, &b.Seen, &b.Source, &b.Note); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(attrs), &b.Attrs)
		b.FirstSeen, b.LastSeen = time.Unix(fs, 0), time.Unix(ls, 0)
		out[b.ID] = &b
	}
	return out, rows.Err()
}

// UpsertBaseline records items as known. seenInc is added to the seen counter.
func (s *Store) UpsertBaseline(items []BaselineItem, source string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO baseline(id,collector,key,value,attrs,first_seen,last_seen,seen,source,note) VALUES(?,?,?,?,?,?,?,1,?,?)
ON CONFLICT(id) DO UPDATE SET value=excluded.value, attrs=excluded.attrs, last_seen=excluded.last_seen, seen=baseline.seen+1,
  note=CASE WHEN excluded.note<>'' THEN excluded.note ELSE baseline.note END`)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()
	now := time.Now().Unix()
	for _, it := range items {
		attrs, _ := json.Marshal(trimAttrs(it.Attrs))
		if _, err := stmt.Exec(it.ID, it.Collector, it.Key, it.Value, string(attrs), now, now, source, it.Note); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// TouchBaseline bumps last_seen/seen for items that are unchanged this sweep.
func (s *Store) TouchBaseline(ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, _ := tx.Prepare(`UPDATE baseline SET last_seen=?, seen=seen+1 WHERE id=?`)
	now := time.Now().Unix()
	for _, id := range ids {
		_, _ = stmt.Exec(now, id)
	}
	stmt.Close()
	return tx.Commit()
}

func (s *Store) DeleteBaseline(id string) error {
	_, err := s.db.Exec(`DELETE FROM baseline WHERE id=?`, id)
	return err
}

// QueryBaseline lists baseline items for a collector whose key contains substr.
func (s *Store) QueryBaseline(collector, substr string, limit int) []BaselineItem {
	q := `SELECT id,collector,key,value,attrs,first_seen,last_seen,seen,source,note FROM baseline WHERE 1=1`
	var args []any
	if collector != "" {
		q += ` AND collector=?`
		args = append(args, collector)
	}
	if substr != "" {
		q += ` AND key LIKE ?`
		args = append(args, "%"+substr+"%")
	}
	q += ` ORDER BY collector,key LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []BaselineItem
	for rows.Next() {
		var b BaselineItem
		var attrs string
		var fs, ls int64
		_ = rows.Scan(&b.ID, &b.Collector, &b.Key, &b.Value, &attrs, &fs, &ls, &b.Seen, &b.Source, &b.Note)
		_ = json.Unmarshal([]byte(attrs), &b.Attrs)
		b.FirstSeen, b.LastSeen = time.Unix(fs, 0), time.Unix(ls, 0)
		out = append(out, b)
	}
	return out
}

// BaselineCounts returns item counts per collector.
func (s *Store) BaselineCounts() map[string]int {
	rows, err := s.db.Query(`SELECT collector, COUNT(*) FROM baseline GROUP BY collector`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var c string
		var n int
		_ = rows.Scan(&c, &n)
		out[c] = n
	}
	return out
}

func (s *Store) BumpCollectorRuns(names []string) {
	for _, n := range names {
		_, _ = s.db.Exec(`INSERT INTO collector_runs(collector,runs) VALUES(?,1) ON CONFLICT(collector) DO UPDATE SET runs=runs+1`, n)
	}
}

func (s *Store) CollectorRuns() map[string]int {
	rows, err := s.db.Query(`SELECT collector,runs FROM collector_runs`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var c string
		var n int
		_ = rows.Scan(&c, &n)
		out[c] = n
	}
	return out
}

func trimAttrs(a map[string]string) map[string]string {
	if len(a) == 0 {
		return nil
	}
	out := make(map[string]string, len(a))
	for k, v := range a {
		if k == "pid" || k == "ppid" { // volatile; never part of the baseline
			continue
		}
		if len(v) > 300 {
			v = v[:300]
		}
		out[k] = v
	}
	return out
}

// ---- findings ----

type Finding struct {
	ID            int64             `json:"id"`
	Fingerprint   string            `json:"fingerprint"`
	Collector     string            `json:"collector"`
	Rule          string            `json:"rule"`
	Severity      string            `json:"severity"`
	Title         string            `json:"title"`
	Detail        string            `json:"detail"`
	Evidence      map[string]string `json:"evidence,omitempty"`
	Status        string            `json:"status"` // new | triaging | benign | escalated | incident | closed | suppressed
	Verdict       string            `json:"verdict,omitempty"`
	VerdictReason string            `json:"verdict_reason,omitempty"`
	IncidentID    int64             `json:"incident_id,omitempty"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
	Occurrences   int               `json:"occurrences"`
	// ItemID links a state finding back to the sensor item so a benign
	// verdict can absorb it into the baseline.
	ItemID string `json:"item_id,omitempty"`
	Value  string `json:"value,omitempty"`
}

// OpenFinding returns the most recent non-closed finding with fingerprint, if any.
func (s *Store) OpenFinding(fp string) *Finding {
	list := s.findings(`WHERE fingerprint=? AND status NOT IN ('closed','benign','suppressed') ORDER BY id DESC LIMIT 1`, fp)
	if len(list) == 0 {
		return nil
	}
	return &list[0]
}

// LastFinding returns the most recent finding with fingerprint regardless of status.
func (s *Store) LastFinding(fp string) *Finding {
	list := s.findings(`WHERE fingerprint=? ORDER BY id DESC LIMIT 1`, fp)
	if len(list) == 0 {
		return nil
	}
	return &list[0]
}

func (s *Store) AddFinding(f *Finding) error {
	ev := map[string]string{}
	for k, v := range f.Evidence {
		ev[k] = v
	}
	if f.ItemID != "" {
		ev["_item_id"] = f.ItemID
		ev["_value"] = f.Value
	}
	b, _ := json.Marshal(ev)
	now := time.Now()
	res, err := s.db.Exec(`INSERT INTO findings(fingerprint,collector,rule,severity,title,detail,evidence,status,created_at,updated_at,item_id,item_key) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
		f.Fingerprint, f.Collector, f.Rule, f.Severity, f.Title, f.Detail, string(b), orDefault(f.Status, "new"), now.Unix(), now.Unix(), f.ItemID, itemKey(f.ItemID))
	if err != nil {
		return err
	}
	f.ID, _ = res.LastInsertId()
	f.CreatedAt, f.UpdatedAt = now, now
	return nil
}

func (s *Store) BumpFinding(id int64) {
	_, _ = s.db.Exec(`UPDATE findings SET occurrences=occurrences+1, updated_at=? WHERE id=?`, time.Now().Unix(), id)
}

func (s *Store) SetFindingStatus(id int64, status, verdict, reason string, incident int64) error {
	_, err := s.db.Exec(`UPDATE findings SET status=?, verdict=CASE WHEN ?<>'' THEN ? ELSE verdict END,
  verdict_reason=CASE WHEN ?<>'' THEN ? ELSE verdict_reason END,
  incident_id=CASE WHEN ?>0 THEN ? ELSE incident_id END, updated_at=? WHERE id=?`,
		status, verdict, verdict, reason, reason, incident, incident, time.Now().Unix(), id)
	return err
}

// ItemUnsettled reports whether a finding about the sensor item (or the same
// path seen by another sensor, e.g. a dropped binary that is also a running
// process) is still open, waiting for a human, or was judged an attack. Such
// items must not be absorbed into the baseline by maintenance windows.
func (s *Store) ItemUnsettled(itemID string) bool {
	match, args := `item_id=?`, []any{itemID}
	if key := itemKey(itemID); strings.HasPrefix(key, "/") && len(key) >= 6 {
		// Same path under any collector: "<collector>|<path>[@…]". A range
		// on item_key is a prefix match that uses its index.
		match, args = `item_key>=? AND item_key<?`, []any{key, key + "\U0010FFFF"}
	}
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM findings WHERE `+match+` AND (`+unsettled+`)`, args...).Scan(&n)
	return n > 0
}

// unsettled matches findings still open, waiting for a human, or judged an
// attack (ItemUnsettled); retention never prunes them.
const unsettled = `status IN ('new','triaging','escalated','incident','needs_ack') OR verdict IN ('true_positive','malicious','suspicious','inconclusive')`

// itemKey is the part of a sensor item id after its collector.
func itemKey(itemID string) string {
	_, key, _ := strings.Cut(itemID, "|")
	return key
}

// RequeueTriaging puts findings a triage run claimed but did not finish
// (kodeblue stopped mid-run) back in the queue.
func (s *Store) RequeueTriaging() int {
	res, err := s.db.Exec(`UPDATE findings SET status='new' WHERE status='triaging'`)
	if err != nil {
		return 0
	}
	n, _ := res.RowsAffected()
	return int(n)
}

// Pruned counts the rows Prune deleted.
type Pruned struct {
	Findings, Journal, Ledger int
}

// Prune deletes findings, journal entries and ledger rows older than before,
// in small batches so the daemon and the MCP server are never locked out for
// long. It keeps every finding that is unsettled (see ItemUnsettled) or
// belongs to an incident that is not resolved.
func (s *Store) Prune(before time.Time) (Pruned, error) {
	cut := before.Unix()
	var p Pruned
	for _, t := range []struct {
		n     *int
		table string
		where string
	}{
		{&p.Findings, "findings", `updated_at<? AND NOT (` + unsettled + `) AND (COALESCE(incident_id,0)=0 OR incident_id NOT IN (SELECT id FROM incidents WHERE status<>'resolved'))`},
		{&p.Journal, "journal", `at<?`},
		{&p.Ledger, "ledger", `at<?`},
	} {
		for {
			res, err := s.db.Exec(`DELETE FROM `+t.table+` WHERE id IN (SELECT id FROM `+t.table+` WHERE `+t.where+` LIMIT 1000)`, cut)
			if err != nil {
				return p, fmt.Errorf("prune %s: %w", t.table, err)
			}
			n, _ := res.RowsAffected()
			*t.n += int(n)
			if n < 1000 {
				break
			}
		}
	}
	return p, nil
}

func (s *Store) FindingsByStatus(status string, limit int) []Finding {
	return s.findings(`WHERE status=? ORDER BY id LIMIT ?`, status, limit)
}

// QueuedFindings returns findings still "new", oldest first: the criticals
// (which skip triage) or everything else (the triage queue).
func (s *Store) QueuedFindings(critical bool, limit int) []Finding {
	if critical {
		return s.findings(`WHERE status='new' AND severity='critical' ORDER BY id LIMIT ?`, limit)
	}
	return s.findings(`WHERE status='new' AND severity<>'critical' ORDER BY id LIMIT ?`, limit)
}

func (s *Store) FindingsForIncident(id int64) []Finding {
	return s.findings(`WHERE incident_id=? ORDER BY id`, id)
}

// FindingsUpdatedSince returns findings changed at or after t, oldest change
// first (hub sync).
func (s *Store) FindingsUpdatedSince(t time.Time, limit int) []Finding {
	return s.findings(`WHERE updated_at>=? ORDER BY updated_at, id LIMIT ?`, t.Unix(), limit)
}

func (s *Store) FindingsSince(t time.Time, limit int) []Finding {
	return s.findings(`WHERE created_at>=? ORDER BY id DESC LIMIT ?`, t.Unix(), limit)
}

func (s *Store) GetFinding(id int64) *Finding {
	l := s.findings(`WHERE id=?`, id)
	if len(l) == 0 {
		return nil
	}
	return &l[0]
}

func (s *Store) findings(where string, args ...any) []Finding {
	rows, err := s.db.Query(`SELECT id,fingerprint,collector,rule,severity,title,detail,evidence,status,verdict,verdict_reason,COALESCE(incident_id,0),created_at,updated_at,occurrences FROM findings `+where, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Finding
	for rows.Next() {
		var f Finding
		var ev string
		var c, u int64
		_ = rows.Scan(&f.ID, &f.Fingerprint, &f.Collector, &f.Rule, &f.Severity, &f.Title, &f.Detail, &ev, &f.Status, &f.Verdict, &f.VerdictReason, &f.IncidentID, &c, &u, &f.Occurrences)
		_ = json.Unmarshal([]byte(ev), &f.Evidence)
		f.ItemID, f.Value = f.Evidence["_item_id"], f.Evidence["_value"]
		delete(f.Evidence, "_item_id")
		delete(f.Evidence, "_value")
		f.CreatedAt, f.UpdatedAt = time.Unix(c, 0), time.Unix(u, 0)
		out = append(out, f)
	}
	return out
}

// FindingStats counts findings created since t by status and rule — the raw
// material for tuning false-positive rates.
func (s *Store) FindingStats(t time.Time) map[string]map[string]int {
	rows, err := s.db.Query(`SELECT rule,status,COUNT(*) FROM findings WHERE created_at>=? GROUP BY rule,status`, t.Unix())
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := map[string]map[string]int{}
	for rows.Next() {
		var r, st string
		var n int
		_ = rows.Scan(&r, &st, &n)
		if out[r] == nil {
			out[r] = map[string]int{}
		}
		out[r][st] = n
	}
	return out
}

// ---- incidents ----

type Incident struct {
	ID        int64   `json:"id"`
	Title     string  `json:"title"`
	Severity  string  `json:"severity"`
	Status    string  `json:"status"` // open | investigating | resolved | needs_human
	Verdict   string  `json:"verdict,omitempty"`
	Summary   string  `json:"summary,omitempty"`
	Report    string  `json:"report,omitempty"`
	SessionID string  `json:"session_id,omitempty"`
	RunID     string  `json:"run_id,omitempty"`
	Kind      string  `json:"kind"` // incident | learning | review | operator
	CostUSD   float64 `json:"cost_usd"`
	// SelfEval is the agent's own assessment of its work: how sure it is,
	// what it could not verify, what would have made it faster.
	SelfEval   string    `json:"self_eval,omitempty"`
	Confidence float64   `json:"confidence,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func (s *Store) CreateIncident(in *Incident) error {
	now := time.Now()
	res, err := s.db.Exec(`INSERT INTO incidents(title,severity,status,kind,created_at,updated_at) VALUES(?,?,?,?,?,?)`,
		in.Title, in.Severity, orDefault(in.Status, "open"), orDefault(in.Kind, "incident"), now.Unix(), now.Unix())
	if err != nil {
		return err
	}
	in.ID, _ = res.LastInsertId()
	in.CreatedAt, in.UpdatedAt = now, now
	return nil
}

func (s *Store) UpdateIncident(in *Incident) error {
	_, err := s.db.Exec(`UPDATE incidents SET title=?,severity=?,status=?,verdict=?,summary=?,report=?,session_id=?,run_id=?,cost_usd=?,
  self_eval=CASE WHEN ?<>'' THEN ? ELSE self_eval END, confidence=CASE WHEN ?>0 THEN ? ELSE confidence END, updated_at=? WHERE id=?`,
		in.Title, in.Severity, in.Status, in.Verdict, in.Summary, in.Report, in.SessionID, in.RunID, in.CostUSD, in.SelfEval, in.SelfEval, in.Confidence, in.Confidence, time.Now().Unix(), in.ID)
	return err
}

func (s *Store) GetIncident(id int64) *Incident {
	l := s.incidents(`WHERE id=?`, id)
	if len(l) == 0 {
		return nil
	}
	return &l[0]
}

func (s *Store) Incidents(where string, args ...any) []Incident { return s.incidents(where, args...) }

func (s *Store) incidents(where string, args ...any) []Incident {
	rows, err := s.db.Query(`SELECT id,title,severity,status,verdict,summary,report,session_id,run_id,kind,cost_usd,self_eval,confidence,created_at,updated_at FROM incidents `+where, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Incident
	for rows.Next() {
		var in Incident
		var c, u int64
		_ = rows.Scan(&in.ID, &in.Title, &in.Severity, &in.Status, &in.Verdict, &in.Summary, &in.Report, &in.SessionID, &in.RunID, &in.Kind, &in.CostUSD, &in.SelfEval, &in.Confidence, &c, &u)
		in.CreatedAt, in.UpdatedAt = time.Unix(c, 0), time.Unix(u, 0)
		out = append(out, in)
	}
	return out
}

// ---- allow rules ----

type AllowRule struct {
	ID           int64     `json:"id"`
	Collector    string    `json:"collector"`
	KeyPattern   string    `json:"key_pattern"`
	ValuePattern string    `json:"value_pattern,omitempty"`
	Rule         string    `json:"rule,omitempty"` // detection rule it applies to; empty = any
	Reason       string    `json:"reason"`
	CreatedBy    string    `json:"created_by"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
	Hits         int       `json:"hits"`
	CreatedAt    time.Time `json:"created_at"`
}

func (s *Store) AddAllowRule(r *AllowRule) error {
	var exp int64
	if !r.ExpiresAt.IsZero() {
		exp = r.ExpiresAt.Unix()
	}
	res, err := s.db.Exec(`INSERT INTO allow_rules(collector,key_pattern,value_pattern,rule,reason,created_by,expires_at,created_at) VALUES(?,?,?,?,?,?,?,?)`,
		r.Collector, r.KeyPattern, r.ValuePattern, r.Rule, r.Reason, r.CreatedBy, exp, time.Now().Unix())
	if err != nil {
		return err
	}
	r.ID, _ = res.LastInsertId()
	s.Journal(r.CreatedBy, "allow_rule.add", fmt.Sprintf("#%d %s %s (%s)", r.ID, r.Collector, r.KeyPattern, r.Reason))
	return nil
}

func (s *Store) AllowRules() []AllowRule {
	rows, err := s.db.Query(`SELECT id,collector,key_pattern,value_pattern,rule,reason,created_by,expires_at,hits,created_at FROM allow_rules WHERE disabled=0 AND (expires_at=0 OR expires_at>?)`, time.Now().Unix())
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []AllowRule
	for rows.Next() {
		var r AllowRule
		var exp, c int64
		_ = rows.Scan(&r.ID, &r.Collector, &r.KeyPattern, &r.ValuePattern, &r.Rule, &r.Reason, &r.CreatedBy, &exp, &r.Hits, &c)
		if exp > 0 {
			r.ExpiresAt = time.Unix(exp, 0)
		}
		r.CreatedAt = time.Unix(c, 0)
		out = append(out, r)
	}
	return out
}

// TouchIncident bumps updated_at so the hub re-syncs it (e.g. its live
// transcript changed).
func (s *Store) TouchIncident(id int64) {
	_, _ = s.db.Exec(`UPDATE incidents SET updated_at=? WHERE id=?`, time.Now().Unix(), id)
}

func (s *Store) HitAllowRule(id int64) {
	_, _ = s.db.Exec(`UPDATE allow_rules SET hits=hits+1 WHERE id=?`, id)
}

func (s *Store) DisableAllowRule(id int64, actor string) error {
	_, err := s.db.Exec(`UPDATE allow_rules SET disabled=1 WHERE id=?`, id)
	s.Journal(actor, "allow_rule.disable", fmt.Sprintf("#%d", id))
	return err
}

// ---- monitors ----

type MonitorRow struct {
	ID         string          `json:"id"`
	Spec       json.RawMessage `json:"spec"`
	CreatedBy  string          `json:"created_by"`
	CreatedAt  time.Time       `json:"created_at"`
	LastRun    time.Time       `json:"last_run"`
	LastOK     bool            `json:"last_ok"`
	LastOutput string          `json:"last_output,omitempty"`
	Fails      int             `json:"fails"`
	Runs       int             `json:"runs"`
	Disabled   bool            `json:"disabled"`
}

func (s *Store) PutMonitor(id string, spec []byte, by string) error {
	_, err := s.db.Exec(`INSERT INTO monitors(id,spec,created_by,created_at) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET spec=excluded.spec, disabled=0`,
		id, string(spec), by, time.Now().Unix())
	if err == nil {
		s.Journal(by, "monitor.put", id)
	}
	return err
}

func (s *Store) Monitors(includeDisabled bool) []MonitorRow {
	q := `SELECT id,spec,created_by,created_at,last_run,last_ok,last_output,fails,runs,disabled FROM monitors`
	if !includeDisabled {
		q += ` WHERE disabled=0`
	}
	rows, err := s.db.Query(q + ` ORDER BY id`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []MonitorRow
	for rows.Next() {
		var m MonitorRow
		var spec string
		var c, lr int64
		var ok, dis int
		_ = rows.Scan(&m.ID, &spec, &m.CreatedBy, &c, &lr, &ok, &m.LastOutput, &m.Fails, &m.Runs, &dis)
		m.Spec = json.RawMessage(spec)
		m.CreatedAt, m.LastRun = time.Unix(c, 0), time.Unix(lr, 0)
		m.LastOK, m.Disabled = ok == 1, dis == 1
		out = append(out, m)
	}
	return out
}

func (s *Store) RecordMonitorRun(id string, ok bool, output string) {
	okInt, failInc := 1, 0
	if !ok {
		okInt, failInc = 0, 1
	}
	if len(output) > 2000 {
		output = output[:2000]
	}
	_, _ = s.db.Exec(`UPDATE monitors SET last_run=?, last_ok=?, last_output=?, runs=runs+1, fails=fails+? WHERE id=?`, time.Now().Unix(), okInt, output, failInc, id)
}

func (s *Store) DisableMonitor(id, actor, reason string) error {
	_, err := s.db.Exec(`UPDATE monitors SET disabled=1 WHERE id=?`, id)
	s.Journal(actor, "monitor.disable", id+": "+reason)
	return err
}

// ---- notification outbox (drained by the hub link) ----

type Notification struct {
	ID         int64             `json:"id"`
	At         time.Time         `json:"at"`
	Kind       string            `json:"kind"`
	Severity   string            `json:"severity"`
	Title      string            `json:"title"`
	Body       string            `json:"body,omitempty"`
	Fields     map[string]string `json:"fields,omitempty"`
	IncidentID int64             `json:"incident_id,omitempty"`
}

// EnqueueNotification implements notify.Queue.
func (s *Store) EnqueueNotification(kind, severity, title, body string, fields map[string]string, incidentID int64) error {
	f, _ := json.Marshal(fields)
	_, err := s.db.Exec(`INSERT INTO outbox(at,kind,severity,title,body,fields,incident_id) VALUES(?,?,?,?,?,?,?)`,
		time.Now().Unix(), kind, severity, title, body, string(f), incidentID)
	return err
}

// UnsyncedNotifications returns queued notifications, oldest first.
func (s *Store) UnsyncedNotifications(limit int) []Notification {
	rows, err := s.db.Query(`SELECT id,at,kind,severity,title,body,fields,incident_id FROM outbox WHERE synced=0 ORDER BY id LIMIT ?`, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Notification
	for rows.Next() {
		var n Notification
		var at int64
		var f string
		_ = rows.Scan(&n.ID, &at, &n.Kind, &n.Severity, &n.Title, &n.Body, &f, &n.IncidentID)
		_ = json.Unmarshal([]byte(f), &n.Fields)
		n.At = time.Unix(at, 0)
		out = append(out, n)
	}
	return out
}

// MarkNotificationsSynced records that the hub accepted them, and drops
// delivered ones older than 30 days.
func (s *Store) MarkNotificationsSynced(ids []int64) {
	for _, id := range ids {
		_, _ = s.db.Exec(`UPDATE outbox SET synced=1 WHERE id=?`, id)
	}
	_, _ = s.db.Exec(`DELETE FROM outbox WHERE synced=1 AND at<?`, time.Now().Add(-30*24*time.Hour).Unix())
}

// ---- ledger ----

// Spend records one model call (or session) and returns the USD it was booked
// at: the reported cost, or the configured token prices when none was reported.
func (s *Store) Spend(purpose, model string, in, out, cached int, usd float64) float64 {
	if usd == 0 && in+out > 0 {
		usd = (float64(in)*s.pricing[0] + float64(out)*s.pricing[1]) / 1e6
		if usd == 0 {
			s.unpriced.Store(true)
		}
	}
	_, _ = s.db.Exec(`INSERT INTO ledger(at,purpose,model,input_tokens,output_tokens,cached_tokens,cost_usd) VALUES(?,?,?,?,?,?,?)`,
		time.Now().Unix(), purpose, model, in, out, cached, usd)
	return usd
}

// SetPricing prices model calls whose endpoint reports no cost, in USD per
// million input and output tokens.
func (s *Store) SetPricing(inputPerMTok, outputPerMTok float64) {
	s.pricing = [2]float64{inputPerMTok, outputPerMTok}
}

// Unpriced reports whether a model call was recorded at $0 because its
// endpoint reported no cost and no pricing is configured.
func (s *Store) Unpriced() bool { return s.unpriced.Load() }

// SpentSince returns USD and tokens spent since t, overall and per purpose.
func (s *Store) SpentSince(t time.Time) (float64, map[string]float64, int) {
	rows, err := s.db.Query(`SELECT purpose, SUM(cost_usd), SUM(input_tokens+output_tokens) FROM ledger WHERE at>=? GROUP BY purpose`, t.Unix())
	if err != nil {
		return 0, nil, 0
	}
	defer rows.Close()
	total, tokens := 0.0, 0
	per := map[string]float64{}
	for rows.Next() {
		var p string
		var c float64
		var tk int
		_ = rows.Scan(&p, &c, &tk)
		per[p] = c
		total += c
		tokens += tk
	}
	return total, per, tokens
}

func orDefault(s, d string) string {
	if strings.TrimSpace(s) == "" {
		return d
	}
	return s
}

// ReserveCloudflareLookup counts only validated requests, independently of the
// security journal. A conditional insert is atomic across concurrent MCP processes.
func (s *Store) ReserveCloudflareLookup(now time.Time, limit int) (bool, error) {
	cutoff := now.Add(-time.Minute).UnixMilli()
	if _, err := s.db.Exec(`DELETE FROM cloudflare_lookups WHERE at<=?`, cutoff); err != nil {
		return false, err
	}
	var at int64
	err := s.db.QueryRow(`INSERT INTO cloudflare_lookups(at) SELECT ? WHERE (SELECT COUNT(*) FROM cloudflare_lookups WHERE at>?)<? RETURNING at`, now.UnixMilli(), cutoff, limit).Scan(&at)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}
