// Package hub is the kodeblue hub: the central console where operators see
// every server's kodeblue (status, incidents, findings, monitors, agent
// reasoning, self-evaluations) and send them messages. Servers dial in with
// their own API key; the hub never connects to a server.
package hub

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
)

type Store struct{ db *sql.DB }

func OpenStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "hub.db")
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
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, pw TEXT NOT NULL,
  created_at INTEGER NOT NULL, last_login INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS web_sessions (hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, ip TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS servers (id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at INTEGER NOT NULL, created_by TEXT NOT NULL,
  enroll_hash TEXT NOT NULL DEFAULT '', enroll_expires INTEGER NOT NULL DEFAULT 0, key_hash TEXT NOT NULL DEFAULT '',
  enrolled_at INTEGER NOT NULL DEFAULT 0, revoked INTEGER NOT NULL DEFAULT 0, last_seen INTEGER NOT NULL DEFAULT 0,
  last_ip TEXT NOT NULL DEFAULT '', hostname TEXT NOT NULL DEFAULT '', version TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT '{}');
CREATE INDEX IF NOT EXISTS servers_key ON servers(key_hash);
CREATE INDEX IF NOT EXISTS servers_enroll ON servers(enroll_hash);
CREATE TABLE IF NOT EXISTS records (server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE, kind TEXT NOT NULL, rid TEXT NOT NULL,
  updated_at INTEGER NOT NULL, received_at INTEGER NOT NULL, data TEXT NOT NULL, PRIMARY KEY(server_id, kind, rid));
CREATE INDEX IF NOT EXISTS records_kind_time ON records(server_id, kind, updated_at);
CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  author TEXT NOT NULL, body TEXT NOT NULL, incident_id INTEGER NOT NULL DEFAULT 0, conversation_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued', created_at INTEGER NOT NULL, delivered_at INTEGER NOT NULL DEFAULT 0,
  replied_at INTEGER NOT NULL DEFAULT 0, reply TEXT NOT NULL DEFAULT '', session_id TEXT NOT NULL DEFAULT '', cost_usd REAL NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS messages_server ON messages(server_id, status);
CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
  server_id TEXT NOT NULL DEFAULT '', detail TEXT NOT NULL DEFAULT '', ip TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS settings (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS case_state (server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE, incident_id INTEGER NOT NULL,
  col TEXT NOT NULL DEFAULT '', archived INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL, updated_by TEXT NOT NULL,
  PRIMARY KEY(server_id, incident_id));
`)
	if err != nil {
		return err
	}
	// Columns added after the first release.
	for _, c := range []struct{ table, col, def string }{
		{"messages", "decision", "TEXT NOT NULL DEFAULT ''"},
		{"messages", "request_id", "TEXT NOT NULL DEFAULT ''"},
		{"messages", "command", "TEXT NOT NULL DEFAULT ''"},
		{"messages", "rule_hash", "TEXT NOT NULL DEFAULT ''"},
		{"case_state", "pinned_at", "INTEGER NOT NULL DEFAULT 0"},
		{"case_state", "pinned_by", "TEXT NOT NULL DEFAULT ''"},
	} {
		if err := s.addColumn(c.table, c.col, c.def); err != nil {
			return err
		}
	}
	if err := s.migrateSlack(); err != nil {
		return err
	}
	if err := s.migrateWarRoom(); err != nil {
		return err
	}
	return nil
}

func (s *Store) addColumn(table, col, def string) error {
	rows, err := s.db.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return err
	}
	have := false
	for rows.Next() {
		var n string
		_ = rows.Scan(&n)
		have = have || n == col
	}
	rows.Close()
	if have {
		return nil
	}
	_, err = s.db.Exec(`ALTER TABLE ` + table + ` ADD COLUMN ` + col + ` ` + def)
	return err
}

// ---- tokens ----

// NewToken returns a random token with a readable prefix (kbe_ enrollment,
// kbk_ server API key, kbs_ web session).
func NewToken(prefix string) string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return prefix + hex.EncodeToString(b)
}

// Hash is how tokens are stored: the hub keeps no usable credential.
func Hash(token string) string {
	s := sha256.Sum256([]byte(token))
	return hex.EncodeToString(s[:])
}

// ---- settings ----

// The fleet's model endpoint. Enrollment hands it to a server that has
// none of its own; servers that accept hub settings also take later changes
// (EffectiveSettings).
const (
	SettingInferenceKey      = "fleet_inference_key"
	SettingInferenceURL      = "fleet_inference_url"
	SettingInferenceProvider = "fleet_inference_provider"
	SettingInferenceModel    = "fleet_inference_model"
)

func (s *Store) Setting(k string) string {
	var v string
	_ = s.db.QueryRow(`SELECT v FROM settings WHERE k=?`, k).Scan(&v)
	return v
}

func (s *Store) SetSetting(k, v string) error {
	if v == "" {
		_, err := s.db.Exec(`DELETE FROM settings WHERE k=?`, k)
		return err
	}
	_, err := s.db.Exec(`INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, k, v)
	return err
}

// ---- audit ----

type AuditEntry struct {
	ID       int64     `json:"id"`
	At       time.Time `json:"at"`
	Actor    string    `json:"actor"`
	Action   string    `json:"action"`
	ServerID string    `json:"server_id,omitempty"`
	Detail   string    `json:"detail,omitempty"`
	IP       string    `json:"ip,omitempty"`
}

func (s *Store) Audit(actor, action, server, detail, ip string) {
	_, _ = s.db.Exec(`INSERT INTO audit(at,actor,action,server_id,detail,ip) VALUES(?,?,?,?,?,?)`, time.Now().Unix(), actor, action, server, detail, ip)
}

func (s *Store) AuditLog(limit int) []AuditEntry {
	rows, err := s.db.Query(`SELECT id,at,actor,action,server_id,detail,ip FROM audit ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var at int64
		_ = rows.Scan(&e.ID, &at, &e.Actor, &e.Action, &e.ServerID, &e.Detail, &e.IP)
		e.At = time.Unix(at, 0)
		out = append(out, e)
	}
	return out
}

// ---- servers ----

// Host is one monitored server as the hub knows it.
type Host struct {
	ID            string          `json:"id"`
	Name          string          `json:"name"`
	CreatedAt     time.Time       `json:"created_at"`
	CreatedBy     string          `json:"created_by"`
	Enrolled      bool            `json:"enrolled"`
	EnrolledAt    time.Time       `json:"enrolled_at,omitempty"`
	EnrollPending bool            `json:"enroll_pending"`
	EnrollExpires time.Time       `json:"enroll_expires,omitempty"`
	Revoked       bool            `json:"revoked"`
	LastSeen      time.Time       `json:"last_seen,omitempty"`
	LastIP        string          `json:"last_ip,omitempty"`
	Hostname      string          `json:"hostname,omitempty"`
	Version       string          `json:"version,omitempty"`
	Status        json.RawMessage `json:"status"`
}

func (s *Store) CreateServer(name, by string, ttl time.Duration) (*Host, string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 80 {
		return nil, "", errors.New("name must be 1-80 characters")
	}
	id := "srv_" + NewToken("")[:16]
	token := NewToken("kbe_")
	now := time.Now()
	_, err := s.db.Exec(`INSERT INTO servers(id,name,created_at,created_by,enroll_hash,enroll_expires) VALUES(?,?,?,?,?,?)`,
		id, name, now.Unix(), by, Hash(token), now.Add(ttl).Unix())
	if err != nil {
		return nil, "", err
	}
	return s.GetServer(id), token, nil
}

// NewEnrollToken issues a fresh one-time token for an existing server. Using
// it replaces the server's API key (rotation / reinstall).
func (s *Store) NewEnrollToken(id string, ttl time.Duration) (string, error) {
	token := NewToken("kbe_")
	res, err := s.db.Exec(`UPDATE servers SET enroll_hash=?, enroll_expires=? WHERE id=?`, Hash(token), time.Now().Add(ttl).Unix(), id)
	if err != nil {
		return "", err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", errors.New("server not found")
	}
	return token, nil
}

// Enroll consumes a one-time token and returns the server's new API key.
func (s *Store) Enroll(token, hostname, version string) (*Host, string, error) {
	if !strings.HasPrefix(token, "kbe_") {
		return nil, "", errors.New("invalid enrollment token")
	}
	var id string
	err := s.db.QueryRow(`SELECT id FROM servers WHERE enroll_hash=? AND enroll_expires>?`, Hash(token), time.Now().Unix()).Scan(&id)
	if err != nil {
		return nil, "", errors.New("invalid or expired enrollment token")
	}
	key := NewToken("kbk_")
	res, err := s.db.Exec(`UPDATE servers SET key_hash=?, enroll_hash='', enroll_expires=0, enrolled_at=?, revoked=0, hostname=?, version=? WHERE id=? AND enroll_hash=?`,
		Hash(key), time.Now().Unix(), trim(hostname, 200), trim(version, 60), id, Hash(token))
	if err != nil {
		return nil, "", err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return nil, "", errors.New("invalid or expired enrollment token") // used concurrently
	}
	return s.GetServer(id), key, nil
}

// ServerByKey authenticates a server API key.
func (s *Store) ServerByKey(key string) *Host {
	if !strings.HasPrefix(key, "kbk_") {
		return nil
	}
	l := s.servers(`WHERE key_hash=? AND revoked=0`, Hash(key))
	if len(l) == 0 {
		return nil
	}
	return &l[0]
}

// ValidEnrollToken reports whether token is a live, unused enrollment token
// (used to authorize installer downloads).
func (s *Store) ValidEnrollToken(token string) bool {
	if !strings.HasPrefix(token, "kbe_") {
		return false
	}
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM servers WHERE enroll_hash=? AND enroll_expires>?`, Hash(token), time.Now().Unix()).Scan(&n)
	return n > 0
}

func (s *Store) Revoke(id string) error {
	_, err := s.db.Exec(`UPDATE servers SET revoked=1, key_hash='', enroll_hash='', enroll_expires=0 WHERE id=?`, id)
	return err
}

func (s *Store) DeleteServer(id string) error {
	if _, err := s.db.Exec(`DELETE FROM servers WHERE id=?`, id); err != nil {
		return err
	}
	return s.SetSetting(settingServerPrefix+id, "")
}

func (s *Store) RenameServer(id, name string) error {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 80 {
		return errors.New("name must be 1-80 characters")
	}
	_, err := s.db.Exec(`UPDATE servers SET name=? WHERE id=?`, name, id)
	return err
}

func (s *Store) Seen(id, ip string) {
	_, _ = s.db.Exec(`UPDATE servers SET last_seen=?, last_ip=? WHERE id=?`, time.Now().Unix(), ip, id)
}

func (s *Store) GetServer(id string) *Host {
	l := s.servers(`WHERE id=?`, id)
	if len(l) == 0 {
		return nil
	}
	return &l[0]
}

func (s *Store) Servers() []Host { return s.servers(`ORDER BY name`) }

func (s *Store) servers(where string, args ...any) []Host {
	rows, err := s.db.Query(`SELECT id,name,created_at,created_by,enroll_hash,enroll_expires,key_hash,enrolled_at,revoked,last_seen,last_ip,hostname,version,status FROM servers `+where, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Host
	for rows.Next() {
		var v Host
		var created, exp, enrolled, seen int64
		var eh, kh, status string
		var revoked int
		_ = rows.Scan(&v.ID, &v.Name, &created, &v.CreatedBy, &eh, &exp, &kh, &enrolled, &revoked, &seen, &v.LastIP, &v.Hostname, &v.Version, &status)
		v.CreatedAt = time.Unix(created, 0)
		v.Enrolled, v.Revoked = kh != "", revoked == 1
		v.EnrollPending = eh != "" && exp > time.Now().Unix()
		if exp > 0 {
			v.EnrollExpires = time.Unix(exp, 0)
		}
		if enrolled > 0 {
			v.EnrolledAt = time.Unix(enrolled, 0)
		}
		if seen > 0 {
			v.LastSeen = time.Unix(seen, 0)
		}
		v.Status = json.RawMessage(status)
		out = append(out, v)
	}
	return out
}

// ---- sync ----

var syncKinds = map[string]bool{"incident": true, "finding": true, "monitor": true, "allow_rule": true, "journal": true,
	"action": true, "pending_action": true, "session": true, "report": true, "skill": true, "definition": true,
	"service": true, "vulnerability": true, "containment_rule": true}

const maxRecordBytes = 2 << 20

// ApplySync stores one sync batch from server id.
func (s *Store) ApplySync(id string, req *hubproto.SyncRequest) error {
	_, err := s.ApplySyncNotify(id, req)
	return err
}

// ApplySyncNotify stores one sync batch and reports whether it carried new
// notifications (the Slack forwarder is woken for those).
func (s *Store) ApplySyncNotify(id string, req *hubproto.SyncRequest) (bool, error) {
	newNotes := false
	status, _ := json.Marshal(req.Status)
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	if _, err := tx.Exec(`UPDATE servers SET status=?, version=?, hostname=? WHERE id=?`, string(status), trim(req.Status.Version, 60), trim(req.Status.Hostname, 200), id); err != nil {
		return false, err
	}
	keep := map[string]map[string]bool{}
	for _, k := range req.Replace {
		if syncKinds[k] {
			keep[k] = map[string]bool{}
		}
	}
	stmt, err := tx.Prepare(`INSERT INTO records(server_id,kind,rid,updated_at,received_at,data) VALUES(?,?,?,?,?,?)
ON CONFLICT(server_id,kind,rid) DO UPDATE SET updated_at=excluded.updated_at, received_at=excluded.received_at, data=excluded.data`)
	if err != nil {
		return false, err
	}
	defer stmt.Close()
	for _, r := range req.Records {
		if r.Kind == "notification" && r.ID != "" && len(r.ID) <= 40 && len(r.Data) <= 64<<10 {
			added, err := addNotification(tx, id, r)
			if err != nil {
				return false, err
			}
			newNotes = newNotes || added
			continue
		}
		if !syncKinds[r.Kind] || r.ID == "" || len(r.ID) > 200 || len(r.Data) > maxRecordBytes || !json.Valid(r.Data) {
			continue
		}
		if keep[r.Kind] != nil {
			keep[r.Kind][r.ID] = true
		}
		if _, err := stmt.Exec(id, r.Kind, r.ID, r.UpdatedAt.Unix(), now, string(r.Data)); err != nil {
			return false, err
		}
		if r.Kind == "finding" {
			if err := indexWarFinding(tx, id, r.ID, r.Data); err != nil {
				return false, err
			}
		}
	}
	for kind, ids := range keep {
		rows, err := tx.Query(`SELECT rid FROM records WHERE server_id=? AND kind=?`, id, kind)
		if err != nil {
			return false, err
		}
		var drop []string
		for rows.Next() {
			var rid string
			_ = rows.Scan(&rid)
			if !ids[rid] {
				drop = append(drop, rid)
			}
		}
		rows.Close()
		for _, rid := range drop {
			if _, err := tx.Exec(`DELETE FROM records WHERE server_id=? AND kind=? AND rid=?`, id, kind, rid); err != nil {
				return false, err
			}
		}
	}
	return newNotes, tx.Commit()
}

type Rec struct {
	Kind      string          `json:"kind"`
	ID        string          `json:"id"`
	UpdatedAt time.Time       `json:"updated_at"`
	Data      json.RawMessage `json:"data"`
}

// Records lists a server's records of kind, newest first. q filters on the
// raw JSON text (case-insensitive).
func (s *Store) Records(server, kind, q string, since time.Time, limit int) []Rec {
	query := `SELECT kind,rid,updated_at,data FROM records WHERE server_id=? AND kind=? AND updated_at>=?`
	args := []any{server, kind, since.Unix()}
	if q = strings.TrimSpace(q); q != "" {
		query += ` AND data LIKE ? ESCAPE '\'`
		args = append(args, "%"+likeEscape(q)+"%")
	}
	order := ` ORDER BY updated_at DESC, CAST(rid AS INTEGER) DESC LIMIT ?`
	rows, err := s.db.Query(query+order, append(args, limit)...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []Rec{}
	for rows.Next() {
		var r Rec
		var at int64
		var data string
		_ = rows.Scan(&r.Kind, &r.ID, &at, &data)
		r.UpdatedAt, r.Data = time.Unix(at, 0), json.RawMessage(data)
		out = append(out, r)
	}
	return out
}

func (s *Store) Record(server, kind, rid string) *Rec {
	var r Rec
	var at int64
	var data string
	err := s.db.QueryRow(`SELECT kind,rid,updated_at,data FROM records WHERE server_id=? AND kind=? AND rid=?`, server, kind, rid).Scan(&r.Kind, &r.ID, &at, &data)
	if err != nil {
		return nil
	}
	r.UpdatedAt, r.Data = time.Unix(at, 0), json.RawMessage(data)
	return &r
}

// TaskRow is one incident record (any kind) as a task on the console's
// board: the light fields only, so the board can refresh often.
type TaskRow struct {
	ServerID   string          `json:"server_id"`
	ServerName string          `json:"server_name"`
	UpdatedAt  time.Time       `json:"updated_at"`
	Data       json.RawMessage `json:"data"`
	Board      *CaseState      `json:"board,omitempty"`
	// Pin: an operator pinned the case to the top of its column. Unlike
	// Board it holds whatever the agent does, until someone unpins it.
	Pin *Pin `json:"pin,omitempty"`
}

// Pin records who pinned a case and when.
type Pin struct {
	By string    `json:"by"`
	At time.Time `json:"at"`
}

// CaseState is the hub's own board state for a case: where an operator
// dragged it and whether it is archived. The server never sees it.
type CaseState struct {
	Column    string    `json:"column,omitempty"` // "" (follow the agent) | human | done
	Archived  bool      `json:"archived,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy string    `json:"updated_by"`
}

// SetCaseState updates the column and/or archived flag of one case.
func (s *Store) SetCaseState(server string, incident int64, col *string, archived *bool, by string) (*CaseState, error) {
	cur := s.caseState(server, incident)
	if cur == nil {
		cur = &CaseState{}
	}
	if col != nil {
		cur.Column = *col
	}
	if archived != nil {
		cur.Archived = *archived
	}
	cur.UpdatedAt, cur.UpdatedBy = time.Now().UTC().Truncate(time.Second), by
	_, err := s.db.Exec(`INSERT INTO case_state(server_id,incident_id,col,archived,updated_at,updated_by) VALUES(?,?,?,?,?,?)
ON CONFLICT(server_id,incident_id) DO UPDATE SET col=excluded.col, archived=excluded.archived, updated_at=excluded.updated_at, updated_by=excluded.updated_by`,
		server, incident, cur.Column, cur.Archived, cur.UpdatedAt.Unix(), by)
	return cur, err
}

// SetCasePin pins or unpins a case for everyone. It leaves the board state
// (column, archived, updated_at) alone: a pin is not a move.
func (s *Store) SetCasePin(server string, incident int64, on bool, by string) (*Pin, error) {
	at, who := int64(0), ""
	var pin *Pin
	if on {
		now := time.Now().UTC().Truncate(time.Second)
		at, who, pin = now.Unix(), by, &Pin{By: by, At: now}
	}
	_, err := s.db.Exec(`INSERT INTO case_state(server_id,incident_id,updated_at,updated_by,pinned_at,pinned_by) VALUES(?,?,0,'',?,?)
ON CONFLICT(server_id,incident_id) DO UPDATE SET pinned_at=excluded.pinned_at, pinned_by=excluded.pinned_by`, server, incident, at, who)
	return pin, err
}

func (s *Store) caseState(server string, incident int64) *CaseState {
	var c CaseState
	var at int64
	if s.db.QueryRow(`SELECT col,archived,updated_at,updated_by FROM case_state WHERE server_id=? AND incident_id=?`, server, incident).
		Scan(&c.Column, &c.Archived, &at, &c.UpdatedBy) != nil {
		return nil
	}
	c.UpdatedAt = time.Unix(at, 0).UTC()
	return &c
}

// Approval is a pending containment request as the board shows it.
type Approval struct {
	ServerID string          `json:"server_id"`
	Data     json.RawMessage `json:"data"`
}

// PendingApprovals lists pending_action records, across the fleet or one server.
func (s *Store) PendingApprovals(server string) []Approval {
	q, args := `SELECT server_id, data FROM records WHERE kind='pending_action'`, []any{}
	if server != "" {
		q += ` AND server_id=?`
		args = append(args, server)
	}
	rows, err := s.db.Query(q+` ORDER BY updated_at DESC LIMIT 500`, args...)
	if err != nil {
		return []Approval{}
	}
	defer rows.Close()
	out := []Approval{}
	for rows.Next() {
		var a Approval
		var data string
		_ = rows.Scan(&a.ServerID, &data)
		a.Data = json.RawMessage(data)
		out = append(out, a)
	}
	return out
}

// taskFields are the incident fields the board needs; reports, summaries
// and self-evaluations stay on the record endpoint.
var taskFields = []string{"id", "kind", "title", "severity", "status", "verdict", "confidence", "session_id", "cost_usd", "created_at", "updated_at"}

// Tasks lists incident records newest first, across all servers or one.
func (s *Store) Tasks(server string, limit int) []TaskRow {
	query := `SELECT r.server_id, s.name, r.updated_at, r.data, c.col, c.archived, c.updated_at, c.updated_by, c.pinned_at, c.pinned_by FROM records r JOIN servers s ON s.id=r.server_id
LEFT JOIN case_state c ON c.server_id=r.server_id AND c.incident_id=CAST(r.rid AS INTEGER) WHERE r.kind='incident'`
	args := []any{}
	if server != "" {
		query += ` AND r.server_id=?`
		args = append(args, server)
	}
	rows, err := s.db.Query(query+` ORDER BY r.updated_at DESC, CAST(r.rid AS INTEGER) DESC LIMIT ?`, append(args, limit)...)
	if err != nil {
		return []TaskRow{}
	}
	defer rows.Close()
	out := []TaskRow{}
	for rows.Next() {
		var t TaskRow
		var at int64
		var data string
		var col, by, pby sql.NullString
		var arch, cat, pat sql.NullInt64
		_ = rows.Scan(&t.ServerID, &t.ServerName, &at, &data, &col, &arch, &cat, &by, &pat, &pby)
		if cat.Int64 > 0 {
			t.Board = &CaseState{Column: col.String, Archived: arch.Int64 != 0, UpdatedAt: time.Unix(cat.Int64, 0).UTC(), UpdatedBy: by.String}
		}
		if pat.Int64 > 0 {
			t.Pin = &Pin{By: pby.String, At: time.Unix(pat.Int64, 0).UTC()}
		}
		var full map[string]json.RawMessage
		if json.Unmarshal([]byte(data), &full) != nil {
			continue
		}
		light := map[string]json.RawMessage{}
		for _, k := range taskFields {
			if v, ok := full[k]; ok {
				light[k] = v
			}
		}
		if v, ok := full["summary"]; ok {
			var sum string
			if json.Unmarshal(v, &sum) == nil {
				light["summary"], _ = json.Marshal(trimRunes(sum, 240))
			}
		}
		t.UpdatedAt = time.Unix(at, 0)
		t.Data, _ = json.Marshal(light)
		out = append(out, t)
	}
	return out
}

// Counts summarizes a server for the fleet view.
type Counts struct {
	OpenIncidents  map[string]int `json:"open_incidents"` // severity -> n
	NeedsHuman     int            `json:"needs_human"`
	Investigating  int            `json:"investigating"`
	NeedsAck       int            `json:"needs_ack"`
	PendingActions int            `json:"pending_actions"`
	Monitors       int            `json:"monitors"`
	FailingMonitor int            `json:"failing_monitors"`
	Incidents24h   int            `json:"incidents_24h"`
	Services       int            `json:"services"`
	OpenVulns      map[string]int `json:"open_vulnerabilities"` // severity -> n
	RulesWaiting   int            `json:"rules_waiting"`        // containment rules waiting for approval
}

func (s *Store) Counts(server string) Counts {
	c := Counts{OpenIncidents: map[string]int{}, OpenVulns: map[string]int{}}
	day := time.Now().Add(-24 * time.Hour).Unix()
	rows, err := s.db.Query(`SELECT json_extract(data,'$.severity'), json_extract(data,'$.status'), json_extract(data,'$.kind'), updated_at,
  json_extract(data,'$.created_at') FROM records WHERE server_id=? AND kind='incident'`, server)
	if err == nil {
		for rows.Next() {
			var sev, st, kind, created sql.NullString
			var at int64
			_ = rows.Scan(&sev, &st, &kind, &at, &created)
			if kind.String == "coverage" && st.String == "needs_human" {
				// A service kodeblue cannot monitor well enough: not an
				// incident, but it waits for a human all the same.
				c.NeedsHuman++
			}
			if kind.String != "incident" {
				continue
			}
			if t, err := time.Parse(time.RFC3339Nano, created.String); err == nil && t.Unix() >= day {
				c.Incidents24h++
			}
			switch st.String {
			case "resolved":
			case "investigating":
				c.Investigating++
				c.OpenIncidents[sev.String]++
			case "needs_human":
				c.NeedsHuman++
				c.OpenIncidents[sev.String]++
			default:
				c.OpenIncidents[sev.String]++
			}
		}
		rows.Close()
	}
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM records WHERE server_id=? AND kind='finding' AND json_extract(data,'$.status')='needs_ack'`, server).Scan(&c.NeedsAck)
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM records WHERE server_id=? AND kind='pending_action'`, server).Scan(&c.PendingActions)
	_ = s.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(CASE WHEN json_extract(data,'$.last_ok') THEN 0 ELSE 1 END),0) FROM records
  WHERE server_id=? AND kind='monitor' AND NOT json_extract(data,'$.disabled')`, server).Scan(&c.Monitors, &c.FailingMonitor)
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM records WHERE server_id=? AND kind='service'`, server).Scan(&c.Services)
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM records WHERE server_id=? AND kind='containment_rule'
  AND (json_extract(data,'$.status')='proposed' OR json_extract(data,'$.pending_change'))`, server).Scan(&c.RulesWaiting)
	if rows, err := s.db.Query(`SELECT json_extract(data,'$.severity'), COUNT(*) FROM records WHERE server_id=? AND kind='vulnerability'
  AND json_extract(data,'$.status')='open' GROUP BY 1`, server); err == nil {
		for rows.Next() {
			var sev sql.NullString
			var n int
			if rows.Scan(&sev, &n) == nil {
				c.OpenVulns[sev.String] = n
			}
		}
		rows.Close()
	}
	return c
}

// Prune drops old high-volume records.
func (s *Store) Prune(keep time.Duration) {
	cut := time.Now().Add(-keep).Unix()
	_, _ = s.db.Exec(`DELETE FROM records WHERE kind IN ('journal','finding','session') AND updated_at<?`, cut)
	_, _ = s.db.Exec(`DELETE FROM web_sessions WHERE expires_at<?`, time.Now().Unix())
	_, _ = s.db.Exec(`DELETE FROM audit WHERE at<?`, time.Now().Add(-365*24*time.Hour).Unix())
	_, _ = s.db.Exec(`DELETE FROM notifications WHERE at<?`, cut)
	_, _ = s.db.Exec(`DELETE FROM war_events WHERE NOT EXISTS (SELECT 1 FROM records f WHERE f.server_id=war_events.server_id AND f.kind='finding' AND f.rid=war_events.finding_id)`)
	_, _ = s.db.Exec(`DELETE FROM war_sources WHERE looked_at<? AND NOT EXISTS(SELECT 1 FROM war_events WHERE war_events.ip=war_sources.ip)`, time.Now().Add(-7*24*time.Hour).Unix())
}

// ---- messages ----

type Message struct {
	ID             int64     `json:"id"`
	ServerID       string    `json:"server_id"`
	Author         string    `json:"author"`
	Body           string    `json:"body"`
	IncidentID     int64     `json:"incident_id,omitempty"`
	ConversationID string    `json:"conversation_id"`
	Status         string    `json:"status"` // queued | delivered | done | failed | refused
	CreatedAt      time.Time `json:"created_at"`
	DeliveredAt    time.Time `json:"delivered_at,omitempty"`
	RepliedAt      time.Time `json:"replied_at,omitempty"`
	Reply          string    `json:"reply,omitempty"`
	SessionID      string    `json:"session_id,omitempty"`
	CostUSD        float64   `json:"cost_usd,omitempty"`
	// Decision/RequestID: an approve or deny of a pending containment
	// request, handled by the server without a model.
	Decision  string `json:"decision,omitempty"`
	RequestID string `json:"request_id,omitempty"`
	// Command: a learning command (hubproto.Command*), also handled
	// without a model.
	Command string `json:"command,omitempty"`
	// RuleHash: the containment rule content an approval names.
	RuleHash string `json:"rule_hash,omitempty"`
}

// OpenCommand is the queued or delivered learning command for server, if any.
func (s *Store) OpenCommand(server string) *Message {
	list := s.messages(`WHERE server_id=? AND command IN (?,?) AND status IN ('queued','delivered') ORDER BY id DESC LIMIT 1`, server,
		hubproto.CommandLearn, hubproto.CommandRelearn)
	if len(list) == 0 {
		return nil
	}
	return &list[0]
}

// OpenUpgrade is the queued or delivered upgrade command for server, if any.
func (s *Store) OpenUpgrade(server string) *Message {
	list := s.messages(`WHERE server_id=? AND command=? AND status IN ('queued','delivered') ORDER BY id DESC LIMIT 1`, server, hubproto.CommandUpgrade)
	if len(list) == 0 {
		return nil
	}
	return &list[0]
}

// OpenDecision is the queued or delivered decision on a request, if any.
// DecisionReplyWait is how long a delivered ruling waits for the server's
// reply before the request can be ruled on again (the helper's own deadline
// is 2 minutes).
const DecisionReplyWait = 5 * time.Minute

func (s *Store) OpenDecision(server, request string) *Message {
	// A ruling delivered long ago whose reply never came (the server
	// restarted mid-run, the reply was lost) no longer blocks a new one: the
	// server answers a ruling on a settled request with "no pending request".
	list := s.messages(`WHERE server_id=? AND request_id=? AND decision<>'' AND (status='queued' OR (status='delivered' AND delivered_at>?)) ORDER BY id DESC LIMIT 1`,
		server, request, time.Now().Add(-DecisionReplyWait).Unix())
	if len(list) == 0 {
		return nil
	}
	return &list[0]
}

func (s *Store) AddMessage(m *Message) error {
	if m.ConversationID == "" {
		m.ConversationID = "c_" + NewToken("")[:12]
	}
	res, err := s.db.Exec(`INSERT INTO messages(server_id,author,body,incident_id,conversation_id,created_at,decision,request_id,command,session_id,rule_hash) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		m.ServerID, m.Author, m.Body, m.IncidentID, m.ConversationID, time.Now().Unix(), m.Decision, m.RequestID, m.Command, m.SessionID, m.RuleHash)
	if err != nil {
		return err
	}
	m.ID, _ = res.LastInsertId()
	m.Status = "queued"
	return nil
}

// TakeQueued marks queued messages for server as delivered and returns them.
func (s *Store) TakeQueued(server string) []Message {
	list := s.messages(`WHERE server_id=? AND status='queued' ORDER BY id LIMIT 5`, server)
	for i := range list {
		_, _ = s.db.Exec(`UPDATE messages SET status='delivered', delivered_at=? WHERE id=?`, time.Now().Unix(), list[i].ID)
		list[i].Status = "delivered"
	}
	return list
}

func (s *Store) QueuedCount(server string) int {
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM messages WHERE server_id=? AND status='queued'`, server).Scan(&n)
	return n
}

func (s *Store) Reply(server string, id int64, r hubproto.MessageReply) error {
	switch r.Status {
	case "done", "failed", "refused":
	default:
		return fmt.Errorf("bad status %q", r.Status)
	}
	res, err := s.db.Exec(`UPDATE messages SET status=?, reply=?, session_id=?, cost_usd=?, replied_at=? WHERE id=? AND server_id=? AND status IN ('delivered','queued')`,
		r.Status, trim(r.Text, 60000), trim(r.SessionID, 100), r.CostUSD, time.Now().Unix(), id, server)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("no such message awaiting a reply")
	}
	return nil
}

func (s *Store) Messages(server string, limit int) []Message {
	return s.messages(`WHERE server_id=? ORDER BY id DESC LIMIT ?`, server, limit)
}

// AllMessages lists the newest messages across all servers.
func (s *Store) AllMessages(limit int) []Message {
	return s.messages(`ORDER BY id DESC LIMIT ?`, limit)
}

func (s *Store) messages(where string, args ...any) []Message {
	rows, err := s.db.Query(`SELECT id,server_id,author,body,incident_id,conversation_id,status,created_at,delivered_at,replied_at,reply,session_id,cost_usd,decision,request_id,command,rule_hash FROM messages `+where, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []Message{}
	for rows.Next() {
		var m Message
		var c, d, r int64
		_ = rows.Scan(&m.ID, &m.ServerID, &m.Author, &m.Body, &m.IncidentID, &m.ConversationID, &m.Status, &c, &d, &r, &m.Reply, &m.SessionID, &m.CostUSD, &m.Decision, &m.RequestID, &m.Command, &m.RuleHash)
		m.CreatedAt = time.Unix(c, 0)
		if d > 0 {
			m.DeliveredAt = time.Unix(d, 0)
		}
		if r > 0 {
			m.RepliedAt = time.Unix(r, 0)
		}
		out = append(out, m)
	}
	return out
}

func trim(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// trimRunes cuts s to at most n runes, marking the cut.
func trimRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

func likeEscape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}
