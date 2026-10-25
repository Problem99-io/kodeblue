package hub

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Operator passwords: PBKDF2-HMAC-SHA256, 600k iterations (OWASP 2023).
const pwIter = 600_000

func HashPassword(pw string) (string, error) {
	if len(pw) < 12 {
		return "", errors.New("password must be at least 12 characters")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	dk, err := pbkdf2.Key(sha256.New, pw, salt, pwIter, 32)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", pwIter, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(dk)), nil
}

func CheckPassword(stored, pw string) bool {
	p := strings.Split(stored, "$")
	if len(p) != 4 || p[0] != "pbkdf2-sha256" {
		return false
	}
	iter, err := strconv.Atoi(p[1])
	if err != nil || iter < 100_000 {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(p[2])
	want, err2 := base64.RawStdEncoding.DecodeString(p[3])
	if err1 != nil || err2 != nil {
		return false
	}
	dk, err := pbkdf2.Key(sha256.New, pw, salt, iter, len(want))
	return err == nil && subtle.ConstantTimeCompare(dk, want) == 1
}

// dummyHash keeps login timing the same for unknown users.
var dummyHash = sync.OnceValue(func() string { h, _ := HashPassword("not-a-real-password-000"); return h })

type User struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	LastLogin time.Time `json:"last_login,omitempty"`
}

func (s *Store) AddUser(name, pw string) error {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 64 || strings.ContainsAny(name, " \t\r\n") {
		return errors.New("user name must be 1-64 characters without spaces")
	}
	h, err := HashPassword(pw)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO users(name,pw,created_at) VALUES(?,?,?) ON CONFLICT(name) DO UPDATE SET pw=excluded.pw`, name, h, time.Now().Unix())
	if err == nil {
		// A password change logs the user out everywhere.
		_, _ = s.db.Exec(`DELETE FROM web_sessions WHERE user_id=(SELECT id FROM users WHERE name=?)`, name)
	}
	return err
}

func (s *Store) DeleteUser(name string) error {
	res, err := s.db.Exec(`DELETE FROM users WHERE name=?`, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("no such user")
	}
	return nil
}

func (s *Store) Users() []User {
	rows, err := s.db.Query(`SELECT id,name,created_at,last_login FROM users ORDER BY name`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		var c, l int64
		_ = rows.Scan(&u.ID, &u.Name, &c, &l)
		u.CreatedAt = time.Unix(c, 0)
		if l > 0 {
			u.LastLogin = time.Unix(l, 0)
		}
		out = append(out, u)
	}
	return out
}

// Login verifies credentials and opens a web session. It returns the
// session token (cookie value) and its CSRF token.
func (s *Store) Login(name, pw, ip string, ttl time.Duration) (*User, string, string, error) {
	var id int64
	var stored string
	err := s.db.QueryRow(`SELECT id,pw FROM users WHERE name=?`, name).Scan(&id, &stored)
	if err != nil {
		CheckPassword(dummyHash(), pw)
		return nil, "", "", errors.New("invalid credentials")
	}
	if !CheckPassword(stored, pw) {
		return nil, "", "", errors.New("invalid credentials")
	}
	tok, csrf := NewToken("kbs_"), NewToken("")
	now := time.Now()
	if _, err := s.db.Exec(`INSERT INTO web_sessions(hash,user_id,csrf,created_at,expires_at,ip) VALUES(?,?,?,?,?,?)`, Hash(tok), id, csrf, now.Unix(), now.Add(ttl).Unix(), ip); err != nil {
		return nil, "", "", err
	}
	_, _ = s.db.Exec(`UPDATE users SET last_login=? WHERE id=?`, now.Unix(), id)
	return &User{ID: id, Name: name}, tok, csrf, nil
}

// Session resolves a web session cookie.
func (s *Store) Session(tok string) (*User, string) {
	if !strings.HasPrefix(tok, "kbs_") {
		return nil, ""
	}
	var u User
	var csrf string
	err := s.db.QueryRow(`SELECT u.id,u.name,w.csrf FROM web_sessions w JOIN users u ON u.id=w.user_id WHERE w.hash=? AND w.expires_at>?`, Hash(tok), time.Now().Unix()).Scan(&u.ID, &u.Name, &csrf)
	if err != nil {
		return nil, ""
	}
	return &u, csrf
}

func (s *Store) Logout(tok string) {
	_, _ = s.db.Exec(`DELETE FROM web_sessions WHERE hash=?`, Hash(tok))
}

// limiter counts failures per key in a sliding window (login, enrollment).
// Reserve takes an attempt before the expensive or secret-dependent work,
// so concurrent requests cannot all pass a check that none has recorded yet.
type limiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	hits   map[string][]time.Time
}

func newLimiter(max int, window time.Duration) *limiter {
	return &limiter{max: max, window: window, hits: map[string][]time.Time{}}
}

// limiterSweepAt bounds the map: past this many keys, a reservation first
// drops every key whose window has passed.
const limiterSweepAt = 4096

// reservation is one attempt counted against its keys. Refund takes it
// back (the attempt succeeded, or was never made).
type reservation struct {
	l    *limiter
	keys []string
	at   time.Time
	once sync.Once
}

func (r *reservation) Refund() {
	if r == nil {
		return // nothing was reserved
	}
	r.once.Do(func() {
		r.l.mu.Lock()
		defer r.l.mu.Unlock()
		for _, k := range r.keys {
			h := r.l.hits[k]
			for i := len(h) - 1; i >= 0; i-- {
				if h[i].Equal(r.at) {
					h = append(h[:i], h[i+1:]...)
					break
				}
			}
			if len(h) == 0 {
				delete(r.l.hits, k)
			} else {
				r.l.hits[k] = h
			}
		}
	})
}

// Reserve counts one attempt against every key, atomically, if all of
// them are under the limit; otherwise it counts nothing and returns nil.
func (l *limiter) Reserve(keys ...string) *reservation {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.hits) > limiterSweepAt {
		for k := range l.hits {
			l.prune(k)
		}
	}
	for _, k := range keys {
		if len(l.prune(k)) >= l.max {
			return nil
		}
	}
	now := time.Now()
	for _, k := range keys {
		l.hits[k] = append(l.hits[k], now)
	}
	return &reservation{l: l, keys: keys, at: now}
}

func (l *limiter) prune(key string) []time.Time {
	h := l.hits[key]
	i := 0
	for i < len(h) && time.Since(h[i]) > l.window {
		i++
	}
	h = h[i:]
	if len(h) == 0 {
		delete(l.hits, key)
	} else {
		l.hits[key] = h
	}
	return h
}
