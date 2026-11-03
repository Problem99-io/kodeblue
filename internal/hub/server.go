package hub

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
	"github.com/Problem99-io/kodeblue/internal/blue/upgrade"
)

//go:embed web
var webFS embed.FS

type Options struct {
	DisableIPEnrichment bool
	DataDir             string
	DistDir             string // agent release files served to installers
	PublicURL           string // how servers and browsers reach the hub (for install commands)
	Pin                 string // TLS public-key pin, when the hub's certificate is self-signed
	// SecureCookies is true whenever browsers reach the hub over https
	// (direct TLS, or a TLS-terminating proxy).
	SecureCookies bool
	// BehindProxy trusts X-Forwarded-For, but only on connections from
	// TrustedProxies (default: loopback, a proxy on the same host).
	BehindProxy    bool
	TrustedProxies []netip.Prefix
	// ConsoleAllow, when set, limits the console and operator API to these
	// client addresses; everyone else gets 404. The agent API, installer
	// and release files stay reachable for servers.
	ConsoleAllow []netip.Prefix
	// EndpointAllow lists addresses the hub may reach model endpoints at
	// although they are loopback, link-local or cloud metadata (see egress.go).
	EndpointAllow []netip.Prefix
	EnrollTTL     time.Duration
	SessionTTL    time.Duration
}

type Server struct {
	war warLifecycle
	opt Options
	st  *Store
	log *slog.Logger
	mux *http.ServeMux
	// Sign-in failures are limited per client address (an IPv6 /64 counts
	// as one) and per user name; hashCheck bounds the PBKDF2 work running at
	// once, so a burst of sign-ins cannot starve the rest of the hub.
	login      *limiter
	loginUser  *limiter
	hashCheck  chan struct{}
	knownCheck chan struct{} // one more check slot for browsers signed in from before
	enrol      *limiter
	// trusted are the proxies whose X-Forwarded-For is believed.
	trusted []netip.Prefix

	mu                sync.Mutex
	waiters           map[string]chan struct{} // server id -> wake long-poll
	slackWake         chan struct{}
	telegramWake      chan struct{}
	slackReset        chan struct{}
	telegramReset     chan struct{}
	models            modelCache
	telegramTestLimit *limiter

	distMu   sync.Mutex
	distSnap *distSnapshot

	decideMu sync.Mutex // handleDecision: check for an open ruling and queue one

	deviceOnce sync.Once
	devKey     []byte
}

func NewServer(opt Options, st *Store, logger *slog.Logger) *Server {
	if opt.EnrollTTL <= 0 {
		opt.EnrollTTL = 2 * time.Hour
	}
	if opt.SessionTTL <= 0 {
		opt.SessionTTL = 12 * time.Hour
	}
	s := &Server{opt: opt, st: st, log: logger, mux: http.NewServeMux(), login: newLimiter(loginMaxPerAddr, 15*time.Minute),
		loginUser: newLimiter(loginMaxPerUser, 15*time.Minute), hashCheck: make(chan struct{}, max(1, runtime.NumCPU()/2)), knownCheck: make(chan struct{}, 1),
		enrol: newLimiter(20, 10*time.Minute), waiters: map[string]chan struct{}{}, slackWake: make(chan struct{}, 1), telegramWake: make(chan struct{}, 1), slackReset: make(chan struct{}, 1), telegramReset: make(chan struct{}, 1)}
	s.models.client = endpointClient(opt.EndpointAllow)
	s.telegramTestLimit = newLimiter(3, time.Minute)
	s.trusted = opt.TrustedProxies
	if len(s.trusted) == 0 {
		s.trusted = loopbackProxies
	}
	s.routes()
	return s
}

func (s *Server) Handler() http.Handler { return s.secure(s.consoleGate(s.mux)) }

// Janitor prunes old data until ctx ends.
func (s *Server) Janitor(ctx context.Context) {
	t := time.NewTicker(6 * time.Hour)
	defer t.Stop()
	for {
		s.st.Prune(90 * 24 * time.Hour)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Server) routes() {
	m := s.mux
	// Agent API: server API key (Bearer kbk_…), or the one-time token for enroll.
	m.HandleFunc("POST "+hubproto.PathEnroll, s.handleEnroll)
	m.HandleFunc("POST "+hubproto.PathSync, s.agent(s.handleSync))
	m.HandleFunc("GET "+hubproto.PathMessages, s.agent(s.handlePoll))
	m.HandleFunc("POST "+hubproto.PathMessages+"/{id}/reply", s.agent(s.handleReply))

	// Installer: the script is public (it holds no secrets); release files
	// need a live enrollment token, a server key, or an operator session.
	m.HandleFunc("GET /install.sh", s.handleInstallScript)
	m.HandleFunc("GET /dist/{file}", s.handleDist)

	// Operator API (cookie session; state changes also need the CSRF header).
	m.HandleFunc("POST /api/login", s.handleLogin)
	m.HandleFunc("POST /api/logout", s.op(s.handleLogout))
	m.HandleFunc("GET /api/me", s.op(s.handleMe))
	m.HandleFunc("GET /api/fleet", s.op(s.handleFleet))
	m.HandleFunc("POST /api/servers", s.op(s.handleCreateServer))
	m.HandleFunc("GET /api/servers/{id}", s.op(s.handleServer))
	m.HandleFunc("PATCH /api/servers/{id}", s.op(s.handleRenameServer))
	m.HandleFunc("DELETE /api/servers/{id}", s.op(s.handleDeleteServer))
	m.HandleFunc("POST /api/servers/{id}/enroll-token", s.op(s.handleEnrollToken))
	m.HandleFunc("POST /api/servers/{id}/revoke", s.op(s.handleRevoke))
	m.HandleFunc("GET /api/servers/{id}/records/{kind}", s.op(s.handleRecords))
	m.HandleFunc("GET /api/servers/{id}/records/{kind}/{rid}", s.op(s.handleRecord))
	m.HandleFunc("GET /api/servers/{id}/messages", s.op(s.handleMessages))
	m.HandleFunc("POST /api/servers/{id}/messages", s.op(s.handleSendMessage))
	m.HandleFunc("POST /api/servers/{id}/actions/{rid}/decision", s.op(s.handleDecision))
	m.HandleFunc("POST /api/servers/{id}/learn", s.op(s.handleLearn))
	m.HandleFunc("POST /api/servers/{id}/upgrade", s.op(s.handleUpgrade))
	m.HandleFunc("POST /api/servers/{id}/stop-session", s.op(s.handleStop))
	m.HandleFunc("POST /api/servers/{id}/vulnerabilities/{rid}", s.op(s.handleVuln))
	m.HandleFunc("POST /api/servers/{id}/rules/{rid}", s.op(s.handleRule))
	m.HandleFunc("GET /api/tasks", s.op(s.handleTasks))
	m.HandleFunc("POST /api/cases/state", s.op(s.handleCaseState))
	m.HandleFunc("GET /api/audit", s.op(s.handleAudit))
	s.warRoutes()
	s.slackRoutes()
	s.settingsRoutes()

	// Console.
	sub, _ := fs.Sub(webFS, "web")
	files := http.FileServerFS(sub)
	// Embedded files carry no modification time; make browsers revalidate so
	// a hub upgrade never runs a stale console script.
	m.Handle("GET /assets/", http.StripPrefix("/assets/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		files.ServeHTTP(w, r)
	})))
	m.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		b, _ := webFS.ReadFile("web/index.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(b)
	})
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok\n")) })
}

// secure adds headers that confine the console: no inline script, no
// framing, no third-party origins, no referrers.
func (s *Server) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if s.opt.SecureCookies {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// ---- helpers ----

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func readJSON(w http.ResponseWriter, r *http.Request, limit int64, v any) error {
	// JSON only: a cross-site HTML form cannot send application/json without
	// a CORS preflight, which this server never grants.
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		return errors.New("content-type must be application/json")
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		return err
	}
	return nil
}

func bearer(r *http.Request) string {
	a := r.Header.Get("Authorization")
	if t, ok := strings.CutPrefix(a, "Bearer "); ok {
		return strings.TrimSpace(t)
	}
	return ""
}

// ---- agent side ----

func (s *Server) agent(h func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		srv := s.st.ServerByKey(bearer(r))
		if srv == nil {
			// Same response for unknown, revoked and malformed keys.
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		s.st.Seen(srv.ID, s.clientIP(r))
		h(w, r, srv.ID)
	}
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	var req hubproto.EnrollRequest
	if err := readJSON(w, r, 16<<10, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	// The attempt counts before the token is checked; a success takes it back.
	rsv := s.enrol.Reserve(throttleKey(s.clientAddr(r), ip))
	if rsv == nil {
		writeErr(w, http.StatusTooManyRequests, "too many enrollment attempts; wait a few minutes")
		return
	}
	srv, key, err := s.st.Enroll(strings.TrimSpace(req.Token), req.Hostname, req.Version)
	if err != nil {
		s.st.Audit("anonymous", "enroll.failed", "", "", ip)
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}
	rsv.Refund()
	s.st.Audit("server:"+srv.Name, "enroll", srv.ID, "hostname "+trim(req.Hostname, 100), ip)
	s.log.Info("server enrolled", "server", srv.ID, "name", srv.Name, "ip", ip)
	resp := hubproto.EnrollResponse{ServerID: srv.ID, Name: srv.Name, APIKey: key}
	// The fleet's default model and its connection become the server's own
	// endpoint, so it has models before its first settings sync.
	if ref, conn, ok := s.st.fleetDefaultModel(); ok {
		resp.InferenceKey = conn.APIKey
		resp.Inference = &hubproto.InferenceDefaults{BaseURL: conn.BaseURL, Provider: ref.Provider, Model: ref.Model}
		if ref.Provider == "" {
			resp.Inference.Provider = hubproto.DefaultProvider(conn.Kind)
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleSync(w http.ResponseWriter, r *http.Request, id string) {
	var req hubproto.SyncRequest
	if err := readJSON(w, r, hubproto.MaxSyncBytes, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad sync body")
		return
	}
	added, err := s.st.ApplySyncNotify(id, &req)
	if added {
		s.wakeSlack()
	}
	if err != nil {
		s.log.Error("apply sync", "server", id, "error", err)
		writeErr(w, http.StatusInternalServerError, "store failed")
		return
	}
	resp := hubproto.SyncResponse{OK: true, ServerTime: time.Now().UTC(), Pending: s.st.QueuedCount(id)}
	// Settings travel only when the server takes them and has another version.
	if req.Status.AcceptsSettings {
		if eff := s.st.EffectiveSettings(id); eff.Version != req.Status.SettingsVersion {
			resp.Settings = eff
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) waiter(id string) chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch, ok := s.waiters[id]
	if !ok {
		ch = make(chan struct{})
		s.waiters[id] = ch
	}
	return ch
}

func (s *Server) wake(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ch, ok := s.waiters[id]; ok {
		close(ch)
		delete(s.waiters, id)
	}
}

// handlePoll is the long-poll the agent keeps open for operator messages.
func (s *Server) handlePoll(w http.ResponseWriter, r *http.Request, id string) {
	wait, _ := strconv.Atoi(r.URL.Query().Get("wait"))
	wait = min(max(wait, 0), 55)
	deadline := time.After(time.Duration(wait) * time.Second)
	for {
		ch := s.waiter(id)
		if msgs := s.st.TakeQueued(id); len(msgs) > 0 {
			out := hubproto.MessagesResponse{}
			for _, m := range msgs {
				out.Messages = append(out.Messages, hubproto.OperatorMessage{ID: m.ID, Author: m.Author, Body: m.Body, IncidentID: m.IncidentID,
					ConversationID: m.ConversationID, CreatedAt: m.CreatedAt, Decision: m.Decision, RequestID: m.RequestID, Command: m.Command, SessionID: m.SessionID, RuleHash: m.RuleHash})
			}
			writeJSON(w, http.StatusOK, out)
			return
		}
		select {
		case <-ch:
		case <-deadline:
			writeJSON(w, http.StatusOK, hubproto.MessagesResponse{})
			return
		case <-r.Context().Done():
			return
		}
	}
}

func (s *Server) handleReply(w http.ResponseWriter, r *http.Request, id string) {
	mid, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	var rep hubproto.MessageReply
	if err := readJSON(w, r, 256<<10, &rep); err != nil {
		writeErr(w, http.StatusBadRequest, "bad body")
		return
	}
	if err := s.st.Reply(id, mid, rep); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---- installer ----

// handleInstallScript serves install.sh with the tarball hashes pinned in
// (dist.go), byte for byte what the install command's hash was taken of.
func (s *Server) handleInstallScript(w http.ResponseWriter, r *http.Request) {
	snap := s.dist()
	if snap.script == nil {
		writeErr(w, http.StatusNotFound, "no installer published on this hub (see docs: build-dist)")
		return
	}
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	_, _ = w.Write(snap.script)
}

func (s *Server) handleDist(w http.ResponseWriter, r *http.Request) {
	tok := bearer(r)
	ok := s.st.ValidEnrollToken(tok) || s.st.ServerByKey(tok) != nil
	if !ok {
		if c, err := r.Cookie(s.cookieName()); err == nil {
			u, _ := s.st.Session(c.Value)
			ok = u != nil
		}
	}
	if !ok {
		writeErr(w, http.StatusUnauthorized, "release files need an enrollment token, a server key, or an operator session")
		return
	}
	name := r.PathValue("file")
	if name != filepath.Base(name) || strings.HasPrefix(name, ".") {
		writeErr(w, http.StatusBadRequest, "bad file")
		return
	}
	f, err := os.Open(filepath.Join(s.opt.DistDir, name))
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	defer f.Close()
	st, _ := f.Stat()
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, name, st.ModTime(), f)
}

// InstallCommand is the one-liner shown when a server is added. It saves
// install.sh, checks it against the hash the hub pinned (the script in turn
// pins the tarballs), and only then runs it as root. The token goes in
// installer's stdin (--token-file -) when it reads it from there, so it is in
// no process's argv (printf is a shell builtin); older installers get --token.
func (s *Server) InstallCommand(r *http.Request, token string) string {
	return s.InstallCommandWith(r, token, false)
}

// InstallCommandWith is InstallCommand; hubContain adds --hub-max-mode
// contain, so the hub may switch the new server to contain (the installer
// writes it to the server's root-owned config).
func (s *Server) InstallCommandWith(r *http.Request, token string, hubContain bool) string {
	base := shq(s.publicURL(r))
	curl := "curl -fsSL"
	if strings.HasPrefix(s.publicURL(r), "https://") {
		curl += " --proto =https --proto-redir =https" // no downgrade, redirects included
	}
	extra := ""
	if s.opt.Pin != "" {
		curl += " -k --pinnedpubkey " + shq(s.opt.Pin)
		extra = " --pin " + shq(s.opt.Pin)
	}
	snap := s.dist()
	if hubContain && (snap.script == nil || snap.hubMaxMode) {
		extra += " --hub-max-mode contain"
	}
	if snap.script == nil {
		// No installer published yet: the plain form, whose download fails
		// with the hub's explanation.
		return fmt.Sprintf("%s %s/install.sh | sudo sh -s -- --hub %s%s --token %s", curl, base, base, extra, shq(token))
	}
	// $r is sudo, or nothing for root: root on a minimal server may have no sudo.
	run := fmt.Sprintf(`$r sh "$f" --hub %s%s --token %s`, base, extra, shq(token))
	if snap.tokenStdin {
		run = fmt.Sprintf(`printf '%%s\n' %s | $r sh "$f" --hub %s%s --token-file -`, shq(token), base, extra)
	}
	// The braces keep the installer's exit status past the cleanup.
	return fmt.Sprintf(`f=$(mktemp) && r=$([ "$(id -u)" = 0 ] || echo sudo) && { %s -o "$f" %s/install.sh && echo "%s  $f" | sha256sum -c - && %s; s=$?; rm -f "$f"; (exit "$s"); }`, curl, base, snap.sum, run)
}

func (s *Server) publicURL(r *http.Request) string {
	if s.opt.PublicURL != "" {
		return strings.TrimRight(s.opt.PublicURL, "/")
	}
	scheme := "http"
	if r.TLS != nil || s.opt.SecureCookies {
		scheme = "https"
	}
	u := url.URL{Scheme: scheme, Host: r.Host}
	return u.String()
}

// ---- operator side ----

type opCtx struct {
	user *User
	csrf string
	tok  string
	ip   string
}

func (s *Server) cookieName() string {
	if s.opt.SecureCookies {
		return "__Host-kodeblue"
	}
	return "kodeblue"
}

func (s *Server) op(h func(http.ResponseWriter, *http.Request, *opCtx)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(s.cookieName())
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "sign in required")
			return
		}
		u, csrf := s.st.Session(c.Value)
		if u == nil {
			writeErr(w, http.StatusUnauthorized, "sign in required")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			// Double protection against cross-site requests: SameSite=Strict
			// cookie plus a per-session token only our own script can read.
			if got := r.Header.Get("X-Kodeblue-CSRF"); got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(csrf)) != 1 {
				writeErr(w, http.StatusForbidden, "missing or bad CSRF token")
				return
			}
		}
		h(w, r, &opCtx{user: u, csrf: csrf, tok: c.Value, ip: s.clientIP(r)})
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name     string `json:"name"`
		Password string `json:"password"`
	}
	if err := readJSON(w, r, 4<<10, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	ip := s.clientIP(r)
	if len(req.Name) > 64 || len(req.Password) > 1024 {
		writeErr(w, http.StatusUnauthorized, "invalid user name or password")
		return
	}
	// Each attempt is counted before the password is checked, so a burst of
	// concurrent guesses gets no more tries than a sequence would.
	byAddr := s.login.Reserve(throttleKey(s.clientAddr(r), ip))
	if byAddr == nil {
		writeErr(w, http.StatusTooManyRequests, "too many failed sign-ins; wait 15 minutes")
		return
	}
	// The per-user limit stops guessing spread over many addresses, but
	// anyone could use it to lock an operator out; a browser this user
	// signed in from before (signed device cookie) is exempt from it.
	known := s.knownDevice(r, req.Name)
	var byUser *reservation
	if !known {
		if byUser = s.loginUser.Reserve(req.Name); byUser == nil {
			byAddr.Refund()
			writeErr(w, http.StatusTooManyRequests, "too many failed sign-ins for this user; wait 15 minutes")
			return
		}
	}
	// Bound the PBKDF2 work running at once; past a short wait the hub
	// answers busy instead of queueing CPU it does not have. Known browsers
	// also have a slot of their own, so a flood from many addresses cannot
	// keep an operator out.
	var reserved, slot chan struct{} // reserved stays nil (never ready) for others
	if known {
		reserved = s.knownCheck
	}
	select {
	case s.hashCheck <- struct{}{}:
		slot = s.hashCheck
	case reserved <- struct{}{}:
		slot = reserved
	case <-time.After(loginQueueWait):
		byAddr.Refund()
		byUser.Refund()
		w.Header().Set("Retry-After", "5")
		writeErr(w, http.StatusServiceUnavailable, "the hub is busy checking sign-ins; try again in a few seconds")
		return
	case <-r.Context().Done():
		byAddr.Refund()
		byUser.Refund()
		return
	}
	u, tok, csrf, err := s.st.Login(req.Name, req.Password, ip, s.opt.SessionTTL)
	<-slot
	if err != nil {
		s.st.Audit(trim(req.Name, 64), "login.failed", "", "", ip)
		writeErr(w, http.StatusUnauthorized, "invalid user name or password")
		return
	}
	byAddr.Refund() // only failures count
	byUser.Refund()
	http.SetCookie(w, &http.Cookie{Name: s.cookieName(), Value: tok, Path: "/", HttpOnly: true, Secure: s.opt.SecureCookies,
		SameSite: http.SameSiteStrictMode, MaxAge: int(s.opt.SessionTTL.Seconds())})
	http.SetCookie(w, &http.Cookie{Name: s.deviceCookieName(), Value: s.deviceToken(req.Name), Path: "/", HttpOnly: true, Secure: s.opt.SecureCookies,
		SameSite: http.SameSiteStrictMode, MaxAge: int(deviceTTL.Seconds())})
	s.st.Audit(u.Name, "login", "", "", ip)
	writeJSON(w, http.StatusOK, map[string]any{"user": u, "csrf": csrf})
}

// Sign-in limits: failures allowed per 15 minutes from one client address,
// and against one user name from anywhere; how long a sign-in waits for a
// free password check before the hub answers busy.
const (
	loginMaxPerAddr = 8
	loginMaxPerUser = 24
	loginQueueWait  = 2 * time.Second
)

// settingDeviceKey holds the device-cookie signing key (hex).
const settingDeviceKey = "device_cookie_key"

// deviceTTL is how long a browser counts as one its user signed in from.
const deviceTTL = 180 * 24 * time.Hour

func (s *Server) deviceCookieName() string { return s.cookieName() + "-device" }

// deviceKey signs device cookies; it lives in the database so devices stay
// known across restarts.
func (s *Server) deviceKey() []byte {
	s.deviceOnce.Do(func() {
		k, err := hex.DecodeString(s.st.Setting(settingDeviceKey))
		if err != nil || len(k) != 32 {
			k = make([]byte, 32)
			_, _ = rand.Read(k)
			_ = s.st.SetSetting(settingDeviceKey, hex.EncodeToString(k))
		}
		s.devKey = k
	})
	return s.devKey
}

// deviceToken marks a browser as one name signed in from: the name and an
// HMAC of it. It grants nothing but the per-user limit exemption.
func (s *Server) deviceToken(name string) string {
	m := hmac.New(sha256.New, s.deviceKey())
	m.Write([]byte("kodeblue-device\x00" + name))
	return base64.RawURLEncoding.EncodeToString([]byte(name)) + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (s *Server) knownDevice(r *http.Request, name string) bool {
	c, err := r.Cookie(s.deviceCookieName())
	return err == nil && name != "" && hmac.Equal([]byte(c.Value), []byte(s.deviceToken(name)))
}

// throttleKey is the bucket a client's attempts count in: its address, or
// for IPv6 its /64, which one client usually holds whole.
func throttleKey(a netip.Addr, fallback string) string {
	if !a.IsValid() {
		return fallback
	}
	if a.Is6() && !a.Is4In6() {
		p, _ := a.Prefix(64)
		return p.String()
	}
	return a.String()
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, c *opCtx) {
	s.st.Logout(c.tok)
	http.SetCookie(w, &http.Cookie{Name: s.cookieName(), Value: "", Path: "/", HttpOnly: true, Secure: s.opt.SecureCookies, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request, c *opCtx) {
	writeJSON(w, http.StatusOK, map[string]any{"user": c.user, "csrf": c.csrf, "pin": s.opt.Pin,
		"fleet_model": s.fleetModelName(), "slack": s.st.SlackSettings().Configured, "telegram": s.st.TelegramSettings().Configured, "version": hubproto.Version})
}

type fleetRow struct {
	Host
	Online bool   `json:"online"`
	Counts Counts `json:"counts"`
}

func (s *Server) handleFleet(w http.ResponseWriter, r *http.Request, c *opCtx) {
	out := []fleetRow{}
	for _, srv := range s.st.Servers() {
		out = append(out, fleetRow{Host: srv, Online: online(srv), Counts: s.st.Counts(srv.ID)})
	}
	writeJSON(w, http.StatusOK, out)
}

func online(srv Host) bool {
	return !srv.Revoked && srv.Enrolled && time.Since(srv.LastSeen) < 2*time.Minute
}

func (s *Server) handleCreateServer(w http.ResponseWriter, r *http.Request, c *opCtx) {
	var req struct {
		Name       string `json:"name"`
		HubContain bool   `json:"hub_contain"`
	}
	if err := readJSON(w, r, 4<<10, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	srv, tok, err := s.st.CreateServer(req.Name, c.user.Name, s.opt.EnrollTTL)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	what := srv.Name
	if req.HubContain {
		what += " (install command lets the hub switch it to contain)"
	}
	s.st.Audit(c.user.Name, "server.create", srv.ID, what, c.ip)
	writeJSON(w, http.StatusOK, map[string]any{"server": srv, "token": tok, "expires": srv.EnrollExpires, "install_command": s.InstallCommandWith(r, tok, req.HubContain)})
}

func (s *Server) serverOr404(w http.ResponseWriter, r *http.Request) *Host {
	srv := s.st.GetServer(r.PathValue("id"))
	if srv == nil {
		writeErr(w, http.StatusNotFound, "server not found")
	}
	return srv
}

func (s *Server) handleServer(w http.ResponseWriter, r *http.Request, c *opCtx) {
	srv := s.serverOr404(w, r)
	if srv == nil {
		return
	}
	writeJSON(w, http.StatusOK, fleetRow{Host: *srv, Online: online(*srv), Counts: s.st.Counts(srv.ID)})
}

func (s *Server) handleRenameServer(w http.ResponseWriter, r *http.Request, c *opCtx) {
	srv := s.serverOr404(w, r)
	if srv == nil {
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := readJSON(w, r, 4<<10, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	if err := s.st.RenameServer(srv.ID, req.Name); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.st.Audit(c.user.Name, "server.rename", srv.ID, srv.Name+" -> "+req.Name, c.ip)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleDeleteServer(w http.ResponseWriter, r *http.Request, c *opCtx) {
	srv := s.serverOr404(w, r)
	if srv == nil {
		return
	}
	if err := s.st.DeleteServer(srv.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.st.Audit(c.user.Name, "server.delete", srv.ID, srv.Name, c.ip)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleEnrollToken(w http.ResponseWriter, r *http.Request, c *opCtx) {
	srv := s.serverOr404(w, r)
	if srv == nil {
		return
	}
	var req struct {
		HubContain bool `json:"hub_contain"`
	}
	_ = readJSON(w, r, 4<<10, &req) // an empty body is fine
	tok, err := s.st.NewEnrollToken(srv.ID, s.opt.EnrollTTL)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.st.Audit(c.user.Name, "server.enroll_token", srv.ID, srv.Name, c.ip)
	writeJSON(w, http.StatusOK, map[string]any{"token": tok, "expires": time.Now().Add(s.opt.EnrollTTL), "install_command": s.InstallCommandWith(r, tok, req.HubContain)})
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request, c *opCtx) {
	srv := s.serverOr404(w, r)
	if srv == nil {
		return
	}
	if err := s.st.Revoke(srv.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.st.Audit(c.user.Name, "server.revoke", srv.ID, srv.Name, c.ip)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleRecords(w http.ResponseWriter, r *http.Request, c *opCtx) {
	srv := s.serverOr404(w, r)
	if srv == nil {
		return
	}
	kind := r.PathValue("kind")
	if !syncKinds[kind] {
		writeErr(w, http.StatusBadRequest, "unknown kind")
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	var since time.Time
	if h, _ := strconv.Atoi(q.Get("since_hours")); h > 0 {
		since = time.Now().Add(-time.Duration(h) * time.Hour)
	}
	writeJSON(w, http.StatusOK, s.st.Records(srv.ID, kind, q.Get("q"), since, limit))
}

func (s *Server) handleRecord(w http.ResponseWriter, r *http.Request, c *opCtx) {
	srv := s.serverOr404(w, r)
	if srv == nil {
		return
	}
	rec := s.st.Record(srv.ID, r.PathValue("kind"), r.PathValue("rid"))
	if rec == nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

func (s *Server) handleMessages(w http.ResponseWriter, r *http.Request, c *opCtx) {
	srv := s.serverOr404(w, r)
	if srv == nil {
		return
	}
	writeJSON(w, http.StatusOK, s.st.Messages(srv.ID, 200))
}

func (s *Server) handleSendMessage(w http.ResponseWriter, r *http.Request, c *opCtx) {
	srv := s.serverOr404(w, r)
	if srv == nil {
		return
	}
	var req struct {
		Body           string `json:"body"`
		IncidentID     int64  `json:"incident_id"`
		ConversationID string `json:"conversation_id"`
	}
	if err := readJSON(w, r, 64<<10, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	req.Body = strings.TrimSpace(req.Body)
	if req.Body == "" || len(req.Body) > 8000 {
		writeErr(w, http.StatusBadRequest, "message must be 1-8000 characters")
		return
	}
	if req.ConversationID != "" && (len(req.ConversationID) > 40 || !strings.HasPrefix(req.ConversationID, "c_")) {
		writeErr(w, http.StatusBadRequest, "bad conversation id")
		return
	}
	if !srv.Enrolled || srv.Revoked {
		writeErr(w, http.StatusConflict, "server is not connected to the hub")
		return
	}
	m := &Message{ServerID: srv.ID, Author: c.user.Name, Body: req.Body, IncidentID: req.IncidentID, ConversationID: req.ConversationID}
	if err := s.st.AddMessage(m); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.st.Audit(c.user.Name, "message.send", srv.ID, trim(req.Body, 300), c.ip)
	s.wake(srv.ID)
	writeJSON(w, http.StatusOK, m)
}

// handleTasks is the console's task board: every incident record (incident,
// learning, review, operator) across the fleet, or one server with ?server=,
// plus the operator messages needed to show queued and unanswered ones.
func (s *Server) handleTasks(w http.ResponseWriter, r *http.Request, c *opCtx) {
	server := r.URL.Query().Get("server")
	var msgs []Message
	if server != "" {
		if s.st.GetServer(server) == nil {
			writeErr(w, http.StatusNotFound, "server not found")
			return
		}
		msgs = s.st.Messages(server, 200)
	} else {
		msgs = s.st.AllMessages(300)
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 2000 {
		limit = 500
	}
	writeJSON(w, http.StatusOK, map[string]any{"tasks": s.st.Tasks(server, limit), "messages": msgs, "approvals": s.st.PendingApprovals(server)})
}

// handleDecision approves or denies a containment request an agent recorded
// under recommend mode. The hub only relays the ruling: the server checks the
// request is still pending and runs it through its root helper and policy.
func (s *Server) handleDecision(w http.ResponseWriter, r *http.Request, c *opCtx) {
	srv := s.serverOr404(w, r)
	if srv == nil {
		return
	}
	var req struct {
		Decision string `json:"decision"`
	}
	if err := readJSON(w, r, 4<<10, &req); err != nil || (req.Decision != "approve" && req.Decision != "deny") {
		writeErr(w, http.StatusBadRequest, "decision must be approve or deny")
		return
	}
	rid := r.PathValue("rid")
	rec := s.st.Record(srv.ID, "pending_action", rid)
	if rec == nil {
		writeErr(w, http.StatusNotFound, "no pending containment request "+rid+" on this server")
		return
	}
	if !srv.Enrolled || srv.Revoked {
		writeErr(w, http.StatusConflict, "server is not connected to the hub")
		return
	}
	var st struct {
		AcceptsApprovals bool `json:"accepts_approvals"`
	}
	_ = json.Unmarshal(srv.Status, &st)
	if !st.AcceptsApprovals {
		writeErr(w, http.StatusConflict, "this server does not take approvals from the hub (update kodeblue, or hub.accept_approvals is false): run kodeblue respond "+req.Decision+" "+rid+" on the server")
		return
	}
	// Check and queue as one step: two rulings sent at once (Approve all in
	// one tab, a click in another) must not both be queued.
	s.decideMu.Lock()
	defer s.decideMu.Unlock()
	if m := s.st.OpenDecision(srv.ID, rid); m != nil {
		writeErr(w, http.StatusConflict, m.Author+" already sent "+m.Decision+" for "+rid)
		return
	}
	var pa struct {
		IncidentID    int64             `json:"incident_id"`
		Action        string            `json:"action"`
		Params        map[string]string `json:"params"`
		Justification string            `json:"justification"`
	}
	_ = json.Unmarshal(rec.Data, &pa)
	params := make([]string, 0, len(pa.Params))
	for k, v := range pa.Params {
		params = append(params, k+"="+v)
	}
	sort.Strings(params)
	verb := map[string]string{"approve": "Approve", "deny": "Deny"}[req.Decision]
	m := &Message{ServerID: srv.ID, Author: c.user.Name, IncidentID: pa.IncidentID, Decision: req.Decision, RequestID: rid,
		Body: trim(fmt.Sprintf("%s containment %s: %s %s", verb, rid, pa.Action, strings.Join(params, " ")), 2000)}
	if err := s.st.AddMessage(m); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.st.Audit(c.user.Name, "action."+req.Decision, srv.ID, m.Body, c.ip)
	s.wake(srv.ID)
	writeJSON(w, http.StatusOK, m)
}

// handleLearn asks a server to run the learner again ("learn") or to relearn
// its whole baseline ("relearn"). Like a decision, the hub only relays it:
// the server runs it without a model, if [hub] accept_learning allows.
func (s *Server) handleLearn(w http.ResponseWriter, r *http.Request, c *opCtx) {
	srv := s.serverOr404(w, r)
	if srv == nil {
		return
	}
	var req struct {
		Mode string `json:"mode"`
	}
	if err := readJSON(w, r, 4<<10, &req); err != nil || (req.Mode != hubproto.CommandLearn && req.Mode != hubproto.CommandRelearn) {
		writeErr(w, http.StatusBadRequest, "mode must be learn or relearn")
		return
	}
	if !srv.Enrolled || srv.Revoked {
		writeErr(w, http.StatusConflict, "server is not connected to the hub")
		return
	}
	var st struct {
		AcceptsLearning bool `json:"accepts_learning"`
		Learning        bool `json:"learning"`
		ModelsEnabled   bool `json:"models_enabled"`
	}
	_ = json.Unmarshal(srv.Status, &st)
	switch {
	case !st.AcceptsLearning:
		writeErr(w, http.StatusConflict, "this server does not take learning commands from the hub (update kodeblue, or hub.accept_learning is false): run kodeblue relearn on the server and restart kodeblue")
		return
	case st.Learning:
		writeErr(w, http.StatusConflict, "learning is already running on this server")
		return
	case req.Mode == hubproto.CommandLearn && !st.ModelsEnabled:
		writeErr(w, http.StatusConflict, "the learner needs models, which are off on this server; pick models in Settings, or relearn to collect the baseline only")
		return
	}
	if m := s.st.OpenCommand(srv.ID); m != nil {
		writeErr(w, http.StatusConflict, m.Author+" already sent "+m.Command+"; waiting for the server")
		return
	}
	body := map[string]string{hubproto.CommandLearn: "Run the learner on the current baseline", hubproto.CommandRelearn: "Relearn the baseline, then run the learner"}[req.Mode]
	m := &Message{ServerID: srv.ID, Author: c.user.Name, Command: req.Mode, Body: body}
	if err := s.st.AddMessage(m); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.st.Audit(c.user.Name, "learning."+req.Mode, srv.ID, body, c.ip)
	s.wake(srv.ID)
	writeJSON(w, http.StatusOK, m)
}

// handleUpgrade asks a server to upgrade kodeblue to the hub's own version.
// It is the only way an upgrade starts from the hub: one operator click per
// server, never on its own. The hub names the version and nothing else; the
// server downloads that release from its own release URL, checks it against
// the release's SHA256SUMS and installs it once no learning or agent session
// runs, if its root-owned config accepts upgrades from the hub.
func (s *Server) handleUpgrade(w http.ResponseWriter, r *http.Request, c *opCtx) {
	srv := s.serverOr404(w, r)
	if srv == nil {
		return
	}
	to := hubproto.Version
	if !upgrade.Valid(to) {
		writeErr(w, http.StatusConflict, "this hub runs a development build ("+to+"), not a release: servers upgrade only to a released version")
		return
	}
	if !srv.Enrolled || srv.Revoked {
		writeErr(w, http.StatusConflict, "server is not connected to the hub")
		return
	}
	var st struct {
		Version         string                  `json:"version"`
		AcceptsUpgrades bool                    `json:"accepts_upgrades"`
		Upgrade         *hubproto.UpgradeStatus `json:"upgrade"`
	}
	_ = json.Unmarshal(srv.Status, &st)
	if err := upgrade.Check(to, st.Version); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	switch {
	case !st.AcceptsUpgrades:
		writeErr(w, http.StatusConflict, "this server does not take upgrades from the hub (it runs a kodeblue older than v0.1.7, or hub.accept_upgrades is false): run on the server: sudo kodeblue upgrade "+to+", or the install command without a token")
		return
	case st.Upgrade != nil && st.Upgrade.To == to && (st.Upgrade.State == upgrade.Waiting || st.Upgrade.State == upgrade.Installing):
		writeErr(w, http.StatusConflict, "the upgrade to "+to+" is already "+st.Upgrade.State)
		return
	}
	if m := s.st.OpenUpgrade(srv.ID); m != nil {
		writeErr(w, http.StatusConflict, m.Author+" already asked for an upgrade; waiting for the server")
		return
	}
	body := to
	m := &Message{ServerID: srv.ID, Author: c.user.Name, Command: hubproto.CommandUpgrade, Body: body}
	if err := s.st.AddMessage(m); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.st.Audit(c.user.Name, "upgrade", srv.ID, st.Version+" -> "+to, c.ip)
	s.wake(srv.ID)
	writeJSON(w, http.StatusOK, m)
}

// handleStop asks a server to abort a running agent session. It is a safety
// brake, always allowed on a connected server (not gated by accept_learning):
// the server aborts the named session and resolves its case as unfinished.
func (s *Server) handleStop(w http.ResponseWriter, r *http.Request, c *opCtx) {
	srv := s.serverOr404(w, r)
	if srv == nil {
		return
	}
	var req struct {
		SessionID  string `json:"session_id"`
		IncidentID int64  `json:"incident_id"`
	}
	if err := readJSON(w, r, 4<<10, &req); err != nil || (req.SessionID == "" && req.IncidentID == 0) {
		writeErr(w, http.StatusBadRequest, "session_id or incident_id is required")
		return
	}
	if !srv.Enrolled || srv.Revoked {
		writeErr(w, http.StatusConflict, "server is not connected to the hub")
		return
	}
	m := &Message{ServerID: srv.ID, Author: c.user.Name, Command: hubproto.CommandStop, SessionID: req.SessionID, IncidentID: req.IncidentID, Body: "Stop the running agent session"}
	if err := s.st.AddMessage(m); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.st.Audit(c.user.Name, "session.stop", srv.ID, req.SessionID, c.ip)
	s.wake(srv.ID)
	writeJSON(w, http.StatusOK, m)
}

// handleVuln asks a server to accept the risk of a vulnerability, reopen it,
// or rerun its check. The server applies it without a model.
func (s *Server) handleVuln(w http.ResponseWriter, r *http.Request, c *opCtx) {
	srv := s.serverOr404(w, r)
	if srv == nil {
		return
	}
	var req struct {
		Command string `json:"command"`
		Note    string `json:"note"`
	}
	if err := readJSON(w, r, 8<<10, &req); err != nil || !slices.Contains(hubproto.VulnCommands, req.Command) {
		writeErr(w, http.StatusBadRequest, "command must be one of "+strings.Join(hubproto.VulnCommands, ", "))
		return
	}
	req.Note = strings.TrimSpace(req.Note)
	if req.Command == hubproto.CommandVulnAccept && req.Note == "" {
		writeErr(w, http.StatusBadRequest, "say why the risk is accepted")
		return
	}
	rid := r.PathValue("rid")
	if s.st.Record(srv.ID, "vulnerability", rid) == nil {
		writeErr(w, http.StatusNotFound, "no such vulnerability")
		return
	}
	if !srv.Enrolled || srv.Revoked {
		writeErr(w, http.StatusConflict, "server is not connected to the hub")
		return
	}
	m := &Message{ServerID: srv.ID, Author: c.user.Name, Command: req.Command, RequestID: rid, Body: req.Note}
	if err := s.st.AddMessage(m); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.st.Audit(c.user.Name, "vulnerability."+strings.TrimPrefix(req.Command, "vuln_"), srv.ID, rid+" "+req.Note, c.ip)
	s.wake(srv.ID)
	writeJSON(w, http.StatusOK, m)
}

// handleRule relays an operator's ruling on a containment rule: approve,
// reject, pause or delete. The server's root helper checks an approval
// against the rule content the operator saw (hash).
func (s *Server) handleRule(w http.ResponseWriter, r *http.Request, c *opCtx) {
	srv := s.serverOr404(w, r)
	if srv == nil {
		return
	}
	var req struct {
		Command string `json:"command"`
		Hash    string `json:"hash"`
		Note    string `json:"note"`
	}
	if err := readJSON(w, r, 8<<10, &req); err != nil || !slices.Contains(hubproto.RuleCommands, req.Command) {
		writeErr(w, http.StatusBadRequest, "command must be one of "+strings.Join(hubproto.RuleCommands, ", "))
		return
	}
	req.Note = strings.TrimSpace(req.Note)
	rid := r.PathValue("rid")
	rec := s.st.Record(srv.ID, "containment_rule", rid)
	if rec == nil {
		writeErr(w, http.StatusNotFound, "no such containment rule")
		return
	}
	if req.Command == hubproto.CommandRuleApprove {
		var v struct {
			Hash string `json:"hash"`
		}
		_ = json.Unmarshal(rec.Data, &v)
		if req.Hash == "" || req.Hash != v.Hash {
			writeErr(w, http.StatusConflict, "the rule changed since you opened it; look at it again")
			return
		}
	}
	if (req.Command == hubproto.CommandRulePause || req.Command == hubproto.CommandRuleReject) && req.Note == "" {
		writeErr(w, http.StatusBadRequest, "say why")
		return
	}
	if !srv.Enrolled || srv.Revoked {
		writeErr(w, http.StatusConflict, "server is not connected to the hub")
		return
	}
	m := &Message{ServerID: srv.ID, Author: c.user.Name, Command: req.Command, RequestID: rid, Body: req.Note, RuleHash: req.Hash}
	if err := s.st.AddMessage(m); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.st.Audit(c.user.Name, "containment_rule."+strings.TrimPrefix(req.Command, "rule_"), srv.ID, strings.TrimSpace(rid+" "+req.Hash+" "+req.Note), c.ip)
	s.wake(srv.ID)
	writeJSON(w, http.StatusOK, m)
}

// handleCaseState moves a case to a board column or (un)archives it. This is
// hub-only board state; the agent's own incident status is untouched.
func (s *Server) handleCaseState(w http.ResponseWriter, r *http.Request, c *opCtx) {
	var req struct {
		ServerID   string  `json:"server_id"`
		IncidentID int64   `json:"incident_id"`
		Column     *string `json:"column"`
		Archived   *bool   `json:"archived"`
		Pinned     *bool   `json:"pinned"`
	}
	if err := readJSON(w, r, 4<<10, &req); err != nil || req.IncidentID <= 0 || (req.Column == nil && req.Archived == nil && req.Pinned == nil) {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	if req.Column != nil && *req.Column != "" && *req.Column != "human" && *req.Column != "done" {
		writeErr(w, http.StatusBadRequest, "column must be human, done or empty")
		return
	}
	if s.st.Record(req.ServerID, "incident", strconv.FormatInt(req.IncidentID, 10)) == nil {
		writeErr(w, http.StatusNotFound, "case not found")
		return
	}
	detail := fmt.Sprintf("case #%d", req.IncidentID)
	if req.Pinned != nil {
		pin, err := s.st.SetCasePin(req.ServerID, req.IncidentID, *req.Pinned, c.user.Name)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if req.Column == nil && req.Archived == nil {
			s.st.Audit(c.user.Name, "case.update", req.ServerID, fmt.Sprintf("%s pinned=%v", detail, *req.Pinned), c.ip)
			writeJSON(w, http.StatusOK, map[string]any{"pin": pin})
			return
		}
		detail += fmt.Sprintf(" pinned=%v", *req.Pinned)
	}
	st, err := s.st.SetCaseState(req.ServerID, req.IncidentID, req.Column, req.Archived, c.user.Name)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if req.Column != nil {
		detail += " column=" + map[string]string{"": "auto"}[*req.Column] + *req.Column
	}
	if req.Archived != nil {
		detail += fmt.Sprintf(" archived=%v", *req.Archived)
	}
	s.st.Audit(c.user.Name, "case.update", req.ServerID, detail, c.ip)
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request, c *opCtx) {
	writeJSON(w, http.StatusOK, s.st.AuditLog(300))
}

// ErrNoUsers is returned by Check when no operator can sign in yet.
var ErrNoUsers = errors.New("no operator accounts: create one with `kodeblue-hub user add <name>`")

func (s *Server) Check() error {
	if len(s.st.Users()) == 0 {
		return ErrNoUsers
	}
	return nil
}
