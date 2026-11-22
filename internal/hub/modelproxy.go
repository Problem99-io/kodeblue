package hub

// The model proxy: servers call their hub connections through the hub, which
// adds the connection's key. A server then holds no provider key, so root on
// a server takes none away, and revoking the server ends its model access
// along with everything else. A server reaches only the connections and
// models the hub picked for it.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
)

const (
	// modelProxyPerServer bounds one server's model calls in flight (triage
	// batches plus a few agent sessions fit well within it).
	modelProxyPerServer = 8
	// modelProxyTimeout bounds one call, a long streamed answer included.
	modelProxyTimeout = 15 * time.Minute
	// SettingModelKeys "off" stops handing model keys to servers from before
	// the model proxy (kodeblue-hub fleet set model-keys).
	SettingModelKeys = "model_keys_to_servers"
)

// chatFields are the request fields a server may send. Everything else is
// refused: routing fields such as OpenRouter's "models" fallback list or
// "provider" would reach models the hub did not pick, and others ("n",
// "plugins") multiply the cost.
var chatFields = map[string]bool{
	"model": true, "messages": true, "tools": true, "tool_choice": true, "parallel_tool_calls": true,
	"cache_control": true, "prompt_cache_key": true, "prompt_cache_retention": true, "session_id": true,
	"stream": true, "stream_options": true, "max_tokens": true, "max_completion_tokens": true,
	"temperature": true, "top_p": true, "seed": true, "stop": true, "response_format": true,
	"reasoning_effort": true, "thinking": true, "usage": true,
}

func (s *Server) modelRoutes() {
	s.mux.HandleFunc("POST "+hubproto.PathModels+"{conn}/v1/chat/completions", s.agent(s.handleModelProxy))
	s.mux.HandleFunc("GET "+hubproto.PathModels+"{conn}/v1/models", s.agent(s.handleModelProxy))
}

// proxyGrant is what one server may call on one connection.
type proxyGrant struct {
	conn   hubproto.Connection
	models map[string]bool
}

// serverGrants are one server's grants by connection id, computed for the
// settings version it reported applied.
type serverGrants struct {
	applied string
	conns   map[string]proxyGrant
}

// grantCache keeps each server's grants until a setting changes in this
// process, and at most grantTTL (the kodeblue-hub CLI writes settings from
// another process), so a model call does not recompute the server's
// settings.
type grantCache struct {
	mu     sync.Mutex
	gen    uint64
	at     time.Time
	grants map[string]serverGrants // server id -> grants
}

const grantTTL = 30 * time.Second

// serverConnection is a connection server id may call through the proxy,
// with its key, and the models it may call there.
func (s *Server) serverConnection(id, conn string) (proxyGrant, bool) {
	applied := s.appliedVersion(id)
	gen := s.st.settingsGen()
	c := &s.grants
	c.mu.Lock()
	if c.gen != gen || c.grants == nil || time.Since(c.at) > grantTTL {
		c.gen, c.at, c.grants = gen, time.Now(), map[string]serverGrants{}
	}
	g, cached := c.grants[id]
	c.mu.Unlock()
	if !cached || g.applied != applied {
		g = serverGrants{applied: applied, conns: s.computeGrants(id, applied)}
		c.mu.Lock()
		if c.gen == gen {
			c.grants[id] = g
		}
		c.mu.Unlock()
	}
	pg, ok := g.conns[conn]
	return pg, ok
}

// computeGrants allows the models the hub picks for server id now, and those
// of the settings version it still runs (applied): a server takes new
// settings only when it restarts, after its agent sessions end, so a model
// changed on the hub keeps working for a running session until then.
func (s *Server) computeGrants(id, applied string) map[string]proxyGrant {
	refs := s.st.EffectiveSettings(id).Models
	old := s.st.sentModels(id, applied)
	conns := map[string]hubproto.Connection{}
	for _, c := range s.st.Connections() {
		conns[c.ID] = c
	}
	out := map[string]proxyGrant{}
	for _, m := range []map[string]hubproto.ModelRef{refs, old} {
		for _, r := range m {
			c, ok := conns[r.Connection]
			if !ok || !s.viaHub(c) {
				continue
			}
			pg, ok := out[c.ID]
			if !ok {
				pg = proxyGrant{conn: c, models: map[string]bool{}}
				out[c.ID] = pg
			}
			pg.models[r.Model] = true
		}
	}
	return out
}

// appliedVersion is the settings version server id last reported applied.
func (s *Server) appliedVersion(id string) string {
	if v, ok := s.applied.Load(id); ok {
		return v.(string)
	}
	var st hubproto.Status
	if h := s.st.GetServer(id); h != nil {
		_ = json.Unmarshal(h.Status, &st)
	}
	s.applied.Store(id, st.SettingsVersion)
	return st.SettingsVersion
}

// viaHub reports whether servers on the model proxy reach a connection
// through the hub. Not a connection marked direct (servers call it
// themselves, with its key), nor one on loopback the hub may not reach
// (http://127.0.0.1:11434, a model on each server; --endpoint-allow allows a
// gateway on the hub host instead).
func (s *Server) viaHub(c hubproto.Connection) bool {
	if c.Direct {
		return false
	}
	a, ok := endpointAddr(c.BaseURL)
	return !ok || !a.IsLoopback() || inPrefixes(a, s.opt.EndpointAllow)
}

// endpointAddr is the address an endpoint URL names (localhost and
// *.localhost as 127.0.0.1), or false for a host name.
func endpointAddr(raw string) (netip.Addr, bool) {
	u, err := url.Parse(raw)
	if err != nil {
		return netip.Addr{}, false
	}
	host := u.Hostname()
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return netip.AddrFrom4([4]byte{127, 0, 0, 1}), true
	}
	a, err := netip.ParseAddr(host)
	return a.Unmap(), err == nil
}

// checkChat returns the request to send on: exactly one "model" key (Go's
// decoder matches keys case-insensitively and takes the last duplicate,
// while the endpoint may take another, so variants are refused), a model the
// hub picked, and only chatFields. It is re-encoded, so what the endpoint
// reads is what was checked.
func checkChat(body []byte, models map[string]bool) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, errors.New("the request must be a JSON object")
	}
	fields := map[string]json.RawMessage{}
	seen := map[string]bool{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, errors.New("bad JSON")
		}
		k, _ := t.(string)
		if seen[strings.ToLower(k)] {
			return nil, fmt.Errorf("field %q appears twice", k)
		}
		seen[strings.ToLower(k)] = true
		if !chatFields[k] {
			return nil, fmt.Errorf("field %q is not passed on to the model", k)
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, errors.New("bad JSON")
		}
		fields[k] = v
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('}') || dec.More() {
		return nil, errors.New("bad JSON")
	}
	var model string
	if json.Unmarshal(fields["model"], &model) != nil || !models[model] {
		return nil, errors.New("that model is not picked for this server on the hub")
	}
	return json.Marshal(fields)
}

func (s *Server) handleModelProxy(w http.ResponseWriter, r *http.Request, id string) {
	g, ok := s.serverConnection(id, r.PathValue("conn"))
	if !ok {
		writeErr(w, http.StatusNotFound, "no model connection by that name goes through the hub for this server")
		return
	}
	if g.conn.APIKey == "" {
		writeErr(w, http.StatusBadGateway, "the hub has no API key for this model connection")
		return
	}
	// The slot comes before the body, so the limit also bounds the memory
	// one server can hold here.
	if !s.modelSlot(id) {
		w.Header().Set("Retry-After", "5")
		writeErr(w, http.StatusTooManyRequests, "too many model calls from this server at once")
		return
	}
	defer s.releaseModelSlot(id)
	path, query, body := "/v1/models", url.Values{}, []byte(nil)
	if p := r.URL.Query().Get("provider"); p != "" && hubproto.ValidProvider(p) {
		query.Set("provider", p) // the only parameter the catalog takes
	}
	if r.Method == http.MethodPost {
		path, query = "/v1/chat/completions", nil
		b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, hubproto.MaxModelRequestBytes))
		if err != nil {
			writeErr(w, http.StatusRequestEntityTooLarge, "request too large")
			return
		}
		if body, err = checkChat(b, g.models); err != nil {
			writeErr(w, http.StatusForbidden, err.Error())
			return
		}
	}
	target, err := url.Parse(strings.TrimRight(g.conn.BaseURL, "/") + path)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "bad model connection URL")
		return
	}
	target.RawQuery = query.Encode()
	ctx, cancel := context.WithTimeout(r.Context(), modelProxyTimeout)
	defer cancel()
	// A streamed answer outlasts the hub's two-minute write timeout.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(modelProxyTimeout + time.Minute))
	rp := &httputil.ReverseProxy{
		Transport:     s.proxy.Transport,
		FlushInterval: -1,
		// Only what the endpoint needs: nothing of the server's request (its
		// hub key above all) is passed on.
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL, pr.Out.Host = target, ""
			pr.Out.Header = http.Header{}
			pr.Out.Header.Set("Authorization", "Bearer "+g.conn.APIKey)
			pr.Out.Header.Set("User-Agent", "kodeblue-hub/"+hubproto.Version)
			if a := r.Header.Get("Accept"); a != "" {
				pr.Out.Header.Set("Accept", a)
			}
			if body != nil {
				pr.Out.Body, pr.Out.ContentLength = io.NopCloser(bytes.NewReader(body)), int64(len(body))
				pr.Out.Header.Set("Content-Type", "application/json")
				pr.Out.Header.Set("Content-Length", strconv.Itoa(len(body)))
			}
		},
		ModifyResponse: keepModelHeaders,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			s.log.Warn("model proxy: endpoint unreachable", "server", id, "connection", g.conn.ID, "error", err)
			writeErr(w, http.StatusBadGateway, "the hub could not reach the model endpoint")
		},
	}
	rp.ServeHTTP(w, r.WithContext(ctx))
}

// keepModelHeaders passes on only the headers a model client reads: the
// body's type, how long to wait, and the endpoint's request id, which the
// engine reports for a failed call.
func keepModelHeaders(resp *http.Response) error {
	keep := http.Header{}
	for _, k := range []string{"Content-Type", "Retry-After", "X-Request-Id", "Request-Id", "X-Amzn-Requestid", "X-Amzn-Request-Id", "X-Openrouter-Request-Id"} {
		if v := resp.Header.Get(k); v != "" {
			keep.Set(k, v)
		}
	}
	resp.Header = keep
	return nil
}

func (s *Server) modelSlot(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.modelCalls[id] >= modelProxyPerServer {
		return false
	}
	s.modelCalls[id]++
	return true
}

func (s *Server) releaseModelSlot(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.modelCalls[id]--; s.modelCalls[id] <= 0 {
		delete(s.modelCalls, id)
	}
}

// usesProxy reports whether server id gets its connections without keys: it
// says it calls models through the hub (reported), or once did (the hub
// remembers it, markModelProxy, so a server cannot ask for the keys back by
// claiming to be older), or the hub hands keys to no server at all.
func (s *Server) usesProxy(id string, reported bool) bool {
	return reported || s.st.modelProxyServer(id) || s.st.Setting(SettingModelKeys) == "off"
}

// settingsFor is what the hub sends server id. A server on the model proxy
// gets its connections via the hub without their keys and endpoints; an
// older one still gets them, until it is upgraded or model keys are off.
func (s *Server) settingsFor(id string, reported bool) *hubproto.Settings {
	eff := s.st.EffectiveSettings(id)
	if len(eff.Connections) == 0 || !s.usesProxy(id, reported) {
		return eff
	}
	for i := range eff.Connections {
		if c := &eff.Connections[i]; s.viaHub(*c) {
			c.BaseURL, c.APIKey, c.ViaHub = "", "", true
		}
	}
	eff.Version = ""
	eff.Version = settingsVersion(eff)
	return eff
}

// Why a server holds a key of one of the hub's model connections (fleetRow
// model_keys).
const (
	keysOld    = "old"    // a kodeblue from before the model proxy: the hub still sends it the keys
	keysDirect = "direct" // connections its servers call themselves, with their keys
	keysStale  = "stale"  // its own endpoint key, from an older enrollment, is a hub connection's key
)

// modelKeys reports why server h holds a key of one of the hub's model
// connections, or "" when it holds none the hub knows of.
func (s *Server) modelKeys(h Host) string {
	if !h.Enrolled || h.Revoked {
		return ""
	}
	var st hubproto.Status
	_ = json.Unmarshal(h.Status, &st)
	if st.Version == "" {
		return ""
	}
	key := fmt.Sprint(h.ID, st.ModelProxy, st.AcceptsSettings, st.InferenceKeySum)
	gen := s.st.settingsGen()
	c := &s.keys
	c.mu.Lock()
	if c.gen != gen || c.why == nil || time.Since(c.at) > grantTTL {
		c.gen, c.at, c.why = gen, time.Now(), map[string]string{}
	}
	why, ok := c.why[key]
	c.mu.Unlock()
	if ok {
		return why
	}
	if st.AcceptsSettings {
		for _, cn := range s.settingsFor(h.ID, st.ModelProxy).Connections {
			if cn.APIKey != "" {
				why = keysDirect
				if !s.usesProxy(h.ID, st.ModelProxy) {
					why = keysOld
					break
				}
			}
		}
	}
	if why == "" && st.InferenceKeySum != "" {
		for _, cn := range s.st.Connections() {
			if cn.APIKey != "" && hubproto.KeySum(cn.APIKey) == st.InferenceKeySum {
				why = keysStale
				break
			}
		}
	}
	c.mu.Lock()
	if c.gen == gen {
		c.why[key] = why
	}
	c.mu.Unlock()
	return why
}

// keysCache keeps modelKeys results like grantCache keeps grants.
type keysCache struct {
	mu  sync.Mutex
	gen uint64
	at  time.Time
	why map[string]string
}
