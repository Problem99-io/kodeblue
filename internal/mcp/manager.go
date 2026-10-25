package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"
)

// ToolHandle is everything the engine needs to expose one MCP tool to the agent.
type ToolHandle struct {
	QualifiedName string          // mcp__<server>__<tool>
	ServerName    string          // configured server name
	RemoteName    string          // tool name on the server
	Description   string          // agent-facing description
	InputSchema   json.RawMessage // JSON Schema for the tool arguments
}

// Connection states reported in ServerStatus.State.
const (
	StateConnected    = "connected"    // handshake done, calls are routed
	StateReconnecting = "reconnecting" // the connection was lost; retrying
	StateFailed       = "failed"       // repeated attempts failed; still retrying, more slowly
)

// ServerStatus is a snapshot of a single server's connection state.
type ServerStatus struct {
	Name       string    `json:"name"`
	Transport  string    `json:"transport"`
	State      string    `json:"state"`
	Connected  bool      `json:"connected"`
	ToolCount  int       `json:"tool_count"`
	Tools      []string  `json:"tools,omitempty"`
	Error      string    `json:"error,omitempty"`      // why it is not connected right now
	LastError  string    `json:"last_error,omitempty"` // most recent failure, kept after recovery
	Attempts   int       `json:"attempts,omitempty"`   // consecutive failed attempts, counting connections that dropped right away
	Reconnects int       `json:"reconnects,omitempty"` // successful reconnects since start
	Since      time.Time `json:"since"`                // when State last changed
}

// failedAfterAttempts is how many consecutive failed attempts turn
// "reconnecting" into "failed".
const failedAfterAttempts = 5

type serverConn struct {
	cfg        ServerConfig
	client     *Client      // nil unless state is connected
	tools      []ToolHandle // last known tool list, kept while reconnecting
	state      string
	err        string
	lastErr    string
	attempts   int
	reconnects int
	since      time.Time
	upSince    time.Time     // when the current connection was made
	changed    chan struct{} // closed (and replaced) on every state change
}

// Manager owns the connections to all configured MCP servers and routes tool
// calls to the right one. A stdio server whose process dies is respawned with
// capped exponential backoff. It is safe for concurrent use.
type Manager struct {
	logger *slog.Logger

	// Reconnect tuning; tests shorten these.
	backoffBase time.Duration // delay before the first reconnect attempt
	backoffMax  time.Duration // cap on the delay between attempts
	dialTimeout time.Duration // per attempt: spawn + initialize + tools/list
	callWait    time.Duration // how long Call waits for a reconnecting server
	// A connection lost sooner than minStableUp after it was made counts as
	// a failed attempt, so a server that crashes right after the handshake
	// still backs off and is reported as failed.
	minStableUp time.Duration

	ctx    context.Context // cancelled by Close; stops the supervisors
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu      sync.RWMutex // guards everything below and every serverConn
	servers []*serverConn
	byTool  map[string]*serverConn // qualified tool name -> server
	remote  map[string]string      // qualified tool name -> remote tool name

	hookMu         sync.Mutex // serialises onToolsChanged calls
	onToolsChanged func([]ToolHandle)
}

// NewManager creates an empty manager.
func NewManager(logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{
		logger:      logger,
		backoffBase: time.Second,
		backoffMax:  time.Minute,
		dialTimeout: 20 * time.Second,
		callWait:    5 * time.Second,
		minStableUp: 10 * time.Second,
		ctx:         ctx,
		cancel:      cancel,
		byTool:      make(map[string]*serverConn),
		remote:      make(map[string]string),
	}
}

// Connect dials every enabled server and discovers its tools. Individual
// failures are recorded in status but do not abort the others; every server,
// connected or not, is then supervised and redialled whenever it is down.
func (m *Manager) Connect(ctx context.Context, configs []ServerConfig) {
	for _, cfg := range configs {
		if !cfg.Enabled {
			continue
		}
		sc := &serverConn{cfg: cfg, since: time.Now(), changed: make(chan struct{})}

		dialCtx, cancel := context.WithTimeout(ctx, m.dialTimeout)
		client, tools, err := dial(dialCtx, cfg)
		cancel()
		if err != nil {
			sc.state = StateFailed
			sc.err, sc.lastErr = err.Error(), err.Error()
			sc.attempts = 1
			m.logger.Warn("mcp server connect failed; will retry", "server", cfg.Name, "error", err)
		} else {
			sc.state = StateConnected
			sc.upSince = time.Now()
			sc.client = client
			sc.tools = tools
			m.logger.Info("mcp server connected", "server", cfg.Name, "tools", len(tools))
		}
		m.add(sc)
		m.wg.Add(1)
		go m.supervise(sc, client)
	}
}

// OnToolsChanged registers fn to be called with the full tool list whenever a
// reconnect changes a server's tools — including a server whose first
// connect failed and that later came up. Set it before Connect. Calls are
// serialised and made without the manager's lock held.
func (m *Manager) OnToolsChanged(fn func([]ToolHandle)) {
	m.hookMu.Lock()
	defer m.hookMu.Unlock()
	m.onToolsChanged = fn
}

func (m *Manager) toolsChanged() {
	m.hookMu.Lock()
	defer m.hookMu.Unlock()
	if m.onToolsChanged != nil {
		m.onToolsChanged(m.Tools())
	}
}

// dial connects to one server and lists its tools.
func dial(ctx context.Context, cfg ServerConfig) (*Client, []ToolHandle, error) {
	client, err := Connect(ctx, cfg)
	if err != nil {
		return nil, nil, err
	}
	remote, err := client.ListTools(ctx)
	if err != nil {
		_ = client.Close()
		return nil, nil, err
	}
	tools := make([]ToolHandle, 0, len(remote))
	for _, rt := range remote {
		tools = append(tools, ToolHandle{
			QualifiedName: QualifiedToolName(cfg.Name, rt.Name),
			ServerName:    cfg.Name,
			RemoteName:    rt.Name,
			Description:   describeMCPTool(cfg.Name, rt),
			InputSchema:   normalizeSchema(rt.InputSchema),
		})
	}
	return client, tools, nil
}

func (m *Manager) add(sc *serverConn) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.servers = append(m.servers, sc)
	m.rebuildLocked()
}

// rebuildLocked recomputes the tool routing tables from every server's
// current tool list. The first server with a given qualified name wins.
func (m *Manager) rebuildLocked() {
	m.byTool = make(map[string]*serverConn)
	m.remote = make(map[string]string)
	for _, sc := range m.servers {
		for _, th := range sc.tools {
			if _, clash := m.byTool[th.QualifiedName]; clash {
				continue
			}
			m.byTool[th.QualifiedName] = sc
			m.remote[th.QualifiedName] = th.RemoteName
		}
	}
}

// setStateLocked records a state change and wakes callers waiting on it.
func (sc *serverConn) setStateLocked(state string) {
	if sc.state != state {
		sc.state = state
		sc.since = time.Now()
	}
	close(sc.changed)
	sc.changed = make(chan struct{})
}

// supervise watches one server for the life of the manager: whenever its
// connection is lost (a stdio child exited), it redials until it succeeds.
func (m *Manager) supervise(sc *serverConn, client *Client) {
	defer m.wg.Done()
	for {
		if client != nil {
			select {
			case <-m.ctx.Done():
				return
			case <-client.Done():
			}
			m.lost(sc, client)
		}
		if client = m.redial(sc); client == nil {
			return // manager closed
		}
	}
}

// lost marks a server as down after its client died.
func (m *Manager) lost(sc *serverConn, client *Client) {
	cause := client.Err()
	if cause == nil {
		cause = ErrServerUnavailable
	}
	_ = client.Close() // the process is already reaped; this releases the rest

	m.mu.Lock()
	sc.client = nil
	lasted := time.Since(sc.upSince)
	stable := lasted >= m.minStableUp
	if stable {
		sc.attempts = 0
		sc.err, sc.lastErr = cause.Error(), cause.Error()
		sc.setStateLocked(StateReconnecting)
	} else {
		// It died soon after connecting: count that attempt as failed, so
		// a server that crashes right after the handshake backs off.
		cause = fmt.Errorf("lost %s after connecting: %w", lasted.Round(time.Millisecond), cause)
		m.recordFailureLocked(sc, cause)
	}
	attempts := sc.attempts
	m.mu.Unlock()
	if stable {
		m.logger.Warn("mcp server connection lost; reconnecting", "server", sc.cfg.Name, "error", cause)
	} else {
		m.logger.Warn("mcp server connection lost soon after connecting; backing off", "server", sc.cfg.Name, "attempt", attempts, "error", cause)
		if attempts == failedAfterAttempts {
			m.logger.Error("mcp server still down; retrying in the background", "server", sc.cfg.Name, "attempt", attempts)
		}
	}
}

// recordFailureLocked counts one more failed attempt.
func (m *Manager) recordFailureLocked(sc *serverConn, err error) {
	sc.attempts++
	sc.err, sc.lastErr = err.Error(), err.Error()
	state := StateReconnecting
	if sc.state == StateFailed || sc.attempts >= failedAfterAttempts {
		state = StateFailed
	}
	sc.setStateLocked(state)
}

func (m *Manager) logFailure(sc *serverConn, attempts int, err error) {
	switch {
	case attempts < failedAfterAttempts:
		m.logger.Warn("mcp server reconnect failed", "server", sc.cfg.Name, "attempt", attempts, "error", err)
	case attempts == failedAfterAttempts:
		m.logger.Error("mcp server still down; retrying in the background", "server", sc.cfg.Name, "attempt", attempts, "error", err)
	default:
		m.logger.Debug("mcp server reconnect failed", "server", sc.cfg.Name, "attempt", attempts, "error", err)
	}
}

// redial retries the connection with capped exponential backoff until it
// succeeds (returning the new client) or the manager closes (returning nil).
func (m *Manager) redial(sc *serverConn) *Client {
	for {
		m.mu.RLock()
		failures := sc.attempts
		m.mu.RUnlock()

		timer := time.NewTimer(m.backoff(failures))
		select {
		case <-m.ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}

		ctx, cancel := context.WithTimeout(m.ctx, m.dialTimeout)
		client, tools, err := dial(ctx, sc.cfg)
		cancel()
		if err == nil {
			if m.ctx.Err() != nil {
				_ = client.Close()
				return nil
			}
			m.up(sc, client, tools)
			return client
		}
		if m.ctx.Err() != nil {
			return nil
		}

		m.mu.Lock()
		m.recordFailureLocked(sc, err)
		attempts := sc.attempts
		m.mu.Unlock()
		m.logFailure(sc, attempts, err)
	}
}

// backoff returns the delay before the next attempt after `failures`
// consecutive failures: base, 2×base, 4×base, … capped at backoffMax.
func (m *Manager) backoff(failures int) time.Duration {
	d := m.backoffBase
	for i := 0; i < failures && d < m.backoffMax; i++ {
		d *= 2
	}
	return min(d, m.backoffMax)
}

// up installs a freshly dialled client and its (possibly changed) tool list.
func (m *Manager) up(sc *serverConn, client *Client, tools []ToolHandle) {
	m.mu.Lock()
	added, removed := diffTools(sc.tools, tools)
	sc.client = client
	sc.tools = tools
	sc.err = ""
	sc.upSince = time.Now()
	sc.reconnects++
	sc.setStateLocked(StateConnected)
	if len(added) > 0 || len(removed) > 0 {
		m.rebuildLocked()
	}
	m.mu.Unlock()

	m.logger.Info("mcp server reconnected", "server", sc.cfg.Name, "tools", len(tools))
	if len(added) > 0 || len(removed) > 0 {
		// Removed tools now fail with "not available"; added ones reach
		// the engine's tool registry through OnToolsChanged.
		m.logger.Warn("mcp server tool list changed", "server", sc.cfg.Name, "added", added, "removed", removed)
		m.toolsChanged()
	}
}

// diffTools reports the remote tool names in next but not prev, and vice versa.
func diffTools(prev, next []ToolHandle) (added, removed []string) {
	has := func(list []ToolHandle, name string) bool {
		return slices.ContainsFunc(list, func(th ToolHandle) bool { return th.RemoteName == name })
	}
	for _, th := range next {
		if !has(prev, th.RemoteName) {
			added = append(added, th.RemoteName)
		}
	}
	for _, th := range prev {
		if !has(next, th.RemoteName) {
			removed = append(removed, th.RemoteName)
		}
	}
	return added, removed
}

// Tools returns the aggregated tool handles across all servers (for a server
// that is reconnecting, its last known list).
func (m *Manager) Tools() []ToolHandle {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []ToolHandle
	for _, sc := range m.servers {
		out = append(out, sc.tools...)
	}
	return out
}

// Call routes a tool invocation (by qualified name) to its server. If the
// server is reconnecting, Call waits briefly for it to come back; past that it
// fails with an error wrapping ErrServerUnavailable. A call that was in flight
// when the server died is not retried, since tools need not be idempotent.
func (m *Manager) Call(ctx context.Context, qualifiedName string, args json.RawMessage) (string, bool, error) {
	timer := time.NewTimer(m.callWait)
	defer timer.Stop()
	for {
		m.mu.RLock()
		sc := m.byTool[qualifiedName]
		remote := m.remote[qualifiedName]
		var (
			client  *Client
			changed chan struct{}
			down    error
		)
		if sc != nil {
			client, changed = sc.client, sc.changed
			if client == nil {
				down = fmt.Errorf("%w: %q is %s (%d failed attempts; last error: %s); retry shortly",
					ErrServerUnavailable, sc.cfg.Name, sc.state, sc.attempts, sc.err)
			}
		}
		m.mu.RUnlock()

		if sc == nil {
			return "", true, fmt.Errorf("mcp tool not available: %s", qualifiedName)
		}
		if client != nil && !isClosed(client.Done()) {
			return client.CallTool(ctx, remote, args)
		}
		if down == nil {
			// The child just died and the supervisor has not caught up yet.
			down = fmt.Errorf("%w: %q: %v", ErrServerUnavailable, sc.cfg.Name, client.Err())
		}
		select {
		case <-changed:
		case <-timer.C:
			return "", true, down
		case <-ctx.Done():
			return "", true, ctx.Err()
		case <-m.ctx.Done():
			return "", true, down
		}
	}
}

func isClosed(ch <-chan struct{}) bool {
	if ch == nil {
		return false
	}
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// Status returns a snapshot for each configured server.
func (m *Manager) Status() []ServerStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]ServerStatus, 0, len(m.servers))
	for _, sc := range m.servers {
		connected := sc.client != nil && !isClosed(sc.client.Done())
		st := ServerStatus{
			Name:       sc.cfg.Name,
			Transport:  sc.cfg.NormalizedTransport(),
			State:      sc.state,
			Connected:  connected,
			ToolCount:  len(sc.tools),
			Error:      sc.err,
			LastError:  sc.lastErr,
			Attempts:   sc.attempts,
			Reconnects: sc.reconnects,
			Since:      sc.since,
		}
		if connected && time.Since(sc.upSince) >= m.minStableUp {
			st.Attempts = 0 // the connection has held; earlier failures are over
		}
		if sc.client != nil && !connected {
			// Died a moment ago; the supervisor is about to notice.
			st.State = StateReconnecting
			if err := sc.client.Err(); err != nil {
				st.Error = err.Error()
			}
		}
		for _, th := range sc.tools {
			st.Tools = append(st.Tools, th.RemoteName)
		}
		out = append(out, st)
	}
	return out
}

// Close stops reconnecting and shuts down every server connection.
func (m *Manager) Close() {
	m.cancel()
	m.wg.Wait()
	m.mu.Lock()
	servers := m.servers
	m.servers = nil
	m.byTool = make(map[string]*serverConn)
	m.remote = make(map[string]string)
	m.mu.Unlock()
	for _, sc := range servers {
		if sc.client != nil {
			_ = sc.client.Close()
		}
	}
}

// TestResult is returned by TestServer.
type TestResult struct {
	OK         bool     `json:"ok"`
	ServerName string   `json:"server_name,omitempty"`
	Version    string   `json:"version,omitempty"`
	ToolCount  int      `json:"tool_count"`
	Tools      []string `json:"tools,omitempty"`
	Error      string   `json:"error,omitempty"`
}

func describeMCPTool(server string, rt RemoteTool) string {
	desc := rt.Description
	if desc == "" {
		desc = "Tool exposed by the MCP server."
	}
	return fmt.Sprintf("[MCP: %s] %s", server, desc)
}

// normalizeSchema guarantees a valid JSON Schema object for the provider.
func normalizeSchema(raw json.RawMessage) json.RawMessage {
	trimmed := string(raw)
	if len(raw) == 0 || trimmed == "null" {
		return json.RawMessage(`{"type":"object"}`)
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return json.RawMessage(`{"type":"object"}`)
	}
	if _, ok := obj["type"]; !ok {
		obj["type"] = "object"
		if b, err := json.Marshal(obj); err == nil {
			return b
		}
	}
	return raw
}
