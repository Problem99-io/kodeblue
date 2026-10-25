//go:build unix

package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The test binary doubles as a stdio MCP server: TestMain runs fakeServer
// instead of the tests when MCP_FAKE_SERVER is set.
func TestMain(m *testing.M) {
	if os.Getenv("MCP_FAKE_SERVER") == "1" {
		fakeServer()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// fakeServer speaks just enough MCP over stdio for the tests:
//   - MCP_FAKE_TOOLS names a file listing the advertised tools, one per line;
//   - MCP_FAKE_FAIL names a file whose existence makes the server exit at once;
//   - MCP_FAKE_FLAKY names a file whose existence makes it exit right after
//     answering tools/list, i.e. just after the handshake.
//
// Tools: echo, pid (returns the server's pid), hang (never answers), crash
// (exits mid-call), ask (sends server-initiated requests first; see below),
// flood (sends 20000 pings, then ignores its input for a while) and anything
// else listed, which answers "<name> ok".
func fakeServer() {
	if _, err := os.Stat(os.Getenv("MCP_FAKE_FAIL")); err == nil {
		fmt.Fprintln(os.Stderr, "fake mcp server: failing on purpose")
		os.Exit(1)
	}
	out := json.NewEncoder(os.Stdout)
	reply := func(id json.RawMessage, result any) {
		_ = out.Encode(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
	}
	text := func(s string) map[string]any {
		return map[string]any{"content": []map[string]any{{"type": "text", "text": s}}}
	}

	// State for "ask": the call waits for our client's answers to the
	// server-initiated requests before it replies.
	var askID json.RawMessage
	askAnswers := map[string]string{}

	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for in.Scan() {
		var msg struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Name      string         `json:"name"`
				Arguments map[string]any `json:"arguments"`
			} `json:"params"`
			Result json.RawMessage `json:"result"`
			Error  *rpcError       `json:"error"`
		}
		if json.Unmarshal(in.Bytes(), &msg) != nil {
			continue
		}
		if msg.Method == "" { // a response to one of our requests
			switch {
			case msg.Error != nil:
				askAnswers[string(msg.ID)] = strconv.Itoa(msg.Error.Code)
			default:
				askAnswers[string(msg.ID)] = "ok"
			}
			if askID != nil && askAnswers[string(askID)] != "" && askAnswers[`"p1"`] != "" {
				reply(askID, text(fmt.Sprintf("sampling=%s ping=%s", askAnswers[string(askID)], askAnswers[`"p1"`])))
				askID = nil
			}
			continue
		}
		switch msg.Method {
		case "initialize":
			reply(msg.ID, map[string]any{
				"protocolVersion": protocolVersion,
				"serverInfo":      map[string]any{"name": "fake-stdio", "version": "1"},
			})
		case "tools/list":
			var tools []map[string]any
			data, _ := os.ReadFile(os.Getenv("MCP_FAKE_TOOLS"))
			for _, name := range strings.Fields(string(data)) {
				tools = append(tools, map[string]any{"name": name, "inputSchema": map[string]any{"type": "object"}})
			}
			reply(msg.ID, map[string]any{"tools": tools})
			if _, err := os.Stat(os.Getenv("MCP_FAKE_FLAKY")); err == nil {
				os.Exit(4)
			}
		case "tools/call":
			switch msg.Params.Name {
			case "echo":
				reply(msg.ID, text(fmt.Sprint("echo: ", msg.Params.Arguments["message"])))
			case "pid":
				reply(msg.ID, text(strconv.Itoa(os.Getpid())))
			case "hang":
			case "crash":
				os.Exit(3)
			case "ask":
				// A request that reuses the pending call's id, a
				// notification, and a ping. The client must answer the
				// requests rather than take the first for its response.
				askID = msg.ID
				_ = out.Encode(map[string]any{"jsonrpc": "2.0", "id": msg.ID, "method": "sampling/createMessage", "params": map[string]any{}})
				_ = out.Encode(map[string]any{"jsonrpc": "2.0", "method": "notifications/message", "params": map[string]any{"data": "hi"}})
				_ = out.Encode(map[string]any{"jsonrpc": "2.0", "id": "p1", "method": "ping"})
			case "flood":
				for i := 0; i < 20000; i++ {
					_ = out.Encode(map[string]any{"jsonrpc": "2.0", "id": fmt.Sprint("f", i), "method": "ping"})
				}
				time.Sleep(time.Second)
				reply(msg.ID, text("flood ok"))
			default:
				reply(msg.ID, text(msg.Params.Name+" ok"))
			}
		default:
			if msg.ID != nil {
				_ = out.Encode(map[string]any{"jsonrpc": "2.0", "id": msg.ID, "error": map[string]any{"code": rpcMethodNotFound, "message": "nope"}})
			}
		}
	}
}

type fakeEnv struct {
	cfg       ServerConfig
	toolsFile string
	failFile  string
	flakyFile string
}

func newFakeEnv(t *testing.T, tools ...string) *fakeEnv {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	e := &fakeEnv{toolsFile: dir + "/tools", failFile: dir + "/fail", flakyFile: dir + "/flaky"}
	e.setTools(t, tools...)
	e.cfg = ServerConfig{
		Name:      "fake",
		Transport: TransportStdio,
		Command:   exe,
		Args:      []string{"-test.run=^$"},
		Env:       map[string]string{"MCP_FAKE_SERVER": "1", "MCP_FAKE_TOOLS": e.toolsFile, "MCP_FAKE_FAIL": e.failFile, "MCP_FAKE_FLAKY": e.flakyFile},
		Enabled:   true,
	}
	return e
}

func (e *fakeEnv) setTools(t *testing.T, tools ...string) {
	t.Helper()
	if err := os.WriteFile(e.toolsFile, []byte(strings.Join(tools, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
}

// checkGoroutines fails the test if goroutines started during it are still
// running once it (and its deferred Close calls) finished.
func checkGoroutines(t *testing.T) {
	t.Helper()
	before := runtime.NumGoroutine()
	t.Cleanup(func() {
		deadline := time.Now().Add(5 * time.Second)
		for runtime.NumGoroutine() > before {
			if time.Now().After(deadline) {
				buf := make([]byte, 1<<20)
				buf = buf[:runtime.Stack(buf, true)]
				t.Errorf("goroutine leak: %d before, %d after\n%s", before, runtime.NumGoroutine(), buf)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
}

func testManager(base time.Duration) *Manager {
	m := NewManager(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})))
	m.backoffBase = base
	m.backoffMax = 4 * base
	m.callWait = 5 * time.Second
	m.dialTimeout = 10 * time.Second
	m.minStableUp = 0
	return m
}

func waitStatus(t *testing.T, m *Manager, what string, ok func(ServerStatus) bool) ServerStatus {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		st := m.Status()[0]
		if ok(st) {
			return st
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s; status: %+v", what, st)
		}
		time.Sleep(time.Millisecond)
	}
}

func callText(t *testing.T, m *Manager, tool, args string) string {
	t.Helper()
	out, isErr, err := m.Call(context.Background(), QualifiedToolName("fake", tool), json.RawMessage(args))
	if err != nil || isErr {
		t.Fatalf("call %s: err=%v isErr=%v out=%q", tool, err, isErr, out)
	}
	return out
}

func serverPID(t *testing.T, m *Manager) int {
	t.Helper()
	pid, err := strconv.Atoi(callText(t, m, "pid", `{}`))
	if err != nil {
		t.Fatal(err)
	}
	return pid
}

// waitReaped waits until pid no longer exists. kill(pid, 0) still succeeds
// for a zombie, so ESRCH means the process was waited for.
func waitReaped(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := syscall.Kill(pid, 0)
		if errors.Is(err, syscall.ESRCH) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("process %d not reaped (kill 0: %v)", pid, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestStdioServerRequestsAreAnsweredNotMisrouted(t *testing.T) {
	checkGoroutines(t)
	e := newFakeEnv(t, "ask")
	client, err := Connect(context.Background(), e.cfg)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, isErr, err := client.CallTool(ctx, "ask", nil)
	if err != nil || isErr {
		t.Fatalf("CallTool: err=%v isErr=%v out=%q", err, isErr, out)
	}
	if want := fmt.Sprintf("sampling=%d ping=ok", rpcMethodNotFound); out != want {
		t.Fatalf("got %q, want %q", out, want)
	}
}

func TestManagerReconnectsAfterServerKilled(t *testing.T) {
	checkGoroutines(t)
	e := newFakeEnv(t, "echo", "pid", "hang")
	m := testManager(200 * time.Millisecond)
	defer m.Close()
	m.Connect(context.Background(), []ServerConfig{e.cfg})

	st := m.Status()[0]
	if st.State != StateConnected || !st.Connected || st.ToolCount != 3 {
		t.Fatalf("unexpected initial status: %+v", st)
	}
	pid := serverPID(t, m)

	// A call in flight when the server dies may have taken effect: it fails
	// with "outcome unknown", which is not retryable.
	inflight := make(chan error, 1)
	go func() {
		_, _, err := m.Call(context.Background(), QualifiedToolName("fake", "hang"), nil)
		inflight <- err
	}()
	time.Sleep(50 * time.Millisecond) // let the call reach the server

	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-inflight:
		if !errors.Is(err, ErrOutcomeUnknown) || IsRetryable(err) || !strings.Contains(err.Error(), "signal: killed") {
			t.Fatalf("in-flight call: want non-retryable outcome-unknown 'signal: killed' error, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight call never failed")
	}
	waitReaped(t, pid)

	st = waitStatus(t, m, "reconnecting", func(st ServerStatus) bool { return st.State == StateReconnecting })
	if st.Connected || !strings.Contains(st.Error, "signal: killed") {
		t.Fatalf("status during outage: %+v", st)
	}

	// A call made during the outage waits for the respawn instead of failing.
	if out := callText(t, m, "echo", `{"message":"back"}`); out != "echo: back" {
		t.Fatalf("echo after reconnect: %q", out)
	}
	st = m.Status()[0]
	if st.State != StateConnected || !st.Connected || st.Reconnects != 1 || st.Error != "" ||
		!strings.Contains(st.LastError, "signal: killed") {
		t.Fatalf("status after reconnect: %+v", st)
	}
	if pid2 := serverPID(t, m); pid2 == pid {
		t.Fatalf("server not respawned: pid still %d", pid)
	}

	// It survives more than one crash.
	pid = serverPID(t, m)
	_ = syscall.Kill(pid, syscall.SIGKILL)
	waitStatus(t, m, "second reconnect", func(st ServerStatus) bool { return st.Reconnects == 2 && st.Connected })
	waitReaped(t, pid)

	pid = serverPID(t, m)
	m.Close()
	waitReaped(t, pid)
}

func TestManagerReportsFailedAndRecovers(t *testing.T) {
	checkGoroutines(t)
	e := newFakeEnv(t, "echo", "pid", "crash")
	m := testManager(5 * time.Millisecond)
	m.callWait = 50 * time.Millisecond
	defer m.Close()
	m.Connect(context.Background(), []ServerConfig{e.cfg})

	// Every respawn now dies during initialize.
	if err := os.WriteFile(e.failFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := m.Call(context.Background(), QualifiedToolName("fake", "crash"), nil)
	if !errors.Is(err, ErrOutcomeUnknown) || !strings.Contains(err.Error(), "exit status 3") {
		t.Fatalf("crash call: want outcome-unknown 'exit status 3' error, got %v", err)
	}

	st := waitStatus(t, m, "failed", func(st ServerStatus) bool { return st.State == StateFailed })
	if st.Connected || st.Attempts < failedAfterAttempts || st.Error == "" {
		t.Fatalf("failed status: %+v", st)
	}
	_, isErr, err := m.Call(context.Background(), QualifiedToolName("fake", "echo"), json.RawMessage(`{"message":"x"}`))
	if !isErr || !IsRetryable(err) || !strings.Contains(err.Error(), "failed") {
		t.Fatalf("call while failed: want retryable error naming the state, got isErr=%v err=%v", isErr, err)
	}

	// Retrying never stops, so the server comes back once it can start.
	if err := os.Remove(e.failFile); err != nil {
		t.Fatal(err)
	}
	st = waitStatus(t, m, "recovery", func(st ServerStatus) bool { return st.State == StateConnected })
	if !st.Connected || st.Attempts != 0 || st.Error != "" || st.Reconnects != 1 {
		t.Fatalf("recovered status: %+v", st)
	}
	if out := callText(t, m, "echo", `{"message":"ok"}`); out != "echo: ok" {
		t.Fatalf("echo after recovery: %q", out)
	}
}

func TestManagerInitialConnectFailureIsRetried(t *testing.T) {
	checkGoroutines(t)
	e := newFakeEnv(t, "echo")
	if err := os.WriteFile(e.failFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	m := testManager(5 * time.Millisecond)
	defer m.Close()
	registered := make(chan []ToolHandle, 1)
	m.OnToolsChanged(func(hs []ToolHandle) { registered <- hs })
	m.Connect(context.Background(), []ServerConfig{e.cfg})

	st := m.Status()[0]
	if st.State != StateFailed || st.Connected || st.Attempts != 1 ||
		!strings.Contains(st.Error, "initialize: mcp server unavailable: server process exited (exit status 1)") {
		t.Fatalf("initial status: %+v", st)
	}
	_ = os.Remove(e.failFile)
	waitStatus(t, m, "connected", func(st ServerStatus) bool { return st.Connected && st.ToolCount == 1 })
	if out := callText(t, m, "echo", `{"message":"late"}`); out != "echo: late" {
		t.Fatalf("echo: %q", out)
	}
	// The engine registers tools once at startup; the hook is how a server
	// that came up later gets its tools in front of the agent.
	select {
	case hs := <-registered:
		if len(hs) != 1 || hs[0].QualifiedName != QualifiedToolName("fake", "echo") {
			t.Fatalf("hook got %+v", hs)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("OnToolsChanged not called after the late connect")
	}
}

func TestManagerToolListChangesOnReconnect(t *testing.T) {
	checkGoroutines(t)
	e := newFakeEnv(t, "echo", "pid", "old")
	m := testManager(5 * time.Millisecond)
	defer m.Close()
	registered := make(chan []ToolHandle, 1)
	m.OnToolsChanged(func(hs []ToolHandle) { registered <- hs })
	m.Connect(context.Background(), []ServerConfig{e.cfg})

	pid := serverPID(t, m)
	e.setTools(t, "echo", "pid", "new")
	_ = syscall.Kill(pid, syscall.SIGKILL)
	waitStatus(t, m, "reconnect", func(st ServerStatus) bool { return st.Reconnects == 1 && st.Connected })

	var names []string
	for _, th := range m.Tools() {
		names = append(names, th.RemoteName)
	}
	if got := strings.Join(names, ","); got != "echo,pid,new" {
		t.Fatalf("tools after reconnect: %s", got)
	}
	if out := callText(t, m, "new", `{}`); out != "new ok" {
		t.Fatalf("new tool: %q", out)
	}
	_, _, err := m.Call(context.Background(), QualifiedToolName("fake", "old"), nil)
	if err == nil || !strings.Contains(err.Error(), "not available") {
		t.Fatalf("removed tool: want not available, got %v", err)
	}
	// The hook runs just after the status turns connected, so wait for it.
	select {
	case hs := <-registered:
		if len(hs) != 3 || hs[2].RemoteName != "new" {
			t.Fatalf("hook got %+v", hs)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("OnToolsChanged not called for the changed tool list")
	}
}

func TestManagerBacksOffWhenServerDiesRightAfterHandshake(t *testing.T) {
	checkGoroutines(t)
	e := newFakeEnv(t, "echo", "pid")
	m := testManager(5 * time.Millisecond)
	m.minStableUp = time.Hour
	defer m.Close()
	m.Connect(context.Background(), []ServerConfig{e.cfg})
	// The first server is past its tools/list check once it answers a call.
	pid := serverPID(t, m)
	if err := os.WriteFile(e.flakyFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)

	// Every respawn handshakes and then exits. Each counts as a failed
	// attempt, so the delay grows and the state ends up failed instead of
	// flapping between reconnecting and connected forever.
	st := waitStatus(t, m, "failed", func(st ServerStatus) bool { return st.State == StateFailed })
	if st.Attempts < failedAfterAttempts || !strings.Contains(st.LastError, "after connecting") {
		t.Fatalf("status: %+v", st)
	}
	if d := m.backoff(st.Attempts); d != m.backoffMax {
		t.Fatalf("backoff after %d failures = %v, want the cap %v", st.Attempts, d, m.backoffMax)
	}

	_ = os.Remove(e.flakyFile)
	waitStatus(t, m, "recovery", func(st ServerStatus) bool { return st.State == StateConnected && st.Connected })
	if out := callText(t, m, "echo", `{"message":"steady"}`); out != "echo: steady" {
		t.Fatalf("echo: %q", out)
	}
}

func TestStdioRepliesToServerRequestsAreBounded(t *testing.T) {
	checkGoroutines(t)
	e := newFakeEnv(t, "flood")
	client, err := Connect(context.Background(), e.cfg)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer client.Close()

	before := runtime.NumGoroutine()
	peak := before
	stop := make(chan struct{})
	sampled := make(chan struct{})
	go func() {
		defer close(sampled)
		for {
			select {
			case <-stop:
				return
			default:
			}
			peak = max(peak, runtime.NumGoroutine())
			time.Sleep(time.Millisecond)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, _, err := client.CallTool(ctx, "flood", nil)
	close(stop)
	<-sampled
	if err != nil || out != "flood ok" {
		t.Fatalf("flood: out=%q err=%v", out, err)
	}
	// 20000 pings against a server that is not reading its input: one
	// writer and a small queue, not a goroutine per reply.
	if peak-before > 10 {
		t.Fatalf("goroutines grew by %d while replying to a flood of server requests", peak-before)
	}
}

func TestStdioWriteToStoppedServerGivesUp(t *testing.T) {
	checkGoroutines(t)
	e := newFakeEnv(t, "echo", "pid")
	m := testManager(5 * time.Millisecond)
	defer m.Close()
	m.Connect(context.Background(), []ServerConfig{e.cfg})
	// Far larger than a pipe buffer, so the write blocks on a stopped reader.
	big := json.RawMessage(`{"message":"` + strings.Repeat("x", 1<<20) + `"}`)

	// The caller's context ends while the write is stuck: the call returns
	// promptly, and since half a message is now in the pipe the server is
	// replaced.
	pid := serverPID(t, m)
	_ = syscall.Kill(pid, syscall.SIGSTOP)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	start := time.Now()
	_, _, err := m.Call(ctx, QualifiedToolName("fake", "echo"), big)
	cancel()
	if err == nil || time.Since(start) > 3*time.Second {
		t.Fatalf("call to a stopped server: err=%v after %v", err, time.Since(start))
	}
	waitReaped(t, pid)
	waitStatus(t, m, "reconnect", func(st ServerStatus) bool { return st.Reconnects == 1 && st.Connected })

	// With no deadline of its own, the write gives up after
	// stdioWriteTimeout and the server is replaced.
	defer func(d time.Duration) { stdioWriteTimeout = d }(stdioWriteTimeout)
	stdioWriteTimeout = 200 * time.Millisecond
	pid = serverPID(t, m)
	_ = syscall.Kill(pid, syscall.SIGSTOP)
	_, _, err = m.Call(context.Background(), QualifiedToolName("fake", "echo"), big)
	if !IsRetryable(err) || !strings.Contains(err.Error(), "stopped reading") {
		t.Fatalf("write timeout: want retryable 'stopped reading' error, got %v", err)
	}
	waitReaped(t, pid)
	waitStatus(t, m, "second reconnect", func(st ServerStatus) bool { return st.Reconnects == 2 && st.Connected })
	if out := callText(t, m, "echo", `{"message":"awake"}`); out != "echo: awake" {
		t.Fatalf("echo: %q", out)
	}
}
