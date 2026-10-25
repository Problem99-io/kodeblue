package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Problem99-io/kodeblue/internal/childenv"
)

// JSON-RPC 2.0 wire types.

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      *int64 `json:"id,omitempty"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

type rpcError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *rpcError) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("rpc error %d: %s", e.Code, e.Message)
}

// rpcResponse is a response to one of our requests, and also the shape of the
// replies we send to server-initiated requests.
type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// rpcMessage is any message a server sends. A response has no method; a
// request has a method and an id; a notification has a method and no id.
type rpcMessage struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Result json.RawMessage `json:"result"`
	Error  *rpcError       `json:"error"`
}

func (m rpcMessage) response() rpcResponse {
	return rpcResponse{JSONRPC: "2.0", ID: m.ID, Result: m.Result, Error: m.Error}
}

// JSON-RPC error code for a method the receiver does not implement.
const rpcMethodNotFound = -32601

// ErrServerUnavailable means the MCP server could not take the call: its
// process had exited, or the engine is still reconnecting to it. The call was
// never delivered, so it is safe to retry once the server is back.
var ErrServerUnavailable = errors.New("mcp server unavailable")

// ErrOutcomeUnknown means the server went away while the call was in flight.
// It may or may not have taken effect, so it is not marked retryable: check
// its effect first (a containment action, say, runs in its own process and
// may well have completed).
var ErrOutcomeUnknown = errors.New("mcp call outcome unknown")

// IsRetryable reports whether err means the call never reached the server
// because it was temporarily unavailable.
func IsRetryable(err error) bool { return errors.Is(err, ErrServerUnavailable) }

var errTransportClosed = errors.New("mcp transport closed")

// transport is a JSON-RPC channel to a single MCP server.
type transport interface {
	roundTrip(ctx context.Context, method string, params any) (json.RawMessage, error)
	notify(ctx context.Context, method string, params any) error
	close() error
	// done is closed once the server is gone for good (stdio: the child
	// exited and was reaped). It is nil for transports with no such signal.
	done() <-chan struct{}
	// err explains why done was closed.
	err() error
}

// ---------------------------------------------------------------------------
// stdio transport
// ---------------------------------------------------------------------------

// drainGrace is how long the transport keeps reading a server's stdout after
// the process exited, so a final response is not lost, before giving up on it
// (a grandchild may have inherited the pipe and keep it open).
const drainGrace = 500 * time.Millisecond

// stdioWriteTimeout bounds a single write to the server's stdin. A server that
// leaves its input unread that long (stopped, or wedged) is killed so the
// supervisor can respawn it. A variable so tests can shorten it.
var stdioWriteTimeout = 10 * time.Second

// maxQueuedReplies bounds the replies to server-initiated requests waiting to
// be written; past it they are dropped and the server's request times out.
const maxQueuedReplies = 32

type rpcResult struct {
	resp rpcResponse
	err  error
}

type stdioTransport struct {
	cmd    *exec.Cmd
	stdin  *os.File // write end of the server's stdin; supports deadlines
	stdout *os.File // read end of the server's stdout; Wait does not close it
	reader *bufio.Reader

	idSeq    atomic.Int64
	writeSem chan struct{} // one writer at a time; acquiring honours ctx

	mu      sync.Mutex
	pending map[int64]chan rpcResult
	closed  bool
	deadErr error // why the server is gone; returned to every later call

	replies   chan rpcResponse // to server-initiated requests; see replyLoop
	readDone  chan struct{}    // readLoop returned
	replyDone chan struct{}    // replyLoop returned
	exited    chan struct{}    // child reaped and pending calls failed
}

func newStdioTransport(_ context.Context, cfg ServerConfig) (*stdioTransport, error) {
	cmd := exec.Command(cfg.Command, cfg.Args...)
	// Never hand the daemon's raw environment to an MCP server: the dumpable
	// flag resets on execve, so every key here is readable in this child's
	// /proc/<pid>/environ by any same-uid process — including previewed apps,
	// which run arbitrary project code and can read /proc. childenv.Filtered
	// strips the daemon's credentials (preview-control grant, provider keys);
	// cfg.Env is the server's own configured environment and is kept.
	cmd.Env = childenv.Filtered()
	for k, v := range cfg.Env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}

	// Plain os.Pipes rather than StdinPipe/StdoutPipe: writes to stdin need
	// deadlines, and Wait closes a StdoutPipe as soon as the child exits,
	// which would race the read of its last response.
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("stdin pipe: %w", err)
	}
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		_ = stdinR.Close()
		_ = stdinW.Close()
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	cmd.Stdin = stdinR
	cmd.Stdout = stdoutW
	// Surface server logs/errors to the engine's stderr for debugging.
	cmd.Stderr = os.Stderr

	err = cmd.Start()
	// The child holds its own copies.
	_ = stdinR.Close()
	_ = stdoutW.Close()
	if err != nil {
		_ = stdinW.Close()
		_ = stdoutR.Close()
		return nil, fmt.Errorf("start mcp server %q: %w", cfg.Command, err)
	}

	t := &stdioTransport{
		cmd:       cmd,
		stdin:     stdinW,
		stdout:    stdoutR,
		reader:    bufio.NewReaderSize(stdoutR, 1<<20),
		writeSem:  make(chan struct{}, 1),
		pending:   make(map[int64]chan rpcResult),
		replies:   make(chan rpcResponse, maxQueuedReplies),
		readDone:  make(chan struct{}),
		replyDone: make(chan struct{}),
		exited:    make(chan struct{}),
	}
	go t.readLoop()
	go t.replyLoop()
	go t.waitLoop()
	return t, nil
}

func (t *stdioTransport) readLoop() {
	defer close(t.readDone)
	for {
		line, err := t.reader.ReadBytes('\n')
		if len(line) > 0 {
			t.dispatch(line)
		}
		if err != nil {
			// With stdout gone the server can never answer again, even if
			// it is still running; make sure it exits so waitLoop reaps it.
			_ = t.cmd.Process.Kill()
			return
		}
	}
}

// replyLoop writes the replies to server-initiated requests. It runs apart
// from the read loop, which must keep draining stdout: a server blocked on
// writing to us would otherwise deadlock against our write to it.
func (t *stdioTransport) replyLoop() {
	defer close(t.replyDone)
	for reply := range t.replies {
		_ = t.write(context.Background(), reply)
	}
}

// waitLoop reaps the child and then fails everything still waiting on it.
func (t *stdioTransport) waitLoop() {
	waitErr := t.cmd.Wait()
	select {
	case <-t.readDone:
	case <-time.After(drainGrace):
		_ = t.stdout.Close() // unblocks the read
		<-t.readDone
	}
	_ = t.stdout.Close()
	// Nothing can be delivered any more; this also unblocks a stuck write
	// (a grandchild may hold the read end).
	_ = t.stdin.Close()
	close(t.replies) // readLoop, the only sender, has returned
	<-t.replyDone

	t.mu.Lock()
	closed := t.closed
	t.mu.Unlock()
	if closed {
		t.failPending(errTransportClosed, errTransportClosed)
	} else {
		status := "exit status 0"
		if waitErr != nil {
			status = waitErr.Error()
		}
		t.failPending(
			fmt.Errorf("%w: server process exited (%s)", ErrServerUnavailable, status),
			fmt.Errorf("%w: the mcp server process exited (%s) while the call was in flight; "+
				"it may or may not have taken effect, so check before retrying", ErrOutcomeUnknown, status))
	}
	close(t.exited)
}

func (t *stdioTransport) dispatch(line []byte) {
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return
	}
	var msg rpcMessage
	if err := json.Unmarshal(line, &msg); err != nil {
		return // non-JSON log line
	}
	if msg.Method != "" {
		// A server-initiated request or notification, never a response to
		// one of ours — even when its id happens to equal a pending one.
		if hasRPCID(msg.ID) {
			t.answerServerRequest(msg)
		}
		return
	}
	id, ok := parseRPCID(msg.ID)
	if !ok {
		return
	}
	t.mu.Lock()
	ch := t.pending[id]
	delete(t.pending, id)
	t.mu.Unlock()
	if ch != nil {
		ch <- rpcResult{resp: msg.response()}
	}
}

// answerServerRequest queues the reply to a request the server sent us. The
// engine advertises no client capabilities (sampling, roots, elicitation), so
// only ping is answered; anything else gets method-not-found instead of
// leaving the server waiting.
func (t *stdioTransport) answerServerRequest(msg rpcMessage) {
	reply := rpcResponse{JSONRPC: "2.0", ID: msg.ID}
	if msg.Method == "ping" {
		reply.Result = json.RawMessage(`{}`)
	} else {
		reply.Error = &rpcError{Code: rpcMethodNotFound, Message: "method not found: " + msg.Method}
	}
	select {
	case t.replies <- reply:
	default:
		// The server floods us with requests faster than it reads the
		// replies; drop this one rather than queue without bound.
	}
}

// failPending records why the server is gone (deadErr, for later calls) and
// fails every call still waiting for a response with inflightErr.
func (t *stdioTransport) failPending(deadErr, inflightErr error) {
	t.mu.Lock()
	if t.deadErr == nil {
		t.deadErr = deadErr
	}
	for id, ch := range t.pending {
		ch <- rpcResult{err: inflightErr}
		delete(t.pending, id)
	}
	t.mu.Unlock()
}

func (t *stdioTransport) roundTrip(ctx context.Context, method string, params any) (json.RawMessage, error) {
	id := t.idSeq.Add(1)
	ch := make(chan rpcResult, 1)

	t.mu.Lock()
	if t.deadErr != nil || t.closed {
		err := t.deadErr
		t.mu.Unlock()
		if err == nil {
			err = errTransportClosed
		}
		return nil, err
	}
	t.pending[id] = ch
	t.mu.Unlock()

	req := rpcRequest{JSONRPC: "2.0", ID: &id, Method: method, Params: params}
	if err := t.write(ctx, req); err != nil {
		t.mu.Lock()
		delete(t.pending, id)
		t.mu.Unlock()
		return nil, err
	}

	select {
	case <-ctx.Done():
		t.mu.Lock()
		delete(t.pending, id)
		t.mu.Unlock()
		return nil, ctx.Err()
	case res := <-ch:
		if res.err != nil {
			return nil, res.err
		}
		if res.resp.Error != nil {
			return nil, res.resp.Error
		}
		return res.resp.Result, nil
	}
}

func (t *stdioTransport) notify(ctx context.Context, method string, params any) error {
	return t.write(ctx, rpcRequest{JSONRPC: "2.0", Method: method, Params: params})
}

// write sends one message. It gives up when ctx ends or after
// stdioWriteTimeout. If the server left its input unread for the whole
// timeout, or a cut-off write left half a message in the pipe, the stream is
// unusable: the server is killed and the supervisor respawns it.
func (t *stdioTransport) write(ctx context.Context, msg any) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	data = append(data, '\n')

	select {
	case t.writeSem <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	case <-t.exited:
		return t.err()
	}
	defer func() { <-t.writeSem }()

	_ = t.stdin.SetWriteDeadline(time.Now().Add(stdioWriteTimeout))
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(interrupted)
		_ = t.stdin.SetWriteDeadline(time.Now())
	})
	n, err := t.stdin.Write(data)
	if !stop() {
		<-interrupted // never let it move the next writer's deadline
	}
	if err == nil {
		return nil
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		if ctx.Err() != nil && n == 0 {
			return ctx.Err() // nothing was sent; the stream is intact
		}
		_ = t.cmd.Process.Kill()
		return fmt.Errorf("%w: the server stopped reading its input (write timed out); restarting it", ErrServerUnavailable)
	}
	// The server stopped reading (it exited, or is exiting).
	return fmt.Errorf("%w: write to server: %v", ErrServerUnavailable, err)
}

func (t *stdioTransport) close() error {
	t.mu.Lock()
	already := t.closed
	t.closed = true
	t.mu.Unlock()
	if !already {
		// A well-behaved server exits on EOF. Wait for an in-progress
		// write first, so the close cannot cut a message in half.
		select {
		case t.writeSem <- struct{}{}:
			_ = t.stdin.Close()
			<-t.writeSem
		case <-time.After(2 * time.Second):
		case <-t.exited:
		}
	}
	select {
	case <-t.exited:
	case <-time.After(2 * time.Second):
		_ = t.cmd.Process.Kill()
		<-t.exited
	}
	return nil
}

func (t *stdioTransport) done() <-chan struct{} { return t.exited }

func (t *stdioTransport) err() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.deadErr
}

// ---------------------------------------------------------------------------
// Streamable HTTP transport (also used for "sse")
// ---------------------------------------------------------------------------

type httpTransport struct {
	url     string
	headers map[string]string
	client  *http.Client

	idSeq     atomic.Int64
	mu        sync.Mutex
	sessionID string
}

func newHTTPTransport(cfg ServerConfig) *httpTransport {
	return &httpTransport{
		url:     strings.TrimSpace(cfg.URL),
		headers: cfg.Headers,
		client:  &http.Client{Timeout: 60 * time.Second},
	}
}

func (t *httpTransport) roundTrip(ctx context.Context, method string, params any) (json.RawMessage, error) {
	id := t.idSeq.Add(1)
	req := rpcRequest{JSONRPC: "2.0", ID: &id, Method: method, Params: params}
	resp, err := t.post(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("empty response from mcp server")
	}
	if resp.Error != nil {
		return nil, resp.Error
	}
	return resp.Result, nil
}

func (t *httpTransport) notify(ctx context.Context, method string, params any) error {
	_, err := t.post(ctx, rpcRequest{JSONRPC: "2.0", Method: method, Params: params})
	return err
}

func (t *httpTransport) post(ctx context.Context, payload rpcRequest) (*rpcResponse, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, t.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json, text/event-stream")
	for k, v := range t.headers {
		httpReq.Header.Set(k, v)
	}
	t.mu.Lock()
	sid := t.sessionID
	t.mu.Unlock()
	if sid != "" {
		httpReq.Header.Set("Mcp-Session-Id", sid)
	}

	httpResp, err := t.client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	if sid := httpResp.Header.Get("Mcp-Session-Id"); sid != "" {
		t.mu.Lock()
		t.sessionID = sid
		t.mu.Unlock()
	}

	if httpResp.StatusCode == http.StatusAccepted || httpResp.StatusCode == http.StatusNoContent {
		return nil, nil // notification accepted, no body
	}
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(httpResp.Body, 2048))
		return nil, fmt.Errorf("mcp http %d: %s", httpResp.StatusCode, strings.TrimSpace(string(snippet)))
	}

	ct := httpResp.Header.Get("Content-Type")
	if strings.Contains(ct, "text/event-stream") {
		return parseSSEResponse(httpResp.Body, payload.ID)
	}

	var resp rpcResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&resp); err != nil {
		if err == io.EOF {
			return nil, nil
		}
		return nil, fmt.Errorf("decode mcp response: %w", err)
	}
	return &resp, nil
}

func (t *httpTransport) close() error { return nil }

func (t *httpTransport) done() <-chan struct{} { return nil }

func (t *httpTransport) err() error { return nil }

// parseSSEResponse reads an SSE stream and returns the JSON-RPC response whose
// id matches wantID (or the first response if wantID is nil).
func parseSSEResponse(r io.Reader, wantID *int64) (*rpcResponse, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 8<<20)
	var dataLines []string
	flush := func() (*rpcResponse, bool) {
		if len(dataLines) == 0 {
			return nil, false
		}
		raw := strings.Join(dataLines, "\n")
		dataLines = dataLines[:0]
		var msg rpcMessage
		if err := json.Unmarshal([]byte(raw), &msg); err != nil {
			return nil, false
		}
		if msg.Method != "" {
			return nil, false // a server request or notification, not our response
		}
		resp := msg.response()
		if wantID == nil {
			return &resp, true
		}
		if id, ok := parseRPCID(resp.ID); ok && id == *wantID {
			return &resp, true
		}
		return nil, false
	}
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if resp, ok := flush(); ok {
				return resp, nil
			}
			continue
		}
		if strings.HasPrefix(line, "data:") {
			dataLines = append(dataLines, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	if resp, ok := flush(); ok {
		return resp, nil
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("no matching response in event stream")
}

func hasRPCID(raw json.RawMessage) bool {
	return len(raw) > 0 && string(raw) != "null"
}

func parseRPCID(raw json.RawMessage) (int64, bool) {
	if len(raw) == 0 {
		return 0, false
	}
	var n int64
	if err := json.Unmarshal(raw, &n); err == nil {
		return n, true
	}
	return 0, false
}
