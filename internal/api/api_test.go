package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	internal "github.com/Problem99-io/kodeblue/internal"
	"github.com/Problem99-io/kodeblue/internal/provider"
	"github.com/Problem99-io/kodeblue/internal/state"
)

// mockAgentLoop implements AgentLoopInterface for tests.
type mockAgentLoop struct {
	runAsyncCalled   bool
	runAsyncCount    int
	lastRunMessage   string
	lastRunSessionID string
	lastRunOptions   RunOptions
	compactCalled    bool
	abortCalled      bool
	running          map[string]bool
	runErr           error
	compactResult    CompactResult
	compactResultSet bool
	compactErr       error
}

func newMockAgentLoop() *mockAgentLoop {
	return &mockAgentLoop{running: make(map[string]bool)}
}

func (m *mockAgentLoop) RunAsync(sessionID, runID string, message string, attachments []internal.Attachment, opts RunOptions) error {
	m.runAsyncCalled = true
	m.runAsyncCount++
	m.lastRunMessage = message
	m.lastRunSessionID = sessionID
	m.lastRunOptions = opts
	if m.runErr != nil {
		return m.runErr
	}
	m.running[runID] = true
	return nil
}

func (m *mockAgentLoop) Abort(runID string) bool {
	m.abortCalled = true
	delete(m.running, runID)
	return true
}

func (m *mockAgentLoop) Interrupt(runID string) bool {
	delete(m.running, runID)
	return true
}

type mockSessionMessageQueue struct {
	loop  *mockAgentLoop
	runs  *state.RunRepo
	queue *state.QueueRepo
}

func (m *mockSessionMessageQueue) SubmitUser(sessionID internal.SessionID, content, clientMessageID string, attachments []internal.Attachment, opts RunOptions) (QueueSubmitResult, error) {
	runs, err := m.runs.GetBySession(sessionID)
	if err != nil {
		return QueueSubmitResult{}, err
	}
	for _, run := range runs {
		if run.Status == internal.RunRunning && m.loop.IsRunning(string(run.ID)) {
			item, err := m.queue.Enqueue(&internal.QueueItem{SessionID: sessionID, Source: internal.QueueItemSourceUser, Heading: "User message", Content: content, ClientMessageID: clientMessageID, Attachments: attachments})
			return QueueSubmitResult{Status: "queued", SessionID: sessionID, Item: item}, err
		}
	}
	run := &internal.Run{ID: internal.NewRunID(), SessionID: sessionID, Status: internal.RunRunning, CreatedAt: time.Now()}
	if err := m.runs.Create(run); err != nil {
		return QueueSubmitResult{}, err
	}
	if err := m.loop.RunAsync(string(sessionID), string(run.ID), content, attachments, opts); err != nil {
		return QueueSubmitResult{}, err
	}
	return QueueSubmitResult{Status: "started", SessionID: sessionID, RunID: run.ID}, nil
}

func (m *mockSessionMessageQueue) RemoveQueuedUser(sessionID internal.SessionID, itemID internal.QueueItemID) (bool, error) {
	return m.queue.RemovePending(sessionID, itemID)
}

func (m *mockSessionMessageQueue) UpdateQueuedUser(sessionID internal.SessionID, itemID internal.QueueItemID, content, expectedContent string) (bool, error) {
	return m.queue.UpdatePendingUser(sessionID, itemID, content, expectedContent)
}

func (m *mockSessionMessageQueue) Steer(sessionID internal.SessionID) (QueueActionResult, error) {
	count, err := m.queue.PendingCount(sessionID)
	return QueueActionResult{Status: "interrupting", PendingCount: count}, err
}

func (m *mockSessionMessageQueue) Continue(sessionID internal.SessionID) (QueueActionResult, error) {
	if err := m.queue.SetPaused(sessionID, false); err != nil {
		return QueueActionResult{}, err
	}
	count, err := m.queue.PendingCount(sessionID)
	return QueueActionResult{Status: "idle", PendingCount: count}, err
}

func (m *mockSessionMessageQueue) Pause(sessionID internal.SessionID) error {
	return m.queue.SetPaused(sessionID, true)
}

func (m *mockAgentLoop) CompactSession(_ context.Context, sessionID string, opts RunOptions) (CompactResult, error) {
	m.compactCalled = true
	if m.compactErr != nil {
		return CompactResult{}, m.compactErr
	}
	if !m.compactResultSet {
		return CompactResult{Compacted: true, BeforeActive: 10, AfterActive: 9, TotalHistory: 11}, nil
	}
	return m.compactResult, nil
}

func (m *mockAgentLoop) IsRunning(runID string) bool {
	return m.running[runID]
}

// setupTestDeps creates a temp DB and wired Dependencies for testing.
func setupTestDeps(t *testing.T) (*Dependencies, *mockAgentLoop) {
	t.Helper()
	projectRoot := t.TempDir()
	dbPath := t.TempDir() + "/test.db"
	db, err := state.NewDB(dbPath)
	if err != nil {
		t.Fatalf("failed to create test db: %v", err)
	}
	if err := db.Migrate(); err != nil {
		t.Fatalf("failed to migrate: %v", err)
	}
	if err := db.MigrateAgents(); err != nil {
		t.Fatalf("failed to migrate agents: %v", err)
	}
	t.Cleanup(func() {
		db.Close()
		os.Remove(dbPath)
	})

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	mock := newMockAgentLoop()

	queueRepo := state.NewQueueRepo(db)
	deps := &Dependencies{
		DB:          db,
		Sessions:    state.NewSessionRepo(db),
		Runs:        state.NewRunRepo(db),
		Messages:    state.NewMessageRepo(db),
		Queue:       queueRepo,
		Events:      state.NewEventRepo(db),
		Questions:   state.NewPendingQuestionRepo(db),
		Agents:      state.NewAgentRepo(db),
		Providers:   provider.NewRegistry(),
		AgentLoop:   mock,
		EventHub:    NewEventHub(logger),
		Logger:      logger,
		ProjectRoot: projectRoot,
	}
	deps.MessageQueue = &mockSessionMessageQueue{loop: mock, runs: deps.Runs, queue: queueRepo}
	return deps, mock
}

func TestAgentMaxOutputTokensAPI(t *testing.T) {
	deps, _ := setupTestDeps(t)
	router := NewRouter(deps)

	create := httptest.NewRequest(http.MethodPost, "/v1/agents", strings.NewReader(`{"name":"limited","reasoning_effort":"HIGH","max_output_tokens":16384}`))
	created := httptest.NewRecorder()
	router.ServeHTTP(created, create)
	if created.Code != http.StatusCreated {
		t.Fatalf("create status = %d: %s", created.Code, created.Body.String())
	}
	var agent internal.AgentDefinition
	if err := json.NewDecoder(created.Body).Decode(&agent); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if agent.MaxOutputTokens != 16384 {
		t.Fatalf("create max_output_tokens = %d, want 16384", agent.MaxOutputTokens)
	}
	if agent.ReasoningEffort != "high" {
		t.Fatalf("create reasoning_effort = %q, want high", agent.ReasoningEffort)
	}

	update := httptest.NewRequest(http.MethodPatch, "/v1/agents/"+agent.ID, strings.NewReader(`{"max_output_tokens":0}`))
	updated := httptest.NewRecorder()
	router.ServeHTTP(updated, update)
	if updated.Code != http.StatusOK {
		t.Fatalf("update status = %d: %s", updated.Code, updated.Body.String())
	}
	if got, err := deps.Agents.Get(agent.ID); err != nil || got == nil || got.MaxOutputTokens != 0 {
		t.Fatalf("updated agent = %#v, err=%v; want zero output limit", got, err)
	}

	unbounded := httptest.NewRequest(http.MethodPost, "/v1/agents", strings.NewReader(`{"name":"unbounded","max_output_tokens":-1}`))
	unboundedResponse := httptest.NewRecorder()
	router.ServeHTTP(unboundedResponse, unbounded)
	if unboundedResponse.Code != http.StatusCreated {
		t.Fatalf("unbounded limit response = %d: %s", unboundedResponse.Code, unboundedResponse.Body.String())
	}

	invalidNegative := httptest.NewRequest(http.MethodPost, "/v1/agents", strings.NewReader(`{"name":"invalid","max_output_tokens":-2}`))
	invalid := httptest.NewRecorder()
	router.ServeHTTP(invalid, invalidNegative)
	if invalid.Code != http.StatusBadRequest || !strings.Contains(invalid.Body.String(), "must be -1 or between 0 and 1000000") {
		t.Fatalf("invalid negative limit response = %d: %s", invalid.Code, invalid.Body.String())
	}

	badEffort := httptest.NewRequest(http.MethodPatch, "/v1/agents/"+agent.ID, strings.NewReader(`{"reasoning_effort":"turbo"}`))
	badEffortResponse := httptest.NewRecorder()
	router.ServeHTTP(badEffortResponse, badEffort)
	if badEffortResponse.Code != http.StatusBadRequest || !strings.Contains(badEffortResponse.Body.String(), "reasoning_effort") {
		t.Fatalf("invalid reasoning effort response = %d: %s", badEffortResponse.Code, badEffortResponse.Body.String())
	}
}

type fakeModelProvider struct {
	name         string
	defaultModel string
	models       []string
}

func (f *fakeModelProvider) Name() string { return f.name }

func (f *fakeModelProvider) Stream(ctx context.Context, req *provider.Request) (<-chan provider.StreamEvent, error) {
	ch := make(chan provider.StreamEvent)
	close(ch)
	return ch, nil
}

func (f *fakeModelProvider) CountTokens(ctx context.Context, req *provider.Request) (*provider.Usage, error) {
	return &provider.Usage{InputTokens: 1}, nil
}

func (f *fakeModelProvider) DefaultModel() string { return f.defaultModel }

func (f *fakeModelProvider) Models(ctx context.Context) ([]string, error) {
	return append([]string(nil), f.models...), nil
}

func TestHealthEndpoint(t *testing.T) {
	deps, _ := setupTestDeps(t)
	router := NewRouter(deps)

	req := httptest.NewRequest("GET", "/v1/health", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "ok" {
		t.Errorf("expected status=ok, got %v", resp["status"])
	}
}

func TestSessionEventHistoryExcludesTokenEventsByDefault(t *testing.T) {
	deps, _ := setupTestDeps(t)
	now := time.Now()
	session := &internal.Session{ID: internal.NewSessionID(), Status: internal.SessionActive, CreatedAt: now, UpdatedAt: now}
	if err := deps.Sessions.Create(session); err != nil {
		t.Fatal(err)
	}
	for _, eventType := range []string{internal.EventModelToken, internal.EventModelCompleted} {
		event := &internal.Event{Type: eventType, Timestamp: now, SessionID: session.ID, RunID: internal.NewRunID(), Payload: json.RawMessage(`{}`)}
		if err := deps.Events.Append(event); err != nil {
			t.Fatal(err)
		}
	}

	router := NewRouter(deps)
	req := httptest.NewRequest(http.MethodGet, "/v1/sessions/"+string(session.ID)+"/events/history", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var events []internal.Event
	if err := json.NewDecoder(w.Body).Decode(&events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Type != internal.EventModelCompleted {
		t.Fatalf("unexpected event history: %#v", events)
	}
}

func TestListProviderModels(t *testing.T) {
	deps, _ := setupTestDeps(t)
	deps.Providers.Register("openai", &fakeModelProvider{
		name:         "openai",
		defaultModel: "gpt-5.4-nano",
		models:       []string{"gpt-5.4-nano", "gpt-5.4-mini"},
	})
	deps.Providers.Register("anthropic", &fakeModelProvider{
		name:         "anthropic",
		defaultModel: "claude-sonnet-4-6",
		models:       []string{"claude-sonnet-4-6"},
	})

	router := NewRouter(deps)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/v1/providers/models", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Providers []struct {
			Provider     string   `json:"provider"`
			DefaultModel string   `json:"default_model"`
			Models       []string `json:"models"`
		} `json:"providers"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Providers) != 2 {
		t.Fatalf("expected 2 providers, got %d", len(resp.Providers))
	}
}

func TestCreateSession(t *testing.T) {
	deps, _ := setupTestDeps(t)
	router := NewRouter(deps)

	body, _ := json.Marshal(map[string]any{
		"provider": "anthropic",
		"model":    "claude-sonnet-4-6",
	})
	req := httptest.NewRequest("POST", "/v1/sessions", bytes.NewReader(body))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var session internal.Session
	json.NewDecoder(w.Body).Decode(&session)
	if session.ID == "" {
		t.Error("session ID should not be empty")
	}
	if session.Provider != "anthropic" {
		t.Errorf("expected provider=anthropic, got %s", session.Provider)
	}
	if session.Status != internal.SessionActive {
		t.Errorf("expected status=active, got %s", session.Status)
	}
}

func TestGetSession(t *testing.T) {
	deps, _ := setupTestDeps(t)
	router := NewRouter(deps)

	// Create
	body, _ := json.Marshal(map[string]any{"provider": "anthropic", "model": "test"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/v1/sessions", bytes.NewReader(body)))
	var created internal.Session
	json.NewDecoder(w.Body).Decode(&created)

	// Get
	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/v1/sessions/"+string(created.ID), nil))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var got internal.Session
	json.NewDecoder(w.Body).Decode(&got)
	if got.ID != created.ID {
		t.Errorf("expected ID %s, got %s", created.ID, got.ID)
	}
}

func TestGetSessionNotFound(t *testing.T) {
	deps, _ := setupTestDeps(t)
	router := NewRouter(deps)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/v1/sessions/sess_nonexistent", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestListSessions(t *testing.T) {
	deps, _ := setupTestDeps(t)
	router := NewRouter(deps)

	// Create 2 sessions
	for i := 0; i < 2; i++ {
		body, _ := json.Marshal(map[string]any{"provider": "test", "model": "m"})
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("POST", "/v1/sessions", bytes.NewReader(body)))
	}

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/v1/sessions", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var sessions []internal.Session
	json.NewDecoder(w.Body).Decode(&sessions)
	if len(sessions) != 2 {
		t.Errorf("expected 2 sessions, got %d", len(sessions))
	}
}

func TestSendMessage(t *testing.T) {
	deps, mock := setupTestDeps(t)
	router := NewRouter(deps)

	// Create session
	body, _ := json.Marshal(map[string]any{"provider": "anthropic", "model": "test"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/v1/sessions", bytes.NewReader(body)))
	var session internal.Session
	json.NewDecoder(w.Body).Decode(&session)

	// Send message
	msgBody, _ := json.Marshal(map[string]string{"content": "hello"})
	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/v1/sessions/"+string(session.ID)+"/messages", bytes.NewReader(msgBody)))

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", w.Code, w.Body.String())
	}
	if !mock.runAsyncCalled {
		t.Error("expected RunAsync to be called")
	}

	var run internal.Run
	json.NewDecoder(w.Body).Decode(&run)
	if run.ID == "" {
		t.Error("run ID should not be empty")
	}
	if run.SessionID != session.ID {
		t.Errorf("run session ID mismatch: expected %s got %s", session.ID, run.SessionID)
	}
}

func TestSendMessageQueuesWhenRunAlreadyActive(t *testing.T) {
	deps, mock := setupTestDeps(t)
	router := NewRouter(deps)

	// Create session
	body, _ := json.Marshal(map[string]any{"provider": "anthropic", "model": "test"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/v1/sessions", bytes.NewReader(body)))
	var session internal.Session
	json.NewDecoder(w.Body).Decode(&session)

	// First message starts an active run.
	msgBody, _ := json.Marshal(map[string]string{"content": "first"})
	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/v1/sessions/"+string(session.ID)+"/messages", bytes.NewReader(msgBody)))
	if w.Code != http.StatusAccepted {
		t.Fatalf("expected first send 202, got %d: %s", w.Code, w.Body.String())
	}
	var firstRun internal.Run
	json.NewDecoder(w.Body).Decode(&firstRun)
	if !mock.IsRunning(string(firstRun.ID)) {
		t.Fatalf("expected first run to be active")
	}

	// Second message is accepted into the durable inbox while the first run is active.
	secondBody, _ := json.Marshal(map[string]string{"content": "second"})
	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/v1/sessions/"+string(session.ID)+"/messages", bytes.NewReader(secondBody)))
	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Status string              `json:"status"`
		Item   *internal.QueueItem `json:"queue_item"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode queued response: %v", err)
	}
	if resp.Status != "queued" || resp.Item == nil || resp.Item.Content != "second" {
		t.Fatalf("unexpected queued response: %#v", resp)
	}
	if mock.runAsyncCount != 1 {
		t.Fatalf("queued message started a concurrent run: count=%d", mock.runAsyncCount)
	}
}

func TestSessionQueueEndpointsListAndRemove(t *testing.T) {
	deps, mock := setupTestDeps(t)
	router := NewRouter(deps)
	session := &internal.Session{ID: internal.NewSessionID(), Status: internal.SessionActive, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := deps.Sessions.Create(session); err != nil {
		t.Fatal(err)
	}
	active := &internal.Run{ID: internal.NewRunID(), SessionID: session.ID, Status: internal.RunRunning, CreatedAt: time.Now()}
	if err := deps.Runs.Create(active); err != nil {
		t.Fatal(err)
	}
	mock.running[string(active.ID)] = true

	requestBody := strings.NewReader(`{"content":"queued user","client_message_id":"client-42","attachments":[{"media_type":"text/plain","file_name":"note.txt","data":"c2VjcmV0"}]}`)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/v1/sessions/"+string(session.ID)+"/messages", requestBody))
	if w.Code != http.StatusAccepted {
		t.Fatalf("queue user status = %d: %s", w.Code, w.Body.String())
	}
	var submit struct {
		Item *internal.QueueItem `json:"queue_item"`
	}
	if err := json.NewDecoder(w.Body).Decode(&submit); err != nil || submit.Item == nil {
		t.Fatalf("decode queued item: %#v, %v", submit, err)
	}

	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/v1/sessions/"+string(session.ID)+"/queue", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("list queue status = %d: %s", w.Code, w.Body.String())
	}
	var list sessionQueueResponse
	if err := json.NewDecoder(w.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	if list.Count != 1 || len(list.Items) != 1 {
		t.Fatalf("queue count = %d items=%d, want 1", list.Count, len(list.Items))
	}
	if len(list.Items[0].Attachments) != 1 || list.Items[0].Attachments[0].Data != "" {
		t.Fatalf("queue API leaked or lost attachment descriptor: %#v", list.Items[0].Attachments)
	}

	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/v1/sessions/"+string(session.ID)+"/queue/"+string(submit.Item.ID), nil))
	if w.Code != http.StatusOK {
		t.Fatalf("user removal status = %d: %s", w.Code, w.Body.String())
	}
}

func TestSessionQueueContinueUnpausesPreservedMessages(t *testing.T) {
	deps, _ := setupTestDeps(t)
	router := NewRouter(deps)
	session := &internal.Session{ID: internal.NewSessionID(), Status: internal.SessionActive, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := deps.Sessions.Create(session); err != nil {
		t.Fatal(err)
	}
	if _, err := deps.Queue.Enqueue(&internal.QueueItem{SessionID: session.ID, Source: internal.QueueItemSourceUser, Content: "preserved"}); err != nil {
		t.Fatal(err)
	}
	if err := deps.Queue.SetPaused(session.ID, true); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/v1/sessions/"+string(session.ID)+"/queue/continue", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("continue status = %d: %s", w.Code, w.Body.String())
	}
	paused, err := deps.Queue.IsPaused(session.ID)
	if err != nil || paused {
		t.Fatalf("queue remained paused: paused=%t err=%v", paused, err)
	}
	if count, _ := deps.Queue.PendingCount(session.ID); count != 1 {
		t.Fatalf("continue removed queued messages: count=%d", count)
	}
}

func TestSendMessageEmptyContent(t *testing.T) {
	deps, _ := setupTestDeps(t)
	router := NewRouter(deps)

	// Create session
	body, _ := json.Marshal(map[string]any{"provider": "test", "model": "m"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/v1/sessions", bytes.NewReader(body)))
	var session internal.Session
	json.NewDecoder(w.Body).Decode(&session)

	// Send empty message
	msgBody, _ := json.Marshal(map[string]string{"content": ""})
	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/v1/sessions/"+string(session.ID)+"/messages", bytes.NewReader(msgBody)))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty content, got %d", w.Code)
	}
}

func TestSendMessageSessionNotFound(t *testing.T) {
	deps, _ := setupTestDeps(t)
	router := NewRouter(deps)

	msgBody, _ := json.Marshal(map[string]string{"content": "hello"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/v1/sessions/sess_nonexistent/messages", bytes.NewReader(msgBody)))

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestCompactSession(t *testing.T) {
	deps, mock := setupTestDeps(t)
	router := NewRouter(deps)

	// Create session
	body, _ := json.Marshal(map[string]any{"provider": "openai", "model": "gpt-5.4-nano"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/v1/sessions", bytes.NewReader(body)))
	var session internal.Session
	json.NewDecoder(w.Body).Decode(&session)

	mock.compactResult = CompactResult{
		Compacted:          true,
		BeforeActive:       20,
		AfterActive:        9,
		TotalHistory:       21,
		InputTokens:        84000,
		CompactedMessages:  11,
		SummaryInputTokens: 2048,
		UsedLLMSummary:     true,
		Summary: &CompactionSummaryResult{
			Content: "Current Task:\n- compact the session\n\nRemaining Tasks:\n- none",
			Model:   "gpt-5.4-nano",
			Usage: &internal.MessageUsage{
				InputTokens:              120,
				OutputTokens:             48,
				CacheCreationInputTokens: 0,
				CacheReadInputTokens:     3200,
			},
		},
	}
	mock.compactResultSet = true

	reqBody, _ := json.Marshal(map[string]any{"provider": "openai", "model": "gpt-5.4-nano"})
	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/v1/sessions/"+string(session.ID)+"/compact", bytes.NewReader(reqBody)))

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !mock.compactCalled {
		t.Fatalf("expected CompactSession to be called")
	}

	var resp CompactResult
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Compacted || resp.AfterActive != 9 {
		t.Fatalf("unexpected compact response: %+v", resp)
	}
	if resp.Summary == nil || resp.Summary.Content == "" {
		t.Fatalf("expected compaction summary content in response: %+v", resp)
	}
	if resp.Summary.Usage == nil || resp.Summary.Usage.CacheReadInputTokens != 3200 {
		t.Fatalf("expected summary usage in response: %+v", resp)
	}
}

func TestCompactSessionBusyReturnsConflict(t *testing.T) {
	deps, mock := setupTestDeps(t)
	router := NewRouter(deps)
	body, _ := json.Marshal(map[string]any{"provider": "openai", "model": "gpt-5.4-nano"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/v1/sessions", bytes.NewReader(body)))
	var session internal.Session
	json.NewDecoder(w.Body).Decode(&session)

	// A run in another runtime holds the session lease: the run check in the
	// handler cannot see it, CompactSession can.
	mock.compactErr = fmt.Errorf("compact session %s: %w", session.ID, ErrSessionBusy)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/v1/sessions/"+string(session.ID)+"/compact", nil))
	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetSessionState(t *testing.T) {
	deps, _ := setupTestDeps(t)
	router := NewRouter(deps)

	// Create session
	body, _ := json.Marshal(map[string]any{"provider": "test", "model": "m"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/v1/sessions", bytes.NewReader(body)))
	var session internal.Session
	json.NewDecoder(w.Body).Decode(&session)

	// Get state
	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/v1/sessions/"+string(session.ID)+"/state", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var stateResp sessionStateResponse
	json.NewDecoder(w.Body).Decode(&stateResp)
	if stateResp.Session.ID != session.ID {
		t.Errorf("state session ID mismatch")
	}
}

func TestGetSessionMessages(t *testing.T) {
	deps, _ := setupTestDeps(t)
	router := NewRouter(deps)

	// Create session
	body, _ := json.Marshal(map[string]any{"provider": "openai", "model": "gpt-5.4-nano"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/v1/sessions", bytes.NewReader(body)))
	var session internal.Session
	json.NewDecoder(w.Body).Decode(&session)

	// Seed persisted message history
	err := deps.Messages.Create(session.ID, "run_1", &internal.Message{
		ID:               "msg_1",
		Role:             "assistant",
		Content:          "hello",
		ReasoningContent: "internal-only reasoning",
		CreatedAt:        time.Now(),
	})
	if err != nil {
		t.Fatalf("failed to seed message: %v", err)
	}

	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/v1/sessions/"+string(session.ID)+"/messages", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	bodyBytes := w.Body.Bytes()
	var messages []internal.Message
	if err := json.Unmarshal(bodyBytes, &messages); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(messages))
	}
	if messages[0].Content != "hello" {
		t.Fatalf("expected message content hello, got %q", messages[0].Content)
	}
	var rawMessages []map[string]any
	if err := json.Unmarshal(bodyBytes, &rawMessages); err != nil {
		t.Fatalf("failed to decode raw response: %v", err)
	}
	if _, ok := rawMessages[0]["reasoning_content"]; ok {
		t.Fatal("session messages response should omit reasoning_content")
	}
}

func TestGetSessionMessagesIncludeReasoningOptIn(t *testing.T) {
	deps, _ := setupTestDeps(t)
	router := NewRouter(deps)
	body, _ := json.Marshal(map[string]any{"provider": "openai", "model": "gpt-5.4-nano"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/v1/sessions", bytes.NewReader(body)))
	var session internal.Session
	json.NewDecoder(w.Body).Decode(&session)
	if err := deps.Messages.Create(session.ID, "run_1", &internal.Message{ID: "msg_1", Role: "assistant", Content: "hello", ReasoningContent: "why", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/v1/sessions/"+string(session.ID)+"/messages?include_reasoning=1", nil))
	var raw []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil || len(raw) != 1 {
		t.Fatalf("decode: %v %s", err, w.Body.String())
	}
	if raw[0]["reasoning_content"] != "why" {
		t.Fatalf("expected reasoning with include_reasoning=1, got %v", raw[0]["reasoning_content"])
	}
}

func TestGetSessionPending(t *testing.T) {
	deps, _ := setupTestDeps(t)
	router := NewRouter(deps)

	// Create session
	body, _ := json.Marshal(map[string]any{"provider": "openai", "model": "gpt-5.4-nano"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/v1/sessions", bytes.NewReader(body)))
	var session internal.Session
	json.NewDecoder(w.Body).Decode(&session)

	run := &internal.Run{
		ID:        internal.NewRunID(),
		SessionID: session.ID,
		Status:    internal.RunRunning,
		CreatedAt: time.Now(),
	}
	if err := deps.Runs.Create(run); err != nil {
		t.Fatalf("failed to create run: %v", err)
	}

	deps.EventHub.RegisterQuestionWait(internal.PendingQuestion{
		QuestionID: "qst_pending_1",
		SessionID:  session.ID,
		RunID:      run.ID,
		Title:      "Need info",
		Question:   "What should we do?",
		Mode:       "single_select",
		Options:    []string{"A", "B"},
		CreatedAt:  time.Now(),
	})

	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/v1/sessions/"+string(session.ID)+"/pending", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		SessionID        string                     `json:"session_id"`
		PendingQuestions []internal.PendingQuestion `json:"pending_questions"`
		TotalPending     int                        `json:"total_pending"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.SessionID != string(session.ID) {
		t.Fatalf("expected session_id %s, got %s", session.ID, resp.SessionID)
	}
	if len(resp.PendingQuestions) != 1 {
		t.Fatalf("expected 1 pending question, got %d", len(resp.PendingQuestions))
	}
	if resp.PendingQuestions[0].QuestionID != "qst_pending_1" {
		t.Fatalf("unexpected question id: %s", resp.PendingQuestions[0].QuestionID)
	}
	if resp.TotalPending != 1 {
		t.Fatalf("expected total_pending=1, got %d", resp.TotalPending)
	}

	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/v1/sessions/"+string(session.ID)+"/status", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var runtimeStatus sessionRuntimeStatusResponse
	if err := json.NewDecoder(w.Body).Decode(&runtimeStatus); err != nil {
		t.Fatal(err)
	}
	if runtimeStatus.PendingQuestions != 1 {
		t.Fatalf("status pending questions = %d, want 1", runtimeStatus.PendingQuestions)
	}
}

func TestAnswerStoredPendingQuestionAfterRestart(t *testing.T) {
	deps, mock := setupTestDeps(t)
	router := NewRouter(deps)

	body, _ := json.Marshal(map[string]any{"provider": "openai", "model": "gpt-5.4-nano"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/v1/sessions", bytes.NewReader(body)))
	var session internal.Session
	json.NewDecoder(w.Body).Decode(&session)

	run := &internal.Run{
		ID:        internal.NewRunID(),
		SessionID: session.ID,
		Status:    internal.RunRunning,
		CreatedAt: time.Now(),
	}
	if err := deps.Runs.Create(run); err != nil {
		t.Fatalf("failed to create run: %v", err)
	}

	question := internal.PendingQuestion{
		QuestionID: "qst_stored_restart",
		SessionID:  session.ID,
		RunID:      run.ID,
		Question:   "Continue after restart?",
		Mode:       "single_select",
		Options:    []string{"Yes", "No", "Later"},
		CreatedAt:  time.Now(),
	}
	if err := deps.Questions.Create(question); err != nil {
		t.Fatalf("failed to store question: %v", err)
	}

	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/v1/sessions/"+string(session.ID)+"/pending", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("expected pending 200, got %d: %s", w.Code, w.Body.String())
	}
	var pendingResp struct {
		PendingQuestions []internal.PendingQuestion `json:"pending_questions"`
	}
	if err := json.NewDecoder(w.Body).Decode(&pendingResp); err != nil {
		t.Fatalf("decode pending response: %v", err)
	}
	if len(pendingResp.PendingQuestions) != 1 || pendingResp.PendingQuestions[0].QuestionID != question.QuestionID {
		t.Fatalf("expected stored pending question, got %+v", pendingResp.PendingQuestions)
	}

	answerBody, _ := json.Marshal(map[string]any{"mode": "single_select", "choices": []string{"Yes"}})
	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/v1/questions/"+question.QuestionID+"/answer", bytes.NewReader(answerBody)))
	if w.Code != http.StatusOK {
		t.Fatalf("expected answer 200, got %d: %s", w.Code, w.Body.String())
	}

	_, status, err := deps.Questions.Get(question.QuestionID)
	if err != nil {
		t.Fatalf("get question: %v", err)
	}
	if status != state.PendingQuestionStatusAnswered {
		t.Fatalf("expected answered status, got %s", status)
	}

	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/v1/sessions/"+string(session.ID)+"/pending", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("expected pending 200 after answer, got %d: %s", w.Code, w.Body.String())
	}
	pendingResp.PendingQuestions = nil
	if err := json.NewDecoder(w.Body).Decode(&pendingResp); err != nil {
		t.Fatalf("decode pending response after answer: %v", err)
	}
	if len(pendingResp.PendingQuestions) != 0 {
		t.Fatalf("expected no pending questions after answer, got %+v", pendingResp.PendingQuestions)
	}

	// Because no live agent consumed the answer (the run was interrupted), the
	// handler should have resumed the run as a fresh dispatch carrying the answer.
	if !mock.runAsyncCalled || mock.runAsyncCount != 1 {
		t.Fatalf("expected exactly one resume RunAsync call, got called=%v count=%d", mock.runAsyncCalled, mock.runAsyncCount)
	}
	if mock.lastRunSessionID != string(session.ID) {
		t.Fatalf("expected resume on session %s, got %s", session.ID, mock.lastRunSessionID)
	}
	if !strings.Contains(mock.lastRunMessage, "Yes") || !strings.Contains(mock.lastRunMessage, "Continue after restart?") {
		t.Fatalf("expected resume message to carry the question and answer, got %q", mock.lastRunMessage)
	}
	if mock.lastRunOptions.QuestionID != question.QuestionID {
		t.Fatal("lost question attribution")
	}
	// Reconnecting is read-only; replaying an answered POST must not dispatch again.
	router = NewRouter(deps)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/v1/sessions/"+string(session.ID)+"/pending", nil))
	if w.Code != http.StatusOK {
		t.Fatal(w.Code)
	}
	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/v1/questions/"+question.QuestionID+"/answer", bytes.NewReader(answerBody)))
	if w.Code != http.StatusConflict || mock.runAsyncCount != 1 {
		t.Fatalf("replay dispatched: status=%d runs=%d", w.Code, mock.runAsyncCount)
	}
}

func TestAnswerBatchPendingQuestionsResumesOnceAfterRestart(t *testing.T) {
	deps, mock := setupTestDeps(t)
	router := NewRouter(deps)

	body, _ := json.Marshal(map[string]any{"provider": "openai", "model": "gpt-5.4-nano"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/v1/sessions", bytes.NewReader(body)))
	var session internal.Session
	json.NewDecoder(w.Body).Decode(&session)

	run := &internal.Run{ID: internal.NewRunID(), SessionID: session.ID, Status: internal.RunRunning, CreatedAt: time.Now()}
	if err := deps.Runs.Create(run); err != nil {
		t.Fatalf("failed to create run: %v", err)
	}

	questions := []internal.PendingQuestion{
		{QuestionID: "qst_batch_1", SessionID: session.ID, RunID: run.ID, Question: "Framework?", Mode: "single_select", Options: []string{"React", "Vue", "Svelte"}, CreatedAt: time.Now()},
		{QuestionID: "qst_batch_2", SessionID: session.ID, RunID: run.ID, Question: "Database?", Mode: "single_select", Options: []string{"Postgres", "MySQL", "SQLite"}, CreatedAt: time.Now()},
	}
	for i := range questions {
		if err := deps.Questions.Create(questions[i]); err != nil {
			t.Fatalf("failed to store question: %v", err)
		}
	}

	// Answer the first question: still one pending, so no resume yet.
	answer1, _ := json.Marshal(map[string]any{"mode": "single_select", "choices": []string{"React"}})
	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/v1/questions/qst_batch_1/answer", bytes.NewReader(answer1)))
	if w.Code != http.StatusOK {
		t.Fatalf("expected answer 200, got %d: %s", w.Code, w.Body.String())
	}
	if mock.runAsyncCalled {
		t.Fatalf("did not expect resume before all questions answered")
	}

	// Answer the last question: the batch is complete, so resume exactly once.
	answer2, _ := json.Marshal(map[string]any{"mode": "single_select", "choices": []string{"Postgres"}, "text": "exact custom user reply"})
	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/v1/questions/qst_batch_2/answer", bytes.NewReader(answer2)))
	if w.Code != http.StatusOK {
		t.Fatalf("expected answer 200, got %d: %s", w.Code, w.Body.String())
	}
	if mock.runAsyncCount != 1 {
		t.Fatalf("expected exactly one resume RunAsync call for the batch, got %d", mock.runAsyncCount)
	}
	if !strings.Contains(mock.lastRunMessage, "React") || !strings.Contains(mock.lastRunMessage, "Postgres") {
		t.Fatalf("expected resume message to carry both answers, got %q", mock.lastRunMessage)
	}
	if !strings.Contains(mock.lastRunMessage, "exact custom user reply") {
		t.Fatal("lost recovered free-text answer")
	}
}

// A continuation checkpoint answered after its run died is still a decision
// about that run: "no" must not quietly restart the work it declined.
func TestDeclinedContinuationCheckpointDoesNotResumeRun(t *testing.T) {
	deps, mock := setupTestDeps(t)
	router := NewRouter(deps)

	session, run := seedSessionAndRun(t, deps, router)
	if err := deps.Questions.Create(internal.PendingQuestion{
		QuestionID: "qst_cont_stop",
		SessionID:  session.ID,
		RunID:      run.ID,
		Kind:       internal.QuestionKindContinuation,
		Title:      "Keep going?",
		Question:   "This run has taken 200 tool-calling turns without finishing. Keep going?",
		Mode:       "single_select",
		Options:    []string{internal.ContinueYesOption, internal.ContinueNoOption},
		CreatedAt:  time.Now(),
	}); err != nil {
		t.Fatalf("failed to store question: %v", err)
	}

	answer, _ := json.Marshal(map[string]any{"mode": "single_select", "choices": []string{internal.ContinueNoOption}})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/v1/questions/qst_cont_stop/answer", bytes.NewReader(answer)))
	if w.Code != http.StatusOK {
		t.Fatalf("expected answer 200, got %d: %s", w.Code, w.Body.String())
	}
	if mock.runAsyncCalled {
		t.Fatalf("declining a continuation checkpoint must not resume the run, message was %q", mock.lastRunMessage)
	}
}

// "Yes" after a restart resumes the run, and the checkpoint — which the agent
// never asked — is not replayed back at it as one of its own questions.
func TestAcceptedContinuationCheckpointResumesWithoutQuotingItself(t *testing.T) {
	deps, mock := setupTestDeps(t)
	router := NewRouter(deps)

	session, run := seedSessionAndRun(t, deps, router)
	if err := deps.Questions.Create(internal.PendingQuestion{
		QuestionID: "qst_cont_go",
		SessionID:  session.ID,
		RunID:      run.ID,
		Kind:       internal.QuestionKindContinuation,
		Title:      "Keep going?",
		Question:   "This run has taken 200 tool-calling turns without finishing. Keep going?",
		Mode:       "single_select",
		Options:    []string{internal.ContinueYesOption, internal.ContinueNoOption},
		CreatedAt:  time.Now(),
	}); err != nil {
		t.Fatalf("failed to store question: %v", err)
	}

	answer, _ := json.Marshal(map[string]any{"mode": "single_select", "text": "finish the migration first"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/v1/questions/qst_cont_go/answer", bytes.NewReader(answer)))
	if w.Code != http.StatusOK {
		t.Fatalf("expected answer 200, got %d: %s", w.Code, w.Body.String())
	}
	if mock.runAsyncCount != 1 {
		t.Fatalf("expected exactly one resume RunAsync call, got %d", mock.runAsyncCount)
	}
	if mock.lastRunOptions.QuestionID != "" {
		t.Fatalf("continuation must not be attributed to a question: %+v", mock.lastRunOptions)
	}
	if !strings.Contains(mock.lastRunMessage, "finish the migration first") {
		t.Fatalf("expected the typed guidance to reach the resumed run, got %q", mock.lastRunMessage)
	}
	if strings.Contains(mock.lastRunMessage, "tool-calling turns") {
		t.Fatalf("the checkpoint must not be quoted back as a question the agent asked, got %q", mock.lastRunMessage)
	}
}

func seedSessionAndRun(t *testing.T, deps *Dependencies, router http.Handler) (internal.Session, *internal.Run) {
	t.Helper()

	body, _ := json.Marshal(map[string]any{"provider": "openai", "model": "gpt-5.4-nano"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/v1/sessions", bytes.NewReader(body)))
	var session internal.Session
	if err := json.NewDecoder(w.Body).Decode(&session); err != nil {
		t.Fatalf("decode session: %v", err)
	}

	run := &internal.Run{ID: internal.NewRunID(), SessionID: session.ID, Status: internal.RunRunning, CreatedAt: time.Now()}
	if err := deps.Runs.Create(run); err != nil {
		t.Fatalf("failed to create run: %v", err)
	}
	return session, run
}

func TestGetSessionMessagesNormalizesArrayFields(t *testing.T) {
	deps, _ := setupTestDeps(t)
	router := NewRouter(deps)

	body, _ := json.Marshal(map[string]any{"provider": "openai", "model": "gpt-5.4-nano"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/v1/sessions", bytes.NewReader(body)))
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var session internal.Session
	if err := json.NewDecoder(w.Body).Decode(&session); err != nil {
		t.Fatalf("decode session: %v", err)
	}

	if err := deps.Messages.Create(session.ID, "run_1", &internal.Message{
		ID:        "msg_norm_1",
		Role:      "assistant",
		Content:   "",
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("failed to seed message: %v", err)
	}

	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/v1/sessions/"+string(session.ID)+"/messages", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var messages []struct {
		ID          string                `json:"id"`
		Attachments []internal.Attachment `json:"attachments"`
		ToolCalls   []internal.ToolCall   `json:"tool_calls"`
		ToolResults []internal.ToolResult `json:"tool_results"`
	}
	if err := json.NewDecoder(w.Body).Decode(&messages); err != nil {
		t.Fatalf("decode messages: %v", err)
	}
	if len(messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(messages))
	}
	if messages[0].Attachments == nil {
		t.Fatal("attachments should decode as an empty array, got nil")
	}
	if messages[0].ToolCalls == nil {
		t.Fatal("tool_calls should decode as an empty array, got nil")
	}
	if messages[0].ToolResults == nil {
		t.Fatal("tool_results should decode as an empty array, got nil")
	}
	if len(messages[0].Attachments) != 0 || len(messages[0].ToolCalls) != 0 || len(messages[0].ToolResults) != 0 {
		t.Fatal("expected normalized array fields to be empty")
	}
}

func TestIgnorePendingQuestion(t *testing.T) {
	deps, _ := setupTestDeps(t)
	router := NewRouter(deps)

	body, _ := json.Marshal(map[string]any{"provider": "openai", "model": "gpt-5.4-nano"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/v1/sessions", bytes.NewReader(body)))
	var session internal.Session
	json.NewDecoder(w.Body).Decode(&session)

	run := &internal.Run{
		ID:        internal.NewRunID(),
		SessionID: session.ID,
		Status:    internal.RunRunning,
		CreatedAt: time.Now(),
	}
	if err := deps.Runs.Create(run); err != nil {
		t.Fatalf("failed to create run: %v", err)
	}

	deps.EventHub.RegisterQuestionWait(internal.PendingQuestion{
		QuestionID: "qst_to_ignore",
		SessionID:  session.ID,
		RunID:      run.ID,
		Question:   "Ignore this?",
		Mode:       "single_select",
		CreatedAt:  time.Now(),
	})

	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("DELETE", "/v1/sessions/"+string(session.ID)+"/pending/questions/qst_to_ignore", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/v1/sessions/"+string(session.ID)+"/pending", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		PendingQuestions []internal.PendingQuestion `json:"pending_questions"`
		TotalPending     int                        `json:"total_pending"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode pending response: %v", err)
	}
	if len(resp.PendingQuestions) != 0 {
		t.Fatalf("expected no pending questions, got %d", len(resp.PendingQuestions))
	}
}

func TestAbortNoActiveRun(t *testing.T) {
	deps, _ := setupTestDeps(t)
	router := NewRouter(deps)

	// Create session
	body, _ := json.Marshal(map[string]any{"provider": "test", "model": "m"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/v1/sessions", bytes.NewReader(body)))
	var session internal.Session
	json.NewDecoder(w.Body).Decode(&session)

	// Abort with no runs
	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/v1/sessions/"+string(session.ID)+"/abort", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	paused, err := deps.Queue.IsPaused(session.ID)
	if err != nil || !paused {
		t.Fatalf("idle stop must freeze delivery for late background reports: paused=%v err=%v", paused, err)
	}

	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/v1/sessions/sess_missing/abort", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown session abort = %d, want 404: %s", w.Code, w.Body.String())
	}
}
