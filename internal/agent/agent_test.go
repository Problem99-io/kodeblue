package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	internal "github.com/Problem99-io/kodeblue/internal"
	"github.com/Problem99-io/kodeblue/internal/policy"
	"github.com/Problem99-io/kodeblue/internal/provider"
	"github.com/Problem99-io/kodeblue/internal/tokenestimate"
	"github.com/Problem99-io/kodeblue/internal/tools"
	"github.com/pkoukk/tiktoken-go"
)

// --- Mock provider ---

type mockProvider struct {
	name      string
	responses [][]provider.StreamEvent // one response per call
	callIndex int
	requests  []*provider.Request
	countFunc func(*provider.Request) (*provider.Usage, error)
	mu        sync.Mutex
}

func newMockProvider(responses [][]provider.StreamEvent) *mockProvider {
	return &mockProvider{name: "mock", responses: responses}
}

func (m *mockProvider) Name() string { return m.name }

func (m *mockProvider) Stream(_ context.Context, req *provider.Request) (<-chan provider.StreamEvent, error) {
	m.mu.Lock()
	idx := m.callIndex
	m.callIndex++
	if req != nil {
		cloned := *req
		m.requests = append(m.requests, &cloned)
	}
	m.mu.Unlock()

	ch := make(chan provider.StreamEvent, 64)
	go func() {
		defer close(ch)
		if idx < len(m.responses) {
			for _, ev := range m.responses[idx] {
				ch <- ev
			}
		} else {
			// End the mock conversation explicitly; silent EOF is a transport failure.
			ch <- provider.StreamEvent{Type: provider.EventDone}
		}
	}()
	return ch, nil
}

func (m *mockProvider) CountTokens(_ context.Context, req *provider.Request) (*provider.Usage, error) {
	if m.countFunc != nil {
		return m.countFunc(req)
	}
	return &provider.Usage{InputTokens: 100}, nil
}

type staticTool struct {
	name    string
	content string
	isError bool
}

func (t *staticTool) Name() internal.ToolName { return internal.ToolName(t.name) }

func (t *staticTool) Description() string { return "returns static content" }

func (t *staticTool) Parameters() json.RawMessage { return json.RawMessage(`{"type":"object"}`) }

func (t *staticTool) Execute(context.Context, json.RawMessage) (*tools.Result, error) {
	return &tools.Result{Content: t.content, IsError: t.isError}, nil
}

// trackedTool lets concurrency tests prove how many tool executions overlap
// without relying on timing-derived event order.
type trackedTool struct {
	name  string
	delay time.Duration
	track *toolExecutionTracker

	mu     sync.Mutex
	starts []string
}

type toolExecutionTracker struct {
	mu        sync.Mutex
	active    int
	maxActive int
}

func (t *toolExecutionTracker) started() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.active++
	if t.active > t.maxActive {
		t.maxActive = t.active
	}
}

func (t *toolExecutionTracker) finished() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.active--
}

func (t *toolExecutionTracker) maximumConcurrency() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.maxActive
}

func (t *trackedTool) Name() internal.ToolName { return internal.ToolName(t.name) }
func (t *trackedTool) Description() string     { return "tracked test tool" }
func (t *trackedTool) Parameters() json.RawMessage {
	return json.RawMessage(`{"type":"object"}`)
}
func (t *trackedTool) Execute(ctx context.Context, _ json.RawMessage) (*tools.Result, error) {
	if t.track != nil {
		t.track.started()
		defer t.track.finished()
	}
	t.mu.Lock()
	t.starts = append(t.starts, t.name)
	t.mu.Unlock()
	select {
	case <-time.After(t.delay):
	case <-ctx.Done():
		return &tools.Result{Content: "cancelled", IsError: true}, nil
	}
	return &tools.Result{Content: t.name}, nil
}

type doneBlockingProvider struct {
	mu        sync.Mutex
	callIndex int
}

func (p *doneBlockingProvider) Name() string { return "done-blocking" }

func (p *doneBlockingProvider) Stream(ctx context.Context, req *provider.Request) (<-chan provider.StreamEvent, error) {
	p.mu.Lock()
	callIndex := p.callIndex
	p.callIndex++
	p.mu.Unlock()

	ch := make(chan provider.StreamEvent, 8)
	go func() {
		defer close(ch)
		if callIndex == 0 {
			ch <- provider.StreamEvent{Type: provider.EventToken, Content: "thinking", Channel: provider.ChannelReasoning}
			ch <- provider.StreamEvent{Type: provider.EventToolUse, ToolCall: &provider.ToolCallEvent{
				ID:        "tc_1",
				Name:      "read_file",
				Arguments: `{"path":"test.txt","start_line":1,"end_line":1}`,
			}}
			ch <- provider.StreamEvent{Type: provider.EventDone, Usage: &provider.Usage{InputTokens: 10, OutputTokens: 2}}
			<-ctx.Done()
			return
		}

		ch <- provider.StreamEvent{Type: provider.EventToken, Content: "done", Channel: provider.ChannelText}
		ch <- provider.StreamEvent{Type: provider.EventDone, Usage: &provider.Usage{InputTokens: 15, OutputTokens: 3}}
	}()
	return ch, nil
}

func (p *doneBlockingProvider) CountTokens(context.Context, *provider.Request) (*provider.Usage, error) {
	return &provider.Usage{InputTokens: 10}, nil
}

// --- Helpers ---

func buildRunConfig(p provider.Provider, toolDefs []internal.ToolDefinition) RunConfig {
	return RunConfig{
		SessionID:   "sess_test",
		RunID:       "run_test",
		Provider:    p,
		Tools:       toolDefs,
		TokenBudget: 100000,
	}
}

func collectEvents(sink *eventCollector) []string {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	types := make([]string, len(sink.events))
	for i, e := range sink.events {
		types[i] = e.Type
	}
	return types
}

func collectEventPayloads(sink *eventCollector, eventType string) []map[string]any {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	var payloads []map[string]any
	for _, event := range sink.events {
		if event.Type != eventType {
			continue
		}
		var payload map[string]any
		if err := json.Unmarshal(event.Payload, &payload); err != nil {
			continue
		}
		payloads = append(payloads, payload)
	}
	return payloads
}

type eventCollector struct {
	mu     sync.Mutex
	events []internal.Event
}

func (ec *eventCollector) sink(event internal.Event) {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	ec.events = append(ec.events, event)
}

// simpleTextResponse returns stream events for a plain text reply (no tool calls).
func simpleTextResponse(text string) []provider.StreamEvent {
	return []provider.StreamEvent{
		{Type: provider.EventToken, Content: text},
		{Type: provider.EventDone, Usage: &provider.Usage{InputTokens: 50, OutputTokens: 20}},
	}
}

// toolCallResponse returns stream events that invoke a tool.
func toolCallResponse(toolID, toolName, argsJSON string) []provider.StreamEvent {
	return []provider.StreamEvent{
		{Type: provider.EventToolUse, ToolCall: &provider.ToolCallEvent{
			ID:        toolID,
			Name:      toolName,
			Arguments: argsJSON,
		}},
		{Type: provider.EventDone, Usage: &provider.Usage{InputTokens: 100, OutputTokens: 50}},
	}
}

func newAllowAllToolGuard() *policy.ToolGuard {
	cfg := policy.DefaultConfig()
	am, _ := policy.NewToolGuard(cfg)
	return am
}

// --- Tests ---

func TestLoopSimpleTextResponse(t *testing.T) {
	ec := &eventCollector{}
	mp := newMockProvider([][]provider.StreamEvent{
		simpleTextResponse("Hello from the AI!"),
	})
	am := newAllowAllToolGuard()
	toolReg := tools.NewRegistry()

	loop := NewLoop(toolReg, am, nil, ec.sink)
	cfg := buildRunConfig(mp, nil)

	result, err := loop.Run(context.Background(), cfg, "Say hello", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msgs := result.Messages
	// Should have user message + assistant message
	if len(msgs) < 2 {
		t.Fatalf("expected at least 2 messages, got %d", len(msgs))
	}
	if msgs[0].Role != "user" {
		t.Errorf("first message should be user, got %s", msgs[0].Role)
	}
	last := msgs[len(msgs)-1]
	if last.Role != "assistant" {
		t.Errorf("last message should be assistant, got %s", last.Role)
	}
	if last.Content != "Hello from the AI!" {
		t.Errorf("expected 'Hello from the AI!', got %q", last.Content)
	}

	// Check events
	types := collectEvents(ec)
	assertContains(t, types, internal.EventMessageStarted)
	assertContains(t, types, internal.EventModelToken)
	assertContains(t, types, internal.EventModelCompleted)
	assertContains(t, types, internal.EventRunCompleted)
}

func TestLoopUsesConfiguredMaxOutputTokens(t *testing.T) {
	for _, tc := range []struct {
		name  string
		limit int
		want  int
	}{
		{name: "default", want: 32768},
		{name: "configured", limit: 16384, want: 16384},
		{name: "provider boundary", limit: -1, want: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mp := newMockProvider([][]provider.StreamEvent{simpleTextResponse("done")})
			loop := NewLoop(tools.NewRegistry(), newAllowAllToolGuard(), nil, func(internal.Event) {})
			cfg := buildRunConfig(mp, nil)
			cfg.MaxOutputTokens = tc.limit
			if _, err := loop.Run(context.Background(), cfg, "test", nil); err != nil {
				t.Fatalf("Run: %v", err)
			}
			if len(mp.requests) != 1 || mp.requests[0].MaxTokens != tc.want {
				t.Fatalf("request MaxTokens = %#v, want %d", mp.requests, tc.want)
			}
		})
	}
}

// A small-window model rejects input + max_tokens beyond its window, so the
// output cap shrinks to what the window has left.
func TestLoopFitsMaxOutputTokensToContextWindow(t *testing.T) {
	mp := newMockProvider([][]provider.StreamEvent{simpleTextResponse("done")})
	loop := NewLoop(tools.NewRegistry(), newAllowAllToolGuard(), nil, func(internal.Event) {})
	cfg := buildRunConfig(mp, nil)
	cfg.TokenBudget = 16384
	if _, err := loop.Run(context.Background(), cfg, "test", nil); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(mp.requests) != 1 {
		t.Fatalf("requests: %d", len(mp.requests))
	}
	if got := mp.requests[0].MaxTokens; got <= 1024 || got > 16384-16384/5 {
		t.Fatalf("MaxTokens = %d, want it to fit a 16k window", got)
	}
}

func TestBuildSystemPromptIsStructuredAndDeterministic(t *testing.T) {
	loop := NewLoop(tools.NewRegistry(), newAllowAllToolGuard(), nil, nil)
	prompt := loop.buildSystemPromptAt(RunConfig{
		BaseDirectory: "/workspace/project",
		AvailableSkills: []AvailableSkill{
			{Name: "z-skill", Description: "last skill"},
			{Name: "a-skill", Description: "first skill"},
		},
		AvailableDefinitions: []AvailableDefinition{
			{ID: "def_auth", Title: "Auth System", Snippet: "Defines login and session flows", Important: true, Scope: []string{"backend/src/routes/auth.ts", "backend/src/services/auth.ts"}, Rules: []AvailableDefinitionItem{{ID: "rule-no-bypass", Title: "No bypass", Content: "Do not skip password verification."}}, Notes: []AvailableDefinitionItem{{ID: "note-rate-limit", Title: "Rate limit", Content: "Lockouts happen after repeated failures."}}},
			{ID: "def_search", Title: "Search System", Snippet: "Defines file and content search helpers"},
		},
	}, time.Date(2026, time.March, 30, 11, 0, 0, 0, time.UTC))

	sections := []string{
		"Runtime context:",
		"- Base directory: /workspace/project",
		"Base instructions:",
		"Definitions:",
		"- Auth System [def_auth] IMPORTANT",
		"Rule No bypass (rule-no-bypass): Do not skip password verification.",
		"Note Rate limit (note-rate-limit): Lockouts happen after repeated failures.",
		"- Search System [def_search]",
		"  Snippet: Defines file and content search helpers",
		"Available skills:",
		"<name>a-skill</name>",
		"<name>z-skill</name>",
	}
	for _, want := range sections {
		if !strings.Contains(prompt, want) {
			t.Fatalf("prompt missing section content %q\nprompt:\n%s", want, prompt)
		}
	}

	aSkillIndex := strings.Index(prompt, "<name>a-skill</name>")
	zSkillIndex := strings.Index(prompt, "<name>z-skill</name>")
	if aSkillIndex == -1 || zSkillIndex == -1 || aSkillIndex > zSkillIndex {
		t.Fatalf("skills are not sorted deterministically\nprompt:\n%s", prompt)
	}
}

func TestEffectiveContextTokensIncludesCacheBuckets(t *testing.T) {
	tests := []struct {
		name  string
		usage provider.Usage
		want  int64
	}{
		{
			name:  "uncached only",
			usage: provider.Usage{InputTokens: 1200},
			want:  1200,
		},
		{
			name:  "includes cache read and write",
			usage: provider.Usage{InputTokens: 800, CacheCreationInputTokens: 3200, CacheReadInputTokens: 6400},
			want:  10400,
		},
		{
			name:  "all zero",
			usage: provider.Usage{},
			want:  0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := effectiveContextTokens(test.usage); got != test.want {
				t.Fatalf("effectiveContextTokens() = %d, want %d", got, test.want)
			}
		})
	}
}

func TestEstimateTextTokensUsesO200kBaseTokenizer(t *testing.T) {
	tokenizer, err := tiktoken.GetEncoding(tokenestimate.EncodingName)
	if err != nil {
		t.Fatalf("GetEncoding(%q) error = %v", tokenestimate.EncodingName, err)
	}

	input := "MiniMax-M2.7 should use o200k_base for token estimation."
	want := int64(len(tokenizer.Encode(input, nil, nil)))
	if got := estimateTextTokens(input); got != want {
		t.Fatalf("estimateTextTokens() = %d, want %d", got, want)
	}
}

func TestBuildSystemPromptKeepsDefaultInstructionsBeforeOverrides(t *testing.T) {
	loop := NewLoop(tools.NewRegistry(), newAllowAllToolGuard(), nil, nil)
	override := "project instructions from AGENTS.md"
	prompt := loop.buildSystemPromptAt(RunConfig{
		BaseDirectory: "/workspace/project",
		Instructions:  []string{override},
	}, time.Date(2026, time.March, 30, 11, 0, 0, 0, time.UTC))

	baseInstructions := strings.TrimSpace(ResolveToolBlocks(BaseInstructions(), toolSet()))
	baseIndex := strings.Index(prompt, baseInstructions)
	overrideIndex := strings.Index(prompt, override)
	if baseIndex == -1 {
		t.Fatalf("prompt missing default instructions\nprompt:\n%s", prompt)
	}
	if overrideIndex == -1 {
		t.Fatalf("prompt missing override instructions\nprompt:\n%s", prompt)
	}
	if baseIndex > overrideIndex {
		t.Fatalf("default instructions should come before override instructions\nprompt:\n%s", prompt)
	}
}

func TestBuildSystemPromptDoesNotDuplicateBaseInstructions(t *testing.T) {
	loop := NewLoop(tools.NewRegistry(), newAllowAllToolGuard(), nil, nil)
	baseInstructions := strings.TrimSpace(BaseInstructions())
	customInstructions := baseInstructions + "\n\nagent specific instructions"
	prompt := loop.buildSystemPromptAt(RunConfig{
		BaseDirectory: "/workspace/project",
		Instructions:  []string{customInstructions},
	}, time.Date(2026, time.March, 30, 11, 0, 0, 0, time.UTC))

	if got := strings.Count(prompt, baseInstructions); got != 1 {
		t.Fatalf("base instructions appear %d times, want 1\nprompt:\n%s", got, prompt)
	}
	if !strings.Contains(prompt, "agent specific instructions") {
		t.Fatalf("prompt missing remaining custom instructions\nprompt:\n%s", prompt)
	}
}

func TestRunSeparatesReasoningFromVisibleAssistantContent(t *testing.T) {
	ec := &eventCollector{}
	loop := NewLoop(tools.NewRegistry(), newAllowAllToolGuard(), nil, ec.sink)
	providerMock := newMockProvider([][]provider.StreamEvent{{
		{Type: provider.EventToken, Content: "Thinking step", Channel: provider.ChannelReasoning},
		{Type: provider.EventToken, Content: "Visible answer", Channel: provider.ChannelText},
		{Type: provider.EventDone, Usage: &provider.Usage{InputTokens: 10, OutputTokens: 5}},
	}})

	result, err := loop.Run(context.Background(), buildRunConfig(providerMock, nil), "Say hello", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	last := result.Messages[len(result.Messages)-1]
	if last.Content != "Visible answer" {
		t.Fatalf("assistant content = %q, want visible text only", last.Content)
	}
	if last.ReasoningContent != "Thinking step" {
		t.Fatalf("assistant reasoning_content = %q, want %q", last.ReasoningContent, "Thinking step")
	}

	payloads := collectEventPayloads(ec, internal.EventModelToken)
	if len(payloads) != 2 {
		t.Fatalf("model token payload count = %d, want 2", len(payloads))
	}
	if payloads[0]["channel"] != provider.ChannelReasoning {
		t.Fatalf("first token channel = %v, want %q", payloads[0]["channel"], provider.ChannelReasoning)
	}
	if payloads[1]["channel"] != provider.ChannelText {
		t.Fatalf("second token channel = %v, want %q", payloads[1]["channel"], provider.ChannelText)
	}
}

func TestRunFreezesSystemPromptAcrossIterations(t *testing.T) {
	ec := &eventCollector{}
	mp := newMockProvider([][]provider.StreamEvent{
		toolCallResponse("tc_1", "read_file", `{"path":"test.txt","start_line":1,"end_line":10}`),
		simpleTextResponse("done"),
	})

	toolCfg := tools.ToolConfig{
		ProjectRoot:    t.TempDir(),
		MaxOutputBytes: 1024,
	}
	toolReg := tools.NewRegistry()
	toolReg.Register(tools.NewReadFile(toolCfg))

	loop := NewLoop(toolReg, newAllowAllToolGuard(), nil, ec.sink)
	cfg := buildRunConfig(mp, toolReg.List())
	cfg.BaseDirectory = "/workspace/project"

	originalPromptNow := promptNow
	defer func() { promptNow = originalPromptNow }()
	times := []time.Time{
		time.Date(2026, time.March, 30, 23, 59, 58, 0, time.UTC),
		time.Date(2026, time.March, 31, 0, 0, 1, 0, time.UTC),
		time.Date(2026, time.April, 1, 0, 0, 1, 0, time.UTC),
	}
	call := 0
	promptNow = func() time.Time {
		if call >= len(times) {
			return times[len(times)-1]
		}
		current := times[call]
		call++
		return current
	}

	_, err := loop.Run(context.Background(), cfg, "Read test.txt", nil)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if len(mp.requests) != 2 {
		t.Fatalf("provider saw %d requests, want 2", len(mp.requests))
	}
	if mp.requests[0].SystemPrompt != mp.requests[1].SystemPrompt {
		t.Fatalf("system prompt changed across iterations\nfirst:\n%s\n\nsecond:\n%s", mp.requests[0].SystemPrompt, mp.requests[1].SystemPrompt)
	}
	if strings.Contains(mp.requests[0].SystemPrompt, "Current date:") {
		t.Fatalf("system prompt should not include volatile current date, got:\n%s", mp.requests[0].SystemPrompt)
	}
	if strings.Contains(mp.requests[1].SystemPrompt, "2026-03-31") || strings.Contains(mp.requests[1].SystemPrompt, "2026-04-01") {
		t.Fatalf("system prompt should not include later volatile dates, got:\n%s", mp.requests[1].SystemPrompt)
	}
}

func TestLoopToolCallAndResponse(t *testing.T) {
	ec := &eventCollector{}

	// First call: provider requests a tool. Second call: provider replies with text.
	mp := newMockProvider([][]provider.StreamEvent{
		toolCallResponse("tc_1", "read_file", `{"path":"test.txt","start_line":1,"end_line":10}`),
		simpleTextResponse("Here is the file content."),
	})

	am := newAllowAllToolGuard()

	// Register read_file tool
	toolCfg := tools.ToolConfig{
		ProjectRoot:    t.TempDir(),
		MaxOutputBytes: 1024,
	}
	toolReg := tools.NewRegistry()
	toolReg.Register(tools.NewReadFile(toolCfg))

	// Create a test file for read_file to find
	testFile := toolCfg.ProjectRoot + "/test.txt"
	writeTestFile(t, testFile, "hello world\n")

	loop := NewLoop(toolReg, am, nil, ec.sink)
	cfg := buildRunConfig(mp, toolReg.List())

	result, err := loop.Run(context.Background(), cfg, "Read test.txt", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msgs := result.Messages
	// Expected: user -> assistant (tool call) -> user (tool result) -> assistant (text)
	if len(msgs) < 4 {
		t.Fatalf("expected at least 4 messages, got %d", len(msgs))
	}

	// Verify tool call was made
	types := collectEvents(ec)
	assertContains(t, types, internal.EventToolRequested)
	assertContains(t, types, internal.EventToolStarted)
	assertContains(t, types, internal.EventToolFinished)
	assertContains(t, types, internal.EventRunCompleted)
}

func TestLoopUsesPreassignedDurableUserMessageIdentity(t *testing.T) {
	mp := newMockProvider([][]provider.StreamEvent{simpleTextResponse("done")})
	loop := NewLoop(tools.NewRegistry(), newAllowAllToolGuard(), nil, nil)
	wantCreatedAt := time.Date(2026, time.August, 25, 8, 47, 34, 0, time.UTC)
	cfg := buildRunConfig(mp, nil)
	cfg.UserMessageID = "msg_durable_original"
	cfg.UserMessageCreatedAt = wantCreatedAt

	result, err := loop.Run(context.Background(), cfg, "original task", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Messages) == 0 {
		t.Fatal("expected user message in result")
	}
	got := result.Messages[0]
	if got.ID != cfg.UserMessageID {
		t.Fatalf("user message ID = %q, want %q", got.ID, cfg.UserMessageID)
	}
	if !got.CreatedAt.Equal(wantCreatedAt) {
		t.Fatalf("user message CreatedAt = %s, want %s", got.CreatedAt, wantCreatedAt)
	}
}

func TestLoopRunsReadOnlyToolTurnInBoundedParallelAndPreservesResultOrder(t *testing.T) {
	ec := &eventCollector{}
	track := &toolExecutionTracker{}
	read := &trackedTool{name: "read_file", delay: 40 * time.Millisecond, track: track}
	grep := &trackedTool{name: "grep", delay: 40 * time.Millisecond, track: track}
	registry := tools.NewRegistry()
	registry.Register(read)
	registry.Register(grep)
	providerMock := newMockProvider([][]provider.StreamEvent{
		{
			{Type: provider.EventToolUse, ToolCall: &provider.ToolCallEvent{ID: "read", Name: "read_file", Arguments: `{"path":"a.txt"}`}},
			{Type: provider.EventToolUse, ToolCall: &provider.ToolCallEvent{ID: "grep", Name: "grep", Arguments: `{"query":"needle","path":"."}`}},
			{Type: provider.EventDone, Usage: &provider.Usage{InputTokens: 10, OutputTokens: 2}},
		},
		simpleTextResponse("done"),
	})
	loop := NewLoop(registry, newAllowAllToolGuard(), nil, ec.sink)
	result, err := loop.Run(context.Background(), buildRunConfig(providerMock, registry.List()), "inspect both", nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := track.maximumConcurrency(); got != 2 {
		t.Fatalf("read-only calls did not overlap; maximum concurrency = %d, want 2", got)
	}
	if len(result.Messages) < 3 || len(result.Messages[2].ToolResults) != 2 {
		t.Fatalf("missing ordered tool results: %#v", result.Messages)
	}
	if got := result.Messages[2].ToolResults[0].ToolCallID; got != "read" {
		t.Fatalf("first tool result id = %q, want read", got)
	}
	if got := result.Messages[2].ToolResults[1].ToolCallID; got != "grep" {
		t.Fatalf("second tool result id = %q, want grep", got)
	}
	outputs := collectEventPayloads(ec, internal.EventToolOutput)
	if len(outputs) != 2 || outputs[0]["tool_call_id"] != "read" || outputs[1]["tool_call_id"] != "grep" {
		t.Fatalf("parallel output events must retain model order: %#v", outputs)
	}
	for _, output := range outputs {
		if output["execution_mode"] != "parallel_read_only" || output["parallel_width"] != float64(2) {
			t.Fatalf("missing observed parallel metrics: %#v", output)
		}
	}
}

func TestLoopKeepsMixedReadAndMutationTurnSequential(t *testing.T) {
	ec := &eventCollector{}
	track := &toolExecutionTracker{}
	read := &trackedTool{name: "read_file", delay: 25 * time.Millisecond, track: track}
	write := &trackedTool{name: "write_file", delay: 25 * time.Millisecond, track: track}
	registry := tools.NewRegistry()
	registry.Register(read)
	registry.Register(write)
	providerMock := newMockProvider([][]provider.StreamEvent{
		{
			{Type: provider.EventToolUse, ToolCall: &provider.ToolCallEvent{ID: "read", Name: "read_file", Arguments: `{"path":"internal/agent/agent_test.go"}`}},
			{Type: provider.EventToolUse, ToolCall: &provider.ToolCallEvent{ID: "write", Name: "write_file", Arguments: `{"path":"internal/agent/agent_test.go","content":"unused"}`}},
			{Type: provider.EventDone, Usage: &provider.Usage{InputTokens: 10, OutputTokens: 2}},
		},
		simpleTextResponse("done"),
	})
	loop := NewLoop(registry, newAllowAllToolGuard(), nil, ec.sink)
	if _, err := loop.Run(context.Background(), buildRunConfig(providerMock, registry.List()), "read then change", nil); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := track.maximumConcurrency(); got != 1 {
		t.Fatalf("mixed read/mutation turn must stay sequential, maximum concurrency = %d", got)
	}
	// Each individual tool sees one call; event order proves the mutation was
	// started only after the read completed rather than merely started after it.
	types := collectEvents(ec)
	readCompleted, writeStarted := -1, -1
	for i, typ := range types {
		if typ == internal.EventToolFinished && readCompleted == -1 {
			readCompleted = i
		}
		if typ == internal.EventToolStarted && readCompleted >= 0 && writeStarted == -1 {
			writeStarted = i
		}
	}
	if readCompleted < 0 || writeStarted <= readCompleted {
		t.Fatalf("mixed turn did not preserve read-before-mutation ordering: %v", types)
	}
	for _, output := range collectEventPayloads(ec, internal.EventToolOutput) {
		if _, parallelized := output["execution_mode"]; parallelized {
			t.Fatalf("mixed turn must not report parallel execution: %#v", output)
		}
	}
	for _, requested := range collectEventPayloads(ec, internal.EventToolRequested) {
		if requested["execution_mode"] != "sequential" || requested["parallel_width"] != float64(1) {
			t.Fatalf("mixed turn must explicitly report sequential scheduling: %#v", requested)
		}
	}
}

func TestLoopEmitsCanonicalErrorTerminalForToolResultError(t *testing.T) {
	ec := &eventCollector{}
	registry := tools.NewRegistry()
	registry.Register(&staticTool{name: "read_file", content: "not found", isError: true})
	providerMock := newMockProvider([][]provider.StreamEvent{
		toolCallResponse("call_error", "read_file", `{"path":"missing.txt"}`),
		simpleTextResponse("done"),
	})
	loop := NewLoop(registry, newAllowAllToolGuard(), nil, ec.sink)
	if _, err := loop.Run(context.Background(), buildRunConfig(providerMock, registry.List()), "read", nil); err != nil {
		t.Fatalf("Run: %v", err)
	}
	finished := collectEventPayloads(ec, internal.EventToolFinished)
	if len(finished) != 1 || finished[0]["status"] != "error" || finished[0]["phase"] != "execution" || finished[0]["category"] != "tool_result_error" {
		t.Fatalf("canonical tool terminal = %#v", finished)
	}
}

func TestLoopCancelsStreamAfterSemanticDoneAndExecutesTool(t *testing.T) {
	ec := &eventCollector{}
	providerMock := &doneBlockingProvider{}
	toolCfg := tools.ToolConfig{
		ProjectRoot:    t.TempDir(),
		MaxOutputBytes: 1024,
	}
	toolReg := tools.NewRegistry()
	toolReg.Register(tools.NewReadFile(toolCfg))
	writeTestFile(t, toolCfg.ProjectRoot+"/test.txt", "hello\n")

	loop := NewLoop(toolReg, newAllowAllToolGuard(), nil, ec.sink)
	result, err := loop.Run(context.Background(), buildRunConfig(providerMock, toolReg.List()), "Read test.txt", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Messages) < 3 {
		t.Fatalf("expected tool-call turn to complete, got %d messages", len(result.Messages))
	}

	types := collectEvents(ec)
	assertContains(t, types, internal.EventToolRequested)
	assertContains(t, types, internal.EventToolStarted)
	assertContains(t, types, internal.EventToolFinished)
	assertContains(t, types, internal.EventRunCompleted)

	assistantWithTool := result.Messages[1]
	if assistantWithTool.ReasoningContent != "thinking" {
		t.Fatalf("assistant reasoning_content = %q, want %q", assistantWithTool.ReasoningContent, "thinking")
	}
}

// buildToolLoopRun wires a run whose model asks for a tool call on every turn,
// so the only things that can end it are the mock running out of responses, an
// abort, or a continuation checkpoint.
func buildToolLoopRun(t *testing.T, ec *eventCollector, turns int) (*Loop, *mockProvider, RunConfig) {
	t.Helper()

	responses := make([][]provider.StreamEvent, turns)
	for i := range responses {
		responses[i] = toolCallResponse("tc_loop", "read_file", `{"path":"x.txt","start_line":1,"end_line":1}`)
	}
	mp := newMockProvider(responses)

	toolCfg := tools.ToolConfig{ProjectRoot: t.TempDir(), MaxOutputBytes: 1024}
	toolReg := tools.NewRegistry()
	toolReg.Register(tools.NewReadFile(toolCfg))

	loop := NewLoop(toolReg, newAllowAllToolGuard(), nil, ec.sink)
	return loop, mp, buildRunConfig(mp, toolReg.List())
}

func (m *mockProvider) callCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.callIndex
}

// Without a continuation gate or explicit hard cap, the loop has no iteration
// cap at all: it keeps calling tools for as long as the model asks.
func TestLoopHasNoIterationCap(t *testing.T) {
	ec := &eventCollector{}

	// Far more tool-call turns than any cap the engine ever shipped with.
	const turns = 250
	loop, mp, cfg := buildToolLoopRun(t, ec, turns)
	// MaxIterations alone remains an interactive checkpoint: without a gate it
	// must not cap a main-agent run.
	cfg.MaxIterations = 2

	// The mock stops emitting tool calls once its responses run out, which is the
	// only thing that ends the run.
	_, err := loop.Run(context.Background(), cfg, "keep going", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if calls := mp.callCount(); calls != turns+1 {
		t.Fatalf("expected %d provider calls (all turns plus the terminating one), got %d", turns+1, calls)
	}

	types := collectEvents(ec)
	assertContains(t, types, internal.EventRunCompleted)
}

func TestLoopEmitsToolFailedForPreExecutionRejections(t *testing.T) {
	tests := []struct {
		name            string
		toolName        string
		arguments       string
		toolDefinitions []internal.ToolDefinition
		toolGuard       func() *policy.ToolGuard
		wantReason      string
	}{
		{
			name:            "per-run allowlist denial",
			toolName:        "grep",
			arguments:       `{}`,
			toolDefinitions: []internal.ToolDefinition{{Name: "read_file"}},
			toolGuard:       newAllowAllToolGuard,
			wantReason:      "not available to this agent",
		},
		{
			name:            "malformed arguments",
			toolName:        "read_file",
			arguments:       `{`,
			toolDefinitions: []internal.ToolDefinition{{Name: "read_file"}},
			toolGuard:       newAllowAllToolGuard,
			wantReason:      "tool arguments were not valid JSON",
		},
		{
			name:            "policy parse error",
			toolName:        "read_file",
			arguments:       `{"path":5}`,
			toolDefinitions: []internal.ToolDefinition{{Name: "read_file"}},
			toolGuard:       newAllowAllToolGuard,
			wantReason:      "policy error: parse read args",
		},
		{
			name:            "policy denial",
			toolName:        "list_dir",
			arguments:       `{"path":"secrets"}`,
			toolDefinitions: []internal.ToolDefinition{{Name: "list_dir"}},
			toolGuard: func() *policy.ToolGuard {
				cfg := policy.DefaultConfig()
				cfg.Paths.DenyPaths = []string{"secrets"}
				am, err := policy.NewToolGuard(cfg)
				if err != nil {
					t.Fatalf("tool guard: %v", err)
				}
				return am
			},
			wantReason: "is denied",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ec := &eventCollector{}
			mp := newMockProvider([][]provider.StreamEvent{
				toolCallResponse("tc_denied", tc.toolName, tc.arguments),
				simpleTextResponse("done"),
			})
			loop := NewLoop(tools.NewRegistry(), tc.toolGuard(), nil, ec.sink)
			if _, err := loop.Run(context.Background(), buildRunConfig(mp, tc.toolDefinitions), "test", nil); err != nil {
				t.Fatalf("Run: %v", err)
			}

			payloads := collectEventPayloads(ec, internal.EventToolFinished)
			if len(payloads) != 1 {
				t.Fatalf("expected one tool.finished event, got %d", len(payloads))
			}
			payload := payloads[0]
			if payload["tool_call_id"] != "tc_denied" || payload["tool_name"] != tc.toolName {
				t.Fatalf("tool.finished identity = %#v, want tc_denied/%s", payload, tc.toolName)
			}
			reason, _ := payload["reason"].(string)
			if !strings.Contains(reason, tc.wantReason) {
				t.Fatalf("tool.finished reason = %q, want substring %q", reason, tc.wantReason)
			}
			types := collectEvents(ec)
			if hasEventType(types, internal.EventToolStarted) || hasEventType(types, internal.EventToolOutput) {
				t.Fatalf("pre-execution rejection must not emit tool started/output: %v", types)
			}
		})
	}
}

// Answering "yes" at a checkpoint releases the held tool results and buys
// another MaxIterations turns — without injecting anything into the transcript.
func TestLoopContinuationCheckpointResumesOnYes(t *testing.T) {
	ec := &eventCollector{}
	const turns = 25
	loop, mp, cfg := buildToolLoopRun(t, ec, turns)
	cfg.MaxIterations = 10

	var asked []ContinuationRequest
	loop.SetContinuationGate(func(_ context.Context, req ContinuationRequest) (ContinuationDecision, error) {
		asked = append(asked, req)
		return ContinuationDecision{Continue: true}, nil
	})

	result, err := loop.Run(context.Background(), cfg, "keep going", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Checkpoints at turns 10 and 20; the run ends on turn 26 when the mock dries up.
	if len(asked) != 2 {
		t.Fatalf("expected 2 checkpoints, got %d (%+v)", len(asked), asked)
	}
	if asked[0].Iterations != 10 || asked[1].Iterations != 20 {
		t.Fatalf("expected checkpoints at turns 10 and 20, got %d and %d", asked[0].Iterations, asked[1].Iterations)
	}
	if asked[0].ToolCalls != 10 {
		t.Fatalf("expected 10 tool calls reported at the first checkpoint, got %d", asked[0].ToolCalls)
	}
	if asked[0].RunID != cfg.RunID || asked[0].SessionID != cfg.SessionID {
		t.Fatalf("checkpoint did not carry run/session identity: %+v", asked[0])
	}
	if calls := mp.callCount(); calls != turns+1 {
		t.Fatalf("expected the run to reach all %d turns, got %d provider calls", turns, calls)
	}

	// Saying yes must not add anything to the conversation: the model just gets
	// the tool results that were being held.
	for _, msg := range result.Messages {
		if msg.Role == "user" && msg.Content != "" && msg.Content != "keep going" {
			t.Fatalf("continuation injected an unexpected user message: %q", msg.Content)
		}
	}
}

// Answering "no" ends the run where it stands, leaving the completed tool
// results in the transcript, exactly like a manual stop.
func TestLoopContinuationCheckpointStopsOnNo(t *testing.T) {
	ec := &eventCollector{}
	loop, mp, cfg := buildToolLoopRun(t, ec, 25)
	cfg.MaxIterations = 3

	loop.SetContinuationGate(func(_ context.Context, _ ContinuationRequest) (ContinuationDecision, error) {
		return ContinuationDecision{Continue: false}, nil
	})

	result, err := loop.Run(context.Background(), cfg, "keep going", nil)
	if !errors.Is(err, ErrAborted) {
		t.Fatalf("expected ErrAborted, got %v", err)
	}
	if calls := mp.callCount(); calls != 3 {
		t.Fatalf("expected the run to stop after 3 turns, got %d provider calls", calls)
	}

	last := result.Messages[len(result.Messages)-1]
	if len(last.ToolResults) == 0 {
		t.Fatalf("expected the held tool results to remain in the transcript, got %+v", last)
	}

	types := collectEvents(ec)
	assertContains(t, types, internal.EventRunAborted)
}

// Free text typed instead of a plain yes continues the run and reaches the model
// as an ordinary user message alongside the held tool results.
func TestLoopContinuationCheckpointDeliversGuidance(t *testing.T) {
	ec := &eventCollector{}
	loop, mp, cfg := buildToolLoopRun(t, ec, 5)
	cfg.MaxIterations = 2

	loop.SetContinuationGate(func(_ context.Context, _ ContinuationRequest) (ContinuationDecision, error) {
		return ContinuationDecision{Continue: true, Guidance: "stop reading and write the file"}, nil
	})

	result, err := loop.Run(context.Background(), cfg, "keep going", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var found bool
	for _, msg := range result.Messages {
		if msg.Role == "user" && msg.Content == "stop reading and write the file" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected the guidance to be appended as a user message")
	}

	// The guidance must ride along with the tool results, not replace them: the
	// run keeps going through every remaining turn.
	if calls := mp.callCount(); calls != 6 {
		t.Fatalf("expected the run to continue to the end, got %d provider calls", calls)
	}
}

// A checkpoint that cannot be answered fails the run rather than looping on.
func TestLoopContinuationGateErrorFailsRun(t *testing.T) {
	ec := &eventCollector{}
	loop, _, cfg := buildToolLoopRun(t, ec, 25)
	cfg.MaxIterations = 2

	loop.SetContinuationGate(func(_ context.Context, _ ContinuationRequest) (ContinuationDecision, error) {
		return ContinuationDecision{}, errors.New("event hub is gone")
	})

	if _, err := loop.Run(context.Background(), cfg, "keep going", nil); err == nil {
		t.Fatal("expected the run to fail when the checkpoint cannot be answered")
	}

	types := collectEvents(ec)
	assertContains(t, types, internal.EventRunFailed)
}

func TestLoopAbort(t *testing.T) {
	ec := &eventCollector{}

	// Provider blocks until context cancelled by using a slow channel
	mp := &blockingProvider{}
	am := newAllowAllToolGuard()
	toolReg := tools.NewRegistry()

	loop := NewLoop(toolReg, am, nil, ec.sink)
	cfg := buildRunConfig(mp, nil)

	var wg sync.WaitGroup
	var runErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, runErr = loop.Run(context.Background(), cfg, "blocking task", nil)
	}()

	// Wait for run to register
	time.Sleep(50 * time.Millisecond)

	if !loop.IsRunning(cfg.RunID) {
		t.Error("expected run to be active")
	}

	ok := loop.Abort(cfg.RunID)
	if !ok {
		t.Error("abort should return true for active run")
	}

	wg.Wait()

	if !errors.Is(runErr, ErrAborted) {
		t.Errorf("expected ErrAborted, got %v", runErr)
	}
	assertContains(t, collectEvents(ec), internal.EventRunAborted)

	if loop.IsRunning(cfg.RunID) {
		t.Error("run should not be active after abort")
	}
}

func TestLoopInterruptsProviderAndPreservesPartialAssistantContent(t *testing.T) {
	ec := &eventCollector{}
	provider := &partialBlockingProvider{tokenSent: make(chan struct{})}
	tokenObserved := make(chan struct{})
	loop := NewLoop(tools.NewRegistry(), newAllowAllToolGuard(), nil, func(event internal.Event) {
		ec.sink(event)
		if event.Type == internal.EventModelToken {
			close(tokenObserved)
		}
	})
	cfg := buildRunConfig(provider, nil)

	resultCh := make(chan RunResult, 1)
	errCh := make(chan error, 1)
	go func() {
		result, err := loop.Run(context.Background(), cfg, "write a response", nil)
		resultCh <- result
		errCh <- err
	}()

	select {
	// A provider enqueue is not proof the recovery adapter and loop have
	// consumed the token. Interrupt only once it has actually reached the UI.
	case <-tokenObserved:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for observed token")
	}
	// Interrupt after the partial token is consumed and observable, not merely
	// after the provider has produced it into its buffered stream.
	deadline := time.Now().Add(time.Second)
	for {
		seen := false
		for _, kind := range collectEvents(ec) {
			if kind == internal.EventModelToken {
				seen = true
				break
			}
		}
		if seen {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("partial token was not emitted")
		}
		time.Sleep(time.Millisecond)
	}
	if !loop.Interrupt(cfg.RunID) {
		t.Fatal("interrupt should find the active provider run")
	}

	result := <-resultCh
	if err := <-errCh; !errors.Is(err, ErrInterrupted) {
		t.Fatalf("expected ErrInterrupted, got %v", err)
	}
	if got := result.Messages[len(result.Messages)-1]; got.Role != "assistant" || got.Content != "partial reply" {
		t.Fatalf("expected preserved partial assistant reply, got %+v", got)
	}
	types := collectEvents(ec)
	assertContains(t, types, internal.EventRunInterrupted)
	for _, eventType := range types {
		if eventType == internal.EventRunAborted {
			t.Fatalf("steer interruption must not emit run.aborted: %v", types)
		}
	}
}

func TestLoopInterruptWaitsForActiveToolThenStopsBeforeNextProviderTurn(t *testing.T) {
	ec := &eventCollector{}
	mp := newMockProvider([][]provider.StreamEvent{
		toolCallResponse("call_1", "read_file", `{}`),
		simpleTextResponse("must not be requested"),
	})
	toolReg := tools.NewRegistry()
	started := make(chan struct{})
	release := make(chan struct{})
	toolReg.Register(&steerBlockingTool{name: "read_file", started: started, release: release})
	loop := NewLoop(toolReg, newAllowAllToolGuard(), nil, ec.sink)
	cfg := buildRunConfig(mp, toolReg.List())

	resultCh := make(chan RunResult, 1)
	errCh := make(chan error, 1)
	go func() {
		result, err := loop.Run(context.Background(), cfg, "use the tool", nil)
		resultCh <- result
		errCh <- err
	}()

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for tool execution")
	}
	if !loop.Interrupt(cfg.RunID) {
		t.Fatal("interrupt should find the active tool run")
	}
	select {
	case err := <-errCh:
		t.Fatalf("interrupt cancelled the active tool instead of waiting: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)

	result := <-resultCh
	if err := <-errCh; !errors.Is(err, ErrInterrupted) {
		t.Fatalf("expected ErrInterrupted, got %v", err)
	}
	if calls := mp.callCount(); calls != 1 {
		t.Fatalf("expected no provider call after the tool boundary, got %d", calls)
	}
	if last := result.Messages[len(result.Messages)-1]; len(last.ToolResults) != 1 || last.ToolResults[0].Content != "tool completed" {
		t.Fatalf("expected completed tool result to be preserved, got %+v", last)
	}
	assertContains(t, collectEvents(ec), internal.EventRunInterrupted)
}

func TestLoopInterruptPendingRunBeforeStartup(t *testing.T) {
	ec := &eventCollector{}
	mp := newMockProvider([][]provider.StreamEvent{simpleTextResponse("must not run")})
	loop := NewLoop(tools.NewRegistry(), newAllowAllToolGuard(), nil, ec.sink)
	cfg := buildRunConfig(mp, nil)
	loop.MarkRunPending(cfg.RunID)
	if !loop.Interrupt(cfg.RunID) {
		t.Fatal("interrupt should record a pending run")
	}

	result, err := loop.Run(context.Background(), cfg, "queued message", nil)
	if !errors.Is(err, ErrInterrupted) {
		t.Fatalf("expected ErrInterrupted, got %v", err)
	}
	if calls := mp.callCount(); calls != 0 {
		t.Fatalf("expected no provider call for startup interruption, got %d", calls)
	}
	if len(result.Messages) != 1 || result.Messages[0].Content != "queued message" {
		t.Fatalf("expected user message to be recorded, got %+v", result.Messages)
	}
	assertContains(t, collectEvents(ec), internal.EventRunInterrupted)
}

func TestLoopAbortNonexistent(t *testing.T) {
	am := newAllowAllToolGuard()
	loop := NewLoop(tools.NewRegistry(), am, nil, nil)
	ok := loop.Abort("run_nonexistent")
	if ok {
		t.Error("abort should return false for non-existent run")
	}
}

func TestCompactor(t *testing.T) {
	ec := &eventCollector{}
	c := NewCompactor(0.90, "", ec.sink)

	if c.NeedsCompaction(50, 100) {
		t.Error("50/100=50% should not need compaction")
	}
	if !c.NeedsCompaction(90, 100) {
		t.Error("90/100=90% should need compaction")
	}
	if !c.NeedsCompaction(230_400, 256_000) {
		t.Error("256k windows should compact at the configured 90% threshold")
	}
	if c.NeedsCompaction(230_399, 256_000) {
		t.Error("256k windows should wait until the configured 90% threshold")
	}
	if !c.NeedsCompaction(900_000, 1_000_000) {
		t.Error("1M windows should compact at the configured 90% threshold")
	}
	if c.NeedsCompaction(899_999, 1_000_000) {
		t.Error("1M windows should wait until the configured 90% threshold")
	}
	if c.NeedsCompaction(50, 0) {
		t.Error("zero budget should never need compaction")
	}

	mp := newMockProvider([][]provider.StreamEvent{
		simpleTextResponse("Summary of the conversation middle."),
	})
	messages := make([]internal.Message, 24)
	for i := range messages {
		role := "user"
		if i%2 == 1 {
			role = "assistant"
		}
		messages[i] = internal.Message{
			ID:      internal.NewMessageID(),
			Role:    role,
			Content: fmt.Sprintf("message %c", rune('A'+i)),
		}
	}

	result, err := c.Compact(context.Background(), mp, "sess_1", "run_1", messages, CompactOptions{ActiveModel: "gpt-5.4", ContextWindow: 40})
	if err != nil {
		t.Fatalf("compact error: %v", err)
	}

	if len(result) >= len(messages) {
		t.Errorf("expected compaction to shrink the history, got %d -> %d messages", len(messages), len(result))
	}
	// With no frozen prefix, the first message is the compacted summary, which
	// subsumes the original task (message A) — it is no longer pinned verbatim.
	if !containsString(result[0].Content, "Compacted context") {
		t.Errorf("first message should be compacted summary, got: %s", result[0].Content)
	}
	// The raw recent tail follows the summary and ends at the last message.
	if got := result[len(result)-1].Content; got != "message X" {
		t.Errorf("recent tail should end at message X, got: %s", got)
	}

	if len(ec.events) == 0 {
		t.Error("expected compaction event")
	}
}

func TestCompactorTooFewMessages(t *testing.T) {
	c := NewCompactor(0.90, "", nil)
	opts := CompactOptions{ActiveModel: "gpt-5.4", ContextWindow: 100_000}

	// A single message has nothing to summarize.
	one := []internal.Message{{ID: internal.NewMessageID(), Role: "user", Content: "hello"}}
	result, err := c.Compact(context.Background(), nil, "s", "r", one, CompactOptions{ActiveModel: "gpt-5.4", ContextWindow: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 || result[0].ID != one[0].ID {
		t.Fatalf("single message must be returned unchanged, got %#v", result)
	}

	// When the whole history fits in the raw-tail budget there is no middle
	// to summarize, so no provider call is needed.
	messages := make([]internal.Message, 21)
	for i := range messages {
		messages[i] = internal.Message{ID: internal.NewMessageID(), Role: "user", Content: "hello"}
	}
	result, err = c.Compact(context.Background(), nil, "s", "r", messages, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != len(messages) {
		t.Errorf("history within the raw-tail budget should not compact, got %d -> %d", len(messages), len(result))
	}
}

func TestCompactorDoesNotSplitToolCallFromToolResult(t *testing.T) {
	messages := make([]internal.Message, 25)
	for i := range messages {
		role := "user"
		if i%2 == 1 {
			role = "assistant"
		}
		messages[i] = internal.Message{ID: internal.NewMessageID(), Role: role, Content: fmt.Sprintf("m%d", i+1)}
	}
	messages[16] = internal.Message{
		ID:      internal.NewMessageID(),
		Role:    "assistant",
		Content: "calling tool",
		ToolCalls: []internal.ToolCall{{
			ID:   "call_1",
			Name: "read_file",
		}},
	}
	messages[17] = internal.Message{
		ID:   internal.NewMessageID(),
		Role: "user",
		ToolResults: []internal.ToolResult{{
			ToolCallID: "call_1",
			Content:    "tool output",
		}},
	}

	// Sweep the window so the raw-tail boundary lands at every position the
	// recent-message cap allows, including between the call and its result.
	keptInTail, summarized := false, false
	for window := int64(8); window <= 400; window += 4 {
		c := NewCompactor(0.90, "", nil)
		mp := newMockProvider([][]provider.StreamEvent{
			simpleTextResponse("Summary of the conversation middle."),
		})
		result, err := c.Compact(context.Background(), mp, "sess_1", "run_1", messages, CompactOptions{ActiveModel: "gpt-5.4", ContextWindow: window})
		if err != nil {
			t.Fatalf("window %d: compact error: %v", window, err)
		}

		toolCallIndex, toolResultIndex := -1, -1
		for i := range result {
			if len(result[i].ToolCalls) > 0 && result[i].ToolCalls[0].ID == "call_1" {
				toolCallIndex = i
			}
			if len(result[i].ToolResults) > 0 && result[i].ToolResults[0].ToolCallID == "call_1" {
				toolResultIndex = i
			}
		}
		switch {
		case toolCallIndex == -1 && toolResultIndex == -1:
			summarized = true
		case toolCallIndex >= 0 && toolResultIndex == toolCallIndex+1:
			if len(result) < len(messages) {
				keptInTail = true
			}
		default:
			t.Fatalf("window %d split the tool call from its result: call=%d result=%d", window, toolCallIndex, toolResultIndex)
		}
	}
	if !keptInTail || !summarized {
		t.Fatalf("window sweep did not cover both outcomes: keptInTail=%t summarized=%t", keptInTail, summarized)
	}
}

func TestCompactorPreservesToolEvidenceAtTailBoundary(t *testing.T) {
	c := NewCompactor(0.80, "", nil)
	mp := newCompactionTestProvider([][]provider.StreamEvent{
		simpleTextResponse("Summary of the conversation middle."),
	})

	messages := make([]internal.Message, 8)
	for i := range messages {
		role := "user"
		if i%2 == 1 {
			role = "assistant"
		}
		messages[i] = internal.Message{ID: internal.NewMessageID(), Role: role, Content: fmt.Sprintf("m%d", i+1)}
	}
	messages[6] = internal.Message{
		ID:      internal.NewMessageID(),
		Role:    "assistant",
		Content: "reading file",
		ToolCalls: []internal.ToolCall{{
			ID:   "call_file_1",
			Name: "read_file",
		}},
	}
	messages[7] = internal.Message{
		ID:   internal.NewMessageID(),
		Role: "user",
		ToolResults: []internal.ToolResult{{
			ToolCallID: "call_file_1",
			Content:    "important file contents",
			Metadata: map[string]any{
				"tool": "read_file",
			},
		}},
	}

	result, err := c.Compact(context.Background(), mp, "sess_1", "run_1", messages, CompactOptions{ActiveModel: "gpt-5.4", ContextWindow: 32})
	if err != nil {
		t.Fatalf("compact error: %v", err)
	}

	toolCallIndex := -1
	toolResultIndex := -1
	for i := range result {
		if len(result[i].ToolCalls) > 0 && result[i].ToolCalls[0].ID == "call_file_1" {
			toolCallIndex = i
		}
		if len(result[i].ToolResults) > 0 && result[i].ToolResults[0].ToolCallID == "call_file_1" {
			toolResultIndex = i
		}
	}

	if toolCallIndex == -1 || toolResultIndex == -1 {
		t.Fatalf("expected boundary tool evidence to remain active after compaction\nresult: %#v", result)
	}
	if toolResultIndex != toolCallIndex+1 {
		t.Fatalf("expected evidence tool result to remain adjacent to its tool call, got call=%d result=%d", toolCallIndex, toolResultIndex)
	}
	if !strings.Contains(result[0].Content, "Compacted context") {
		t.Fatalf("expected compaction summary at the front of the compacted region, got: %s", result[0].Content)
	}
}

func TestCompactorFoldsPriorSummaryWithoutNestingWrapper(t *testing.T) {
	c := NewCompactor(0.90, "", nil)
	mp := newMockProvider([][]provider.StreamEvent{
		simpleTextResponse("Summary:\n- fresh change\n\nDetails:\n- captured new work\n\nRemaining Tasks:\n- none"),
	})

	messages := make([]internal.Message, 24)
	for i := range messages {
		role := "user"
		if i%2 == 1 {
			role = "assistant"
		}
		messages[i] = internal.Message{ID: internal.NewMessageID(), Role: role, Content: fmt.Sprintf("m%d", i+1)}
	}
	messages[2] = internal.Message{ID: internal.NewMessageID(), Role: "user", Content: "[Compacted context — 6 messages summarized]\nSummary:\n- carried forward\n\nDetails:\n- preserved detail\n\nRemaining Tasks:\n- none"}

	result, err := c.Compact(context.Background(), mp, "sess_1", "run_1", messages, CompactOptions{ActiveModel: "gpt-5.4", ContextWindow: 40})
	if err != nil {
		t.Fatalf("compact error: %v", err)
	}

	// The prior summary is part of the live context the model summarizes, so
	// its content is carried forward through the new summary.
	sawPrior := false
	for _, m := range mp.requests[0].Messages {
		if strings.Contains(m.Content, "carried forward") {
			sawPrior = true
		}
	}
	if !sawPrior {
		t.Fatal("summarization request must include the prior compacted summary")
	}

	summary := result[0].Content
	if strings.Count(summary, compactedContextPrefix) != 1 {
		t.Fatalf("expected a single compaction wrapper, got summary:\n%s", summary)
	}
	if !strings.Contains(summary, "fresh change") {
		t.Fatalf("expected fresh summary content, got:\n%s", summary)
	}
	for _, m := range result[1:] {
		if strings.Contains(m.Content, "carried forward") {
			t.Fatalf("prior summary should be folded into the new one, still present: %q", m.Content)
		}
	}
}

func TestAbortDuringToolExecutionAppendsPendingToolResults(t *testing.T) {
	ec := &eventCollector{}
	mp := newMockProvider([][]provider.StreamEvent{
		toolCallResponse("call_1", "read_file", `{}`),
	})
	am := newAllowAllToolGuard()
	toolReg := tools.NewRegistry()
	toolStarted := make(chan struct{})
	toolReg.Register(&blockingTool{name: "read_file", started: toolStarted})

	loop := NewLoop(toolReg, am, nil, ec.sink)
	cfg := buildRunConfig(mp, toolReg.List())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resultCh := make(chan RunResult, 1)
	errCh := make(chan error, 1)
	go func() {
		result, err := loop.Run(ctx, cfg, "do it", nil)
		resultCh <- result
		errCh <- err
	}()

	select {
	case <-toolStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for tool execution to start")
	}
	cancel()

	result := <-resultCh
	err := <-errCh
	if !errors.Is(err, ErrAborted) {
		t.Fatalf("expected ErrAborted, got %v", err)
	}
	if len(result.Messages) != 3 {
		t.Fatalf("expected 3 messages, got %d", len(result.Messages))
	}
	if len(result.Messages[1].ToolCalls) != 1 {
		t.Fatalf("expected assistant tool call message to be preserved")
	}
	if len(result.Messages[2].ToolResults) != 1 {
		t.Fatalf("expected 1 tool result, got %d", len(result.Messages[2].ToolResults))
	}
	tr := result.Messages[2].ToolResults[0]
	if tr.ToolCallID != "call_1" {
		t.Fatalf("expected tool result for call_1, got %s", tr.ToolCallID)
	}
	if !tr.IsError {
		t.Fatalf("expected abort tool result to be marked as error")
	}
	if tr.Content == "" {
		t.Fatalf("expected abort tool result content")
	}
	if !containsString(tr.Content, "aborted") && !containsString(tr.Content, "canceled") {
		t.Fatalf("expected abort-related tool result content, got %q", tr.Content)
	}
}

func TestLoopRepairsDanglingToolCallHistoryBeforeProviderRequest(t *testing.T) {
	ec := &eventCollector{}
	mp := newMockProvider([][]provider.StreamEvent{
		simpleTextResponse("Recovered and continued."),
	})
	am := newAllowAllToolGuard()
	loop := NewLoop(tools.NewRegistry(), am, nil, ec.sink)

	cfg := buildRunConfig(mp, nil)
	cfg.Messages = []internal.Message{
		{ID: internal.NewMessageID(), Role: "user", Content: "hello", CreatedAt: time.Now()},
		{
			ID:      internal.NewMessageID(),
			Role:    "assistant",
			Content: "calling a tool",
			ToolCalls: []internal.ToolCall{{
				ID:   "call_broken",
				Name: "read_file",
			}},
			CreatedAt: time.Now(),
		},
	}

	result, err := loop.Run(context.Background(), cfg, "continue", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mp.requests) != 1 {
		t.Fatalf("expected 1 provider request, got %d", len(mp.requests))
	}
	requestMessages := mp.requests[0].Messages
	if len(requestMessages) != 4 {
		t.Fatalf("expected repaired history plus new user message, got %d messages", len(requestMessages))
	}
	if len(requestMessages[2].ToolResults) != 1 {
		t.Fatalf("expected synthetic tool result before new user message")
	}
	if requestMessages[2].ToolResults[0].ToolCallID != "call_broken" {
		t.Fatalf("expected repaired tool_call_id call_broken, got %s", requestMessages[2].ToolResults[0].ToolCallID)
	}
	if requestMessages[3].Content != "continue" {
		t.Fatalf("expected new user message after repaired tool result, got %q", requestMessages[3].Content)
	}
	if len(result.Messages) < 5 {
		t.Fatalf("expected repaired tool result to remain in run messages, got %d", len(result.Messages))
	}
}

func TestLoopPreflightCompactsBeforePostToolProviderCall(t *testing.T) {
	ec := &eventCollector{}
	mp := newMockProvider([][]provider.StreamEvent{
		toolCallResponse("call_read_1", "read_file", `{"filePath":"README.md","startLine":1,"endLine":20}`),
		simpleTextResponse("done"),
	})
	mp.countFunc = func(req *provider.Request) (*provider.Usage, error) {
		if req == nil {
			return &provider.Usage{InputTokens: 1}, nil
		}
		if len(req.Messages) > 0 && req.Messages[len(req.Messages)-1].Content == compactionUserPrompt {
			return &provider.Usage{InputTokens: 10_000}, nil
		}
		for _, message := range req.Messages {
			if len(message.ToolResults) > 0 {
				return &provider.Usage{InputTokens: 95}, nil
			}
		}
		return &provider.Usage{InputTokens: 10}, nil
	}

	registry := tools.NewRegistry()
	registry.Register(&staticTool{name: "read_file", content: strings.Repeat("tool output ", 40)})
	loop := NewLoop(registry, newAllowAllToolGuard(), NewCompactor(0.80, "", ec.sink), ec.sink)

	cfg := buildRunConfig(mp, registry.List())
	cfg.ModelName = "MiniMax-M2.7"
	cfg.TokenBudget = 100
	cfg.Messages = []internal.Message{
		{ID: internal.NewMessageID(), Role: "user", Content: "history one", CreatedAt: time.Now()},
		{ID: internal.NewMessageID(), Role: "assistant", Content: "history two", CreatedAt: time.Now()},
		{ID: internal.NewMessageID(), Role: "user", Content: "history three", CreatedAt: time.Now()},
		{ID: internal.NewMessageID(), Role: "assistant", Content: "history four", CreatedAt: time.Now()},
		{ID: internal.NewMessageID(), Role: "user", Content: "history five", CreatedAt: time.Now()},
		{ID: internal.NewMessageID(), Role: "assistant", Content: "history six", CreatedAt: time.Now()},
	}
	result, err := loop.Run(context.Background(), cfg, "inspect the file", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	providerRequests := make([]*provider.Request, 0, len(mp.requests))
	for _, req := range mp.requests {
		if len(req.Messages) > 0 && req.Messages[len(req.Messages)-1].Content == compactionUserPrompt {
			continue
		}
		providerRequests = append(providerRequests, req)
	}

	if len(providerRequests) != 2 {
		t.Fatalf("expected 2 non-summary provider requests, got %d total and %d non-summary", len(mp.requests), len(providerRequests))
	}
	if len(providerRequests[1].Messages) >= 9 {
		t.Fatalf("expected second non-summary provider request to be compacted before send, got %d messages", len(providerRequests[1].Messages))
	}
	payloads := collectEventPayloads(ec, internal.EventCompactionPerformed)
	if len(payloads) == 0 {
		t.Fatal("expected preflight compaction event payload")
	}
	if !result.Compacted {
		t.Fatal("expected run result to report compaction")
	}
	if len(result.Messages) == 0 {
		t.Fatal("expected run result to retain messages after compaction")
	}
}

func TestLoopPostToolCompactionDoesNotImmediatelyRepeatOnStaleTokenCount(t *testing.T) {
	ec := &eventCollector{}
	mp := newMockProvider([][]provider.StreamEvent{
		{
			{Type: provider.EventToolUse, ToolCall: &provider.ToolCallEvent{
				ID:        "call_read_1",
				Name:      "read_file",
				Arguments: `{"filePath":"README.md","startLine":1,"endLine":20}`,
			}},
			{Type: provider.EventDone, Usage: &provider.Usage{InputTokens: 1_740, OutputTokens: 50}},
		},
		simpleTextResponse("automatic compaction summary"),
		simpleTextResponse("done"),
		simpleTextResponse("unexpected duplicate summary"),
	})

	registry := tools.NewRegistry()
	registry.Register(&staticTool{name: "read_file", content: strings.Repeat("tool ", 20)})

	loop := NewLoop(registry, newAllowAllToolGuard(), NewCompactor(0.80, "", ec.sink), ec.sink)
	cfg := buildRunConfig(mp, registry.List())
	cfg.ModelName = "MiniMax-M2.7"
	cfg.TokenBudget = 3400
	cfg.Messages = []internal.Message{
		{ID: internal.NewMessageID(), Role: "user", Content: "history one", CreatedAt: time.Now()},
		{ID: internal.NewMessageID(), Role: "assistant", Content: "history two", CreatedAt: time.Now()},
		{ID: internal.NewMessageID(), Role: "user", Content: "history three", CreatedAt: time.Now()},
		{ID: internal.NewMessageID(), Role: "assistant", Content: "history four", CreatedAt: time.Now()},
		{ID: internal.NewMessageID(), Role: "user", Content: "history five", CreatedAt: time.Now()},
		{ID: internal.NewMessageID(), Role: "assistant", Content: "history six", CreatedAt: time.Now()},
		{ID: internal.NewMessageID(), Role: "user", Content: "history seven", CreatedAt: time.Now()},
		{ID: internal.NewMessageID(), Role: "assistant", Content: "history eight", CreatedAt: time.Now()},
		{ID: internal.NewMessageID(), Role: "user", Content: "history nine", CreatedAt: time.Now()},
		{ID: internal.NewMessageID(), Role: "assistant", Content: "history ten", CreatedAt: time.Now()},
		{ID: internal.NewMessageID(), Role: "user", Content: "history eleven", CreatedAt: time.Now()},
		{ID: internal.NewMessageID(), Role: "assistant", Content: "history twelve", CreatedAt: time.Now()},
	}

	result, err := loop.Run(context.Background(), cfg, "inspect the file", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if mp.callIndex != 2 {
		t.Fatalf("expected exactly 2 provider calls (tool call, final reply) when fresh token estimation stays below the threshold, got %d", mp.callIndex)
	}
	payloads := collectEventPayloads(ec, internal.EventCompactionPerformed)
	if len(payloads) != 0 {
		t.Fatalf("expected no compaction event when the refreshed estimate stays below threshold, got %d", len(payloads))
	}
	if result.Compacted {
		t.Fatal("expected run result not to report compaction when the refreshed estimate stays below threshold")
	}
	if last := result.Messages[len(result.Messages)-1]; last.Role != "assistant" || last.Content != "automatic compaction summary" {
		t.Fatalf("expected final assistant reply after compaction, got role=%q content=%q", last.Role, last.Content)
	}
}

func TestLoopFinalAssistantReplyDoesNotTriggerAutomaticCompactionRequest(t *testing.T) {
	ec := &eventCollector{}
	mp := newMockProvider([][]provider.StreamEvent{
		{
			{Type: provider.EventToken, Content: strings.Repeat("final reply ", 20)},
			{Type: provider.EventDone, Usage: &provider.Usage{InputTokens: 1_700, OutputTokens: 200}},
		},
		simpleTextResponse("unexpected automatic compaction summary"),
	})

	loop := NewLoop(tools.NewRegistry(), newAllowAllToolGuard(), NewCompactor(0.80, "", ec.sink), ec.sink)
	cfg := buildRunConfig(mp, nil)
	cfg.ModelName = "MiniMax-M2.7"
	cfg.TokenBudget = 3_400

	result, err := loop.Run(context.Background(), cfg, "wrap this up", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mp.callIndex != 1 {
		t.Fatalf("expected exactly 1 provider call for the final reply, got %d", mp.callIndex)
	}
	payloads := collectEventPayloads(ec, internal.EventCompactionPerformed)
	if len(payloads) != 0 {
		t.Fatalf("expected no automatic compaction event after final assistant reply, got %d", len(payloads))
	}
	if result.Compacted {
		t.Fatal("expected final no-tool reply not to mark the run as compacted")
	}
	if last := result.Messages[len(result.Messages)-1]; last.Role != "assistant" {
		t.Fatalf("expected final message role assistant, got %q", last.Role)
	}
	if !strings.Contains(result.Messages[len(result.Messages)-1].Content, "final reply") {
		t.Fatalf("expected final assistant reply to be preserved, got %q", result.Messages[len(result.Messages)-1].Content)
	}
}

// --- blockingProvider blocks until context is cancelled ---

type blockingProvider struct{}

func (bp *blockingProvider) Name() string { return "blocking" }

func (bp *blockingProvider) Stream(ctx context.Context, _ *provider.Request) (<-chan provider.StreamEvent, error) {
	ch := make(chan provider.StreamEvent)
	go func() {
		defer close(ch)
		<-ctx.Done()
		ch <- provider.StreamEvent{Type: provider.EventError, Error: ctx.Err()}
	}()
	return ch, nil
}

func (bp *blockingProvider) CountTokens(_ context.Context, _ *provider.Request) (*provider.Usage, error) {
	return &provider.Usage{}, nil
}

// partialBlockingProvider emits text, then waits for the stream context to be
// cancelled. It models a real provider stream that has already shown a prefix
// to the user when a steer arrives.
type partialBlockingProvider struct {
	tokenSent chan struct{}
}

func (p *partialBlockingProvider) Name() string { return "partial-blocking" }

func (p *partialBlockingProvider) Stream(ctx context.Context, _ *provider.Request) (<-chan provider.StreamEvent, error) {
	ch := make(chan provider.StreamEvent, 1)
	go func() {
		defer close(ch)
		ch <- provider.StreamEvent{Type: provider.EventToken, Content: "partial reply"}
		close(p.tokenSent)
		<-ctx.Done()
	}()
	return ch, nil
}

func (p *partialBlockingProvider) CountTokens(_ context.Context, _ *provider.Request) (*provider.Usage, error) {
	return &provider.Usage{}, nil
}

type blockingTool struct {
	name    string
	started chan struct{}
}

// steerBlockingTool intentionally ignores completion until release. It lets
// the interruption test prove that Interrupt does not cancel an active tool.
type steerBlockingTool struct {
	name    string
	started chan struct{}
	release chan struct{}
}

func (t *steerBlockingTool) Name() internal.ToolName { return internal.ToolName(t.name) }
func (t *steerBlockingTool) Description() string     { return "blocks until released" }
func (t *steerBlockingTool) Parameters() json.RawMessage {
	return json.RawMessage(`{"type":"object"}`)
}
func (t *steerBlockingTool) Execute(ctx context.Context, _ json.RawMessage) (*tools.Result, error) {
	close(t.started)
	select {
	case <-t.release:
		return &tools.Result{Content: "tool completed"}, nil
	case <-ctx.Done():
		return &tools.Result{Content: ctx.Err().Error(), IsError: true}, ctx.Err()
	}
}

func (t *blockingTool) Name() internal.ToolName { return internal.ToolName(t.name) }

func (t *blockingTool) Description() string { return "blocks until canceled" }

func (t *blockingTool) Parameters() json.RawMessage { return json.RawMessage(`{"type":"object"}`) }

func (t *blockingTool) Execute(ctx context.Context, args json.RawMessage) (*tools.Result, error) {
	if t.started != nil {
		close(t.started)
	}
	<-ctx.Done()
	return &tools.Result{Content: ctx.Err().Error(), IsError: true}, ctx.Err()
}

// --- Test helpers ---

func assertContains(t *testing.T, slice []string, want string) {
	t.Helper()
	for _, s := range slice {
		if s == want {
			return
		}
	}
	t.Errorf("expected %q in %v", want, slice)
}

func hasEventType(slice []string, want string) bool {
	for _, item := range slice {
		if item == want {
			return true
		}
	}
	return false
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstr(s, substr))
}

func containsSubstr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}
}
