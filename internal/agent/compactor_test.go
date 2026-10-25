package agent

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	internal "github.com/Problem99-io/kodeblue/internal"
	"github.com/Problem99-io/kodeblue/internal/provider"
)

type compactionTestProvider struct {
	responses [][]provider.StreamEvent
	requests  []*provider.Request
	callIndex int
}

func newCompactionTestProvider(responses [][]provider.StreamEvent) *compactionTestProvider {
	return &compactionTestProvider{responses: responses}
}

func (p *compactionTestProvider) Name() string { return "compaction-test" }

func (p *compactionTestProvider) Stream(_ context.Context, req *provider.Request) (<-chan provider.StreamEvent, error) {
	if req != nil {
		cloned := *req
		p.requests = append(p.requests, &cloned)
	}
	idx := p.callIndex
	p.callIndex++
	ch := make(chan provider.StreamEvent, 8)
	go func() {
		defer close(ch)
		if idx < len(p.responses) {
			for _, event := range p.responses[idx] {
				ch <- event
			}
		}
	}()
	return ch, nil
}

func (p *compactionTestProvider) CountTokens(_ context.Context, req *provider.Request) (*provider.Usage, error) {
	var total int64
	if req != nil {
		if req.SystemPrompt != "" {
			total += int64(len(strings.Fields(req.SystemPrompt)))
		}
		for _, message := range req.Messages {
			total += int64(len(strings.Fields(message.Content)))
			total += int64(len(message.ToolCalls) * 8)
			total += int64(len(message.ToolResults) * 8)
		}
	}
	if total < 1 {
		total = 1
	}
	return &provider.Usage{InputTokens: total}, nil
}

func TestCompactorUsesFixedThresholdAndConfiguredSummaryModel(t *testing.T) {
	ec := &eventCollector{}
	c := NewCompactor(0.80, "gpt-5.4-nano", ec.sink)

	if c.NeedsCompaction(50, 100) {
		t.Fatal("50/100 should not trigger compaction")
	}
	if c.NeedsCompaction(79, 100) {
		t.Fatal("79/100 should not trigger compaction")
	}
	if !c.NeedsCompaction(80, 100) {
		t.Fatal("80/100 should trigger compaction")
	}

	p := newCompactionTestProvider([][]provider.StreamEvent{simpleTextResponse("Summary of the conversation middle.")})
	messages := make([]internal.Message, 12)
	for i := range messages {
		role := "user"
		if i%2 == 1 {
			role = "assistant"
		}
		messages[i] = internal.Message{
			ID:        internal.NewMessageID(),
			Role:      role,
			Content:   fmt.Sprintf("message %c detail", rune('A'+i)),
			CreatedAt: time.Now(),
		}
	}

	result, err := c.Compact(context.Background(), p, "sess_1", "run_1", messages, CompactOptions{ActiveModel: "gpt-5.4", ContextWindow: 40})
	if err != nil {
		t.Fatalf("Compact() error = %v", err)
	}
	if len(result) >= len(messages) {
		t.Fatalf("expected compacted message count to shrink, got before=%d after=%d", len(messages), len(result))
	}
	// frozenPrefix is 0, so there is no pinned prefix: the summary is first and
	// the raw recent tail (ending at the last original message) follows.
	if !strings.Contains(result[0].Content, "Compacted context") {
		t.Fatalf("expected compaction summary at index 0, got %q", result[0].Content)
	}
	if result[len(result)-1].Content != "message L detail" {
		t.Fatalf("expected recent tail to end at the last original message, got %q", result[len(result)-1].Content)
	}
	// An explicit compaction_model is honoured (docs/engine.md); without one
	// the active model writes the summary (see the fallback test below).
	if len(p.requests) != 1 || p.requests[0].Model != "gpt-5.4-nano" {
		t.Fatalf("expected configured compaction model, got requests=%d model=%q", len(p.requests), firstCompactionRequestModel(p.requests))
	}
	if payloads := collectEventPayloads(ec, internal.EventCompactionPerformed); len(payloads) == 0 {
		t.Fatal("expected compaction event payload")
	}
}

func TestCompactorKeepsToolCallAndResultAdjacentInRawTail(t *testing.T) {
	c := NewCompactor(0.80, "", nil)
	p := newCompactionTestProvider([][]provider.StreamEvent{simpleTextResponse("Summary of the conversation middle.")})

	messages := make([]internal.Message, 8)
	for i := range messages {
		role := "user"
		if i%2 == 1 {
			role = "assistant"
		}
		messages[i] = internal.Message{ID: internal.NewMessageID(), Role: role, Content: fmt.Sprintf("m%d", i+1), CreatedAt: time.Now()}
	}
	messages[6] = internal.Message{
		ID:        internal.NewMessageID(),
		Role:      "assistant",
		Content:   "calling tool",
		CreatedAt: time.Now(),
		ToolCalls: []internal.ToolCall{{ID: "call_1", Name: "read_file"}},
	}
	messages[7] = internal.Message{
		ID:        internal.NewMessageID(),
		Role:      "user",
		CreatedAt: time.Now(),
		ToolResults: []internal.ToolResult{{
			ToolCallID: "call_1",
			Content:    "tool output",
		}},
	}

	result, err := c.Compact(context.Background(), p, "sess_1", "run_1", messages, CompactOptions{ActiveModel: "gpt-5.4", ContextWindow: 32})
	if err != nil {
		t.Fatalf("Compact() error = %v", err)
	}

	toolCallIndex := -1
	toolResultIndex := -1
	for i := range result {
		if len(result[i].ToolCalls) > 0 && result[i].ToolCalls[0].ID == "call_1" {
			toolCallIndex = i
		}
		if len(result[i].ToolResults) > 0 && result[i].ToolResults[0].ToolCallID == "call_1" {
			toolResultIndex = i
		}
	}
	if toolCallIndex == -1 || toolResultIndex == -1 {
		t.Fatalf("expected tool call/result to remain active after compaction: %#v", result)
	}
	if toolResultIndex != toolCallIndex+1 {
		t.Fatalf("expected tool result immediately after tool call, got call=%d result=%d", toolCallIndex, toolResultIndex)
	}
}

func TestCompactorUsesActiveModelFallbackAndFallbackSummary(t *testing.T) {
	ec := &eventCollector{}
	c := NewCompactor(0.80, "", ec.sink)
	p := newCompactionTestProvider(nil)

	messages := make([]internal.Message, 14)
	for i := range messages {
		role := "user"
		if i%2 == 1 {
			role = "assistant"
		}
		messages[i] = internal.Message{
			ID:        internal.NewMessageID(),
			Role:      role,
			Content:   strings.Repeat("very long context ", 40),
			CreatedAt: time.Now(),
		}
	}

	result, err := c.Compact(context.Background(), p, "sess_1", "run_1", messages, CompactOptions{ActiveModel: "gpt-5.4", ContextWindow: 32})
	if err != nil {
		t.Fatalf("Compact() error = %v", err)
	}
	// frozenPrefix is 0, so the summary (carrying the fallback content) is first.
	if !strings.Contains(result[0].Content, "User:") && !strings.Contains(result[0].Content, "Assistant:") {
		t.Fatalf("expected fallback summary content, got %q", result[0].Content)
	}
	if len(p.requests) != 1 {
		t.Fatalf("expected one summary stream attempt before fallback, got %d", len(p.requests))
	}
	payloads := collectEventPayloads(ec, internal.EventCompactionPerformed)
	if len(payloads) == 0 {
		t.Fatal("expected compaction event payload")
	}
	if payloads[0]["used_fallback"] != true {
		t.Fatalf("expected fallback summary to be reported, got %#v", payloads[0])
	}

	p = newCompactionTestProvider([][]provider.StreamEvent{simpleTextResponse("Summary of the conversation middle.")})
	messages = make([]internal.Message, 10)
	for i := range messages {
		role := "user"
		if i%2 == 1 {
			role = "assistant"
		}
		messages[i] = internal.Message{ID: internal.NewMessageID(), Role: role, Content: fmt.Sprintf("m%d detail", i+1), CreatedAt: time.Now()}
	}

	_, err = c.Compact(context.Background(), p, "sess_1", "run_1", messages, CompactOptions{ActiveModel: "gpt-5.4", ContextWindow: 40})
	if err != nil {
		t.Fatalf("Compact() error = %v", err)
	}
	if len(p.requests) != 1 || p.requests[0].Model != "gpt-5.4" {
		t.Fatalf("expected active model fallback, got requests=%d model=%q", len(p.requests), firstCompactionRequestModel(p.requests))
	}
}

func TestManualCompactionUses25kPlanningThreshold(t *testing.T) {
	c := NewCompactor(0.80, "", nil)
	p := newCompactionTestProvider(nil)

	messages := make([]internal.Message, 12)
	for i := range messages {
		role := "user"
		content := strings.Repeat("tail detail ", 1100)
		if i%2 == 1 {
			role = "assistant"
		}
		if i < 2 {
			content = strings.Repeat("frozen prefix ", 1000)
		}
		messages[i] = internal.Message{
			ID:        internal.NewMessageID(),
			Role:      role,
			Content:   content,
			CreatedAt: time.Now(),
		}
	}

	result, err := c.Compact(context.Background(), p, "sess_1", "run_1", messages, CompactOptions{ActiveModel: "gpt-5.4", ContextWindow: 100_000, Manual: true})
	if err != nil {
		t.Fatalf("Compact() error = %v", err)
	}
	if len(result) >= len(messages) {
		t.Fatalf("expected manual compaction above 25k tokens to shrink history, got before=%d after=%d", len(messages), len(result))
	}
	if !strings.Contains(result[0].Content, "Compacted context") {
		t.Fatalf("expected compaction summary at index 0, got %q", result[0].Content)
	}
	if len(p.requests) != 1 {
		t.Fatalf("expected a summary request for manual compaction, got requests=%d", len(p.requests))
	}
	if total := countMessageTokens(messages); total <= manualCompactionTriggerTokens {
		t.Fatalf("expected fixture to exceed manual compaction threshold, got %d", total)
	}
	if tailTokens := countMessageTokens(messages[2:]); tailTokens >= manualCompactionTriggerTokens {
		t.Fatalf("expected non-frozen tail to stay below old raw-tail planning window, got %d", tailTokens)
	}
}

func TestManualCompactionUsesProvidedCurrentInputTokens(t *testing.T) {
	c := NewCompactor(0.80, "", nil)
	p := newCompactionTestProvider(nil)

	messages := make([]internal.Message, 12)
	for i := range messages {
		role := "user"
		content := strings.Repeat("tail detail ", 400)
		if i%2 == 1 {
			role = "assistant"
		}
		if i < 2 {
			content = strings.Repeat("frozen prefix ", 200)
		}
		messages[i] = internal.Message{
			ID:        internal.NewMessageID(),
			Role:      role,
			Content:   content,
			CreatedAt: time.Now(),
		}
	}

	if total := countMessageTokens(messages); total >= manualCompactionTriggerTokens {
		t.Fatalf("expected fixture to stay below estimated manual threshold, got %d", total)
	}

	result, err := c.Compact(context.Background(), p, "sess_1", "run_1", messages, CompactOptions{
		ActiveModel:        "gpt-5.4",
		ContextWindow:      100_000,
		CurrentInputTokens: 35_000,
		Manual:             true,
	})
	if err != nil {
		t.Fatalf("Compact() error = %v", err)
	}
	if len(result) >= len(messages) {
		t.Fatalf("expected provided current input tokens to trigger manual compaction, got before=%d after=%d", len(messages), len(result))
	}
	if len(p.requests) != 1 {
		t.Fatalf("expected a summary request when provided current input tokens exceed threshold, got requests=%d", len(p.requests))
	}
	if !strings.Contains(result[0].Content, "Compacted context") {
		t.Fatalf("expected compaction summary at index 0, got %q", result[0].Content)
	}
}

func TestAutomaticCompactionKeepsRecentRawMessagesAndSummaryStack(t *testing.T) {
	c := NewCompactor(0.80, "", nil)
	p := newCompactionTestProvider([][]provider.StreamEvent{simpleTextResponse("Fresh automatic summary")})

	messages := []internal.Message{
		{ID: internal.NewMessageID(), Role: "user", Content: "raw message 1", CreatedAt: time.Now().Add(-22 * time.Minute)},
		{ID: internal.NewMessageID(), Role: "assistant", Content: "raw message 2", CreatedAt: time.Now().Add(-21 * time.Minute)},
		{ID: internal.NewMessageID(), Role: "user", Content: "[Compacted context — 4 messages summarized]\nsummary one", CreatedAt: time.Now().Add(-20 * time.Minute)},
		{ID: internal.NewMessageID(), Role: "assistant", Content: "[Compacted context — 4 messages summarized]\nsummary two", CreatedAt: time.Now().Add(-19 * time.Minute)},
		{ID: internal.NewMessageID(), Role: "assistant", Content: "[Compacted context — 4 messages summarized]\nsummary three", CreatedAt: time.Now().Add(-18 * time.Minute)},
	}
	for i := 2; i < 14; i++ {
		role := "user"
		if i%2 == 1 {
			role = "assistant"
		}
		messages = append(messages, internal.Message{
			ID:        internal.NewMessageID(),
			Role:      role,
			Content:   fmt.Sprintf("raw message %d", i+1),
			CreatedAt: time.Now().Add(time.Duration(i) * time.Minute),
		})
	}

	result, err := c.Compact(context.Background(), p, "sess_1", "run_1", messages, CompactOptions{
		ActiveModel:   "gpt-5.4",
		Automatic:     true,
		ContextWindow: 100,
		SystemPrompt:  "system prompt",
		Tools: []internal.ToolDefinition{{
			Name:        "read_file",
			Description: "read a file",
		}},
	})
	if err != nil {
		t.Fatalf("Compact() error = %v", err)
	}
	if len(result) >= len(messages) {
		t.Fatalf("expected automatic compaction to shrink history, got before=%d after=%d", len(messages), len(result))
	}
	// frozenPrefix is 0: the fresh summary is first, with the raw recent tail
	// following and ending at the most recent message.
	if !strings.Contains(result[0].Content, "Fresh automatic summary") {
		t.Fatalf("expected new summary at index 0, got %q", result[0].Content)
	}
	if result[0].Role != "user" {
		t.Fatalf("expected unified compacted summary role user, got %q", result[0].Role)
	}
	if result[len(result)-1].Content != "raw message 14" {
		t.Fatalf("expected recent tail to end at the last raw message, got %q", result[len(result)-1].Content)
	}
	if len(p.requests) != 1 {
		t.Fatalf("expected 1 summary request, got %d", len(p.requests))
	}
	if p.requests[0].SystemPrompt != "system prompt" {
		t.Fatalf("expected live agent system prompt for cache parity, got %q", p.requests[0].SystemPrompt)
	}
	if len(p.requests[0].Messages) < 2 {
		t.Fatalf("expected full live context plus synthetic compaction prompt, got %d request messages", len(p.requests[0].Messages))
	}
	if len(p.requests[0].Tools) != 1 {
		t.Fatalf("expected live agent tool definitions to be forwarded for cache parity, got %#v", p.requests[0].Tools)
	}
	if p.requests[0].Model != "gpt-5.4" {
		t.Fatalf("expected active model for automatic summary request, got %q", p.requests[0].Model)
	}
	lastReqMsg := p.requests[0].Messages[len(p.requests[0].Messages)-1]
	if lastReqMsg.Role != "user" || lastReqMsg.Content != compactionUserPrompt {
		t.Fatalf("expected synthetic compaction user prompt at end of request, got role=%q content=%q", lastReqMsg.Role, lastReqMsg.Content)
	}
}

func TestAutomaticCompactionPreservesToolCallResultBoundary(t *testing.T) {
	c := NewCompactor(0.80, "", nil)
	p := newCompactionTestProvider([][]provider.StreamEvent{simpleTextResponse("Fresh automatic summary")})

	messages := make([]internal.Message, 13)
	for i := range messages {
		role := "user"
		if i%2 == 1 {
			role = "assistant"
		}
		messages[i] = internal.Message{ID: internal.NewMessageID(), Role: role, Content: fmt.Sprintf("m%d", i+1), CreatedAt: time.Now()}
	}
	messages[11] = internal.Message{
		ID:        internal.NewMessageID(),
		Role:      "assistant",
		Content:   "calling tool",
		CreatedAt: time.Now(),
		ToolCalls: []internal.ToolCall{{ID: "call_1", Name: "read_file"}},
	}
	messages[12] = internal.Message{
		ID:        internal.NewMessageID(),
		Role:      "user",
		CreatedAt: time.Now(),
		ToolResults: []internal.ToolResult{{
			ToolCallID: "call_1",
			Content:    "tool output",
		}},
	}

	result, err := c.Compact(context.Background(), p, "sess_1", "run_1", messages, CompactOptions{ActiveModel: "gpt-5.4", Automatic: true, ContextWindow: 100})
	if err != nil {
		t.Fatalf("Compact() error = %v", err)
	}
	if len(result) >= len(messages) {
		t.Fatalf("expected automatic compaction to shrink history, got before=%d after=%d", len(messages), len(result))
	}
	// frozenPrefix is 0: the summary is first (role user), then the recent tail.
	if result[0].Role != "user" {
		t.Fatalf("expected unified compaction summary role user, got %q", result[0].Role)
	}
	if !strings.Contains(result[0].Content, "Fresh automatic summary") {
		t.Fatalf("expected compacted summary at index 0, got %q", result[0].Content)
	}
	toolCallIndex := -1
	toolResultIndex := -1
	for i := range result {
		if len(result[i].ToolCalls) > 0 && result[i].ToolCalls[0].ID == "call_1" {
			toolCallIndex = i
		}
		if len(result[i].ToolResults) > 0 && result[i].ToolResults[0].ToolCallID == "call_1" {
			toolResultIndex = i
		}
	}
	if toolCallIndex == -1 || toolResultIndex == -1 {
		t.Fatalf("expected tool call/result to remain active after compaction: %#v", result)
	}
	if toolResultIndex != toolCallIndex+1 {
		t.Fatalf("expected tool result immediately after tool call, got call=%d result=%d", toolCallIndex, toolResultIndex)
	}
}

func firstCompactionRequestModel(requests []*provider.Request) string {
	if len(requests) == 0 || requests[0] == nil {
		return ""
	}
	return requests[0].Model
}

func TestCompactionNeverSummarizesLeadingSystemMessageAndKeepsSystemPrompt(t *testing.T) {
	c := NewCompactor(0.80, "", nil)
	p := newCompactionTestProvider([][]provider.StreamEvent{simpleTextResponse("Fresh summary")})

	messages := []internal.Message{
		{ID: internal.NewMessageID(), Role: "system", Content: "SYSTEM: base instructions that must never be summarized", CreatedAt: time.Now().Add(-30 * time.Minute)},
	}
	for i := 0; i < 14; i++ {
		role := "user"
		if i%2 == 1 {
			role = "assistant"
		}
		messages = append(messages, internal.Message{
			ID:        internal.NewMessageID(),
			Role:      role,
			Content:   fmt.Sprintf("raw message %d", i+1),
			CreatedAt: time.Now().Add(time.Duration(i) * time.Minute),
		})
	}

	result, err := c.Compact(context.Background(), p, "sess_sys", "run_sys", messages, CompactOptions{
		ActiveModel:   "gpt-5.4",
		Automatic:     true,
		ContextWindow: 100,
		SystemPrompt:  "system prompt",
	})
	if err != nil {
		t.Fatalf("Compact() error = %v", err)
	}
	if len(result) >= len(messages) {
		t.Fatalf("expected compaction to shrink history, got before=%d after=%d", len(messages), len(result))
	}
	// The leading system message must be pinned: it stays at index 0, verbatim,
	// and is never folded into a summary.
	if result[0].Role != "system" || result[0].Content != messages[0].Content {
		t.Fatalf("expected leading system message preserved verbatim at index 0, got role=%q content=%q", result[0].Role, result[0].Content)
	}
	for _, m := range result {
		if m.Role == "system" && strings.Contains(m.Content, "Compacted context") {
			t.Fatalf("system message must never be turned into a compaction summary, got %q", m.Content)
		}
	}
	// The summary request must still carry the live system prompt.
	if len(p.requests) != 1 || p.requests[0].SystemPrompt != "system prompt" {
		t.Fatalf("expected summary request to preserve system prompt, got requests=%d prompt=%q", len(p.requests), firstCompactionRequestPrompt(p.requests))
	}
}

func firstCompactionRequestPrompt(requests []*provider.Request) string {
	if len(requests) == 0 || requests[0] == nil {
		return ""
	}
	return requests[0].SystemPrompt
}
