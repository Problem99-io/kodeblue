package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	internal "github.com/Problem99-io/kodeblue/internal"
	"github.com/Problem99-io/kodeblue/internal/provider"
	"github.com/Problem99-io/kodeblue/internal/tools"
)

// stallingSummaryProvider streams part of a summary, then waits for the
// request to be cancelled without ever sending EventDone.
type stallingSummaryProvider struct {
	streaming chan struct{}
}

func (p *stallingSummaryProvider) Name() string { return "stalling" }

func (p *stallingSummaryProvider) Stream(ctx context.Context, _ *provider.Request) (<-chan provider.StreamEvent, error) {
	ch := make(chan provider.StreamEvent, 4)
	go func() {
		defer close(ch)
		ch <- provider.StreamEvent{Type: provider.EventToken, Content: "Current Task:\n- investigate the brute force from 203.0."}
		close(p.streaming)
		<-ctx.Done()
	}()
	return ch, nil
}

func (p *stallingSummaryProvider) CountTokens(context.Context, *provider.Request) (*provider.Usage, error) {
	return &provider.Usage{InputTokens: 1}, nil
}

func longConversation(n int, body string) []internal.Message {
	messages := make([]internal.Message, 0, n)
	for i := 0; i < n; i++ {
		role := "user"
		if i%2 == 1 {
			role = "assistant"
		}
		messages = append(messages, internal.Message{ID: internal.NewMessageID(), Role: role, Content: fmt.Sprintf("m%d %s", i, body), CreatedAt: time.Now()})
	}
	return messages
}

func TestCompactionAbortedDuringSummaryKeepsHistory(t *testing.T) {
	ec := &eventCollector{}
	c := NewCompactor(0.8, "", ec.sink)
	p := &stallingSummaryProvider{streaming: make(chan struct{})}
	messages := longConversation(30, strings.Repeat("evidence ", 200))
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-p.streaming
		cancel()
	}()
	report, err := c.CompactWithReport(ctx, p, "s", "r", messages, CompactOptions{ActiveModel: "m", ContextWindow: 8000, Manual: true})
	if err == nil {
		t.Fatalf("aborted compaction succeeded: %d messages, summary %q", len(report.Messages), report.SummaryContent)
	}
	if len(report.Messages) != 0 {
		t.Fatalf("aborted compaction returned a rewritten history")
	}
	if payloads := collectEventPayloads(ec, internal.EventCompactionPerformed); len(payloads) != 0 {
		t.Fatalf("aborted compaction reported as performed: %v", payloads)
	}
}

func TestCompactionStreamWithoutDoneUsesFallbackNotTruncatedText(t *testing.T) {
	c := NewCompactor(0.8, "", nil)
	p := newCompactionTestProvider([][]provider.StreamEvent{{
		{Type: provider.EventToken, Content: "Current Task:\n- half a summ"},
	}})
	messages := longConversation(30, strings.Repeat("evidence ", 200))
	report, err := c.CompactWithReport(context.Background(), p, "s", "r", messages, CompactOptions{ActiveModel: "m", ContextWindow: 8000, Manual: true})
	if err != nil {
		t.Fatal(err)
	}
	if report.UsedLLMSummary || !report.UsedFallbackSummary || strings.Contains(report.SummaryContent, "half a summ") {
		t.Fatalf("truncated stream accepted as the summary: %+v", report)
	}
}

func TestLoopAbortDuringAutomaticCompactionKeepsHistory(t *testing.T) {
	ec := &eventCollector{}
	c := NewCompactor(0.5, "", ec.sink)
	p := &stallingSummaryProvider{streaming: make(chan struct{})}
	loop := NewLoop(tools.NewRegistry(), newAllowAllToolGuard(), c, ec.sink)
	cfg := buildRunConfig(p, nil)
	cfg.TokenBudget = 4000
	cfg.ModelName = "m"
	cfg.Messages = longConversation(20, strings.Repeat("evidence ", 60))
	go func() {
		<-p.streaming
		loop.Abort(cfg.RunID)
	}()
	result, err := loop.Run(context.Background(), cfg, "next question", nil)
	if err == nil {
		t.Fatal("run was not aborted")
	}
	if result.Compacted {
		t.Fatalf("run reports a compaction that was aborted: %v %+v", err, collectEvents(ec))
	}
	for _, m := range result.Messages {
		if IsCompactionSummary(m.Content) {
			t.Fatalf("aborted compaction left a summary: %q", m.Content)
		}
	}
	if len(result.Messages) < len(cfg.Messages) {
		t.Fatalf("history shrank to %d messages", len(result.Messages))
	}
}

func TestSummaryRequestFitsContextWindow(t *testing.T) {
	c := NewCompactor(0.8, "", nil)
	p := newCompactionTestProvider([][]provider.StreamEvent{simpleTextResponse("fresh summary")})
	var messages []internal.Message
	messages = append(messages, internal.Message{ID: internal.NewMessageID(), Role: "user", Content: "[Compacted context — 9 messages summarized]\nPRIOR-SUMMARY-MARKER sshd brute force from 203.0.113.7"})
	for i := 0; i < 20; i++ {
		id := fmt.Sprintf("call_%d", i)
		messages = append(messages,
			internal.Message{ID: internal.NewMessageID(), Role: "assistant", ToolCalls: []internal.ToolCall{{ID: id, Name: "bash", Arguments: json.RawMessage(`{"command":"journalctl -u ssh"}`)}}},
			internal.Message{ID: internal.NewMessageID(), Role: "user", ToolResults: []internal.ToolResult{{ToolCallID: id, Content: strings.Repeat("Failed password for root from 203.0.113.7 port 22 ssh2\n", 400)}}},
		)
	}
	const window = 64_000
	full := estimateRequestInputTokens(messages, nil, "sys") + estimateTextTokens(compactionUserPrompt)
	if full < window {
		t.Fatalf("fixture too small: %d tokens", full)
	}
	report, err := c.CompactWithReport(context.Background(), p, "s", "r", messages, CompactOptions{ActiveModel: "m", ContextWindow: window, SystemPrompt: "sys", Automatic: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.requests) != 1 {
		t.Fatalf("requests = %d", len(p.requests))
	}
	req := p.requests[0]
	sent := estimateRequestInputTokens(req.Messages, req.Tools, req.SystemPrompt)
	if sent+int64(req.MaxTokens) > window {
		t.Fatalf("summary request %d input + %d output exceeds window %d", sent, req.MaxTokens, window)
	}
	if report.SummaryInputTokens != sent {
		t.Fatalf("reported summary input %d, sent %d", report.SummaryInputTokens, sent)
	}
	var all strings.Builder
	for _, m := range req.Messages {
		all.WriteString(m.Content)
	}
	if !strings.Contains(all.String(), "PRIOR-SUMMARY-MARKER") {
		t.Fatal("trimmed summary input lost the prior compaction summary")
	}
	if last := req.Messages[len(req.Messages)-1]; last.Content != compactionUserPrompt {
		t.Fatalf("summary prompt is not last: %q", last.Content)
	}
	// Tool calls and results stay paired in the trimmed request.
	pending := map[string]bool{}
	for _, m := range req.Messages {
		for _, r := range m.ToolResults {
			if !pending[r.ToolCallID] {
				t.Fatalf("tool result %s without its call", r.ToolCallID)
			}
			delete(pending, r.ToolCallID)
		}
		for _, tc := range m.ToolCalls {
			pending[tc.ID] = true
		}
	}
	if len(pending) != 0 {
		t.Fatalf("tool calls without results: %v", pending)
	}
}

func TestSummaryRequestUnchangedWhenItFits(t *testing.T) {
	c := NewCompactor(0.8, "", nil)
	p := newCompactionTestProvider([][]provider.StreamEvent{simpleTextResponse("fresh summary")})
	messages := longConversation(30, strings.Repeat("evidence ", 600))
	if _, err := c.CompactWithReport(context.Background(), p, "s", "r", messages, CompactOptions{ActiveModel: "m", ContextWindow: 200_000, CurrentInputTokens: 30_000, Manual: true}); err != nil {
		t.Fatal(err)
	}
	req := p.requests[0]
	if len(req.Messages) != len(messages)+1 {
		t.Fatalf("summary request was trimmed although it fits: %d messages", len(req.Messages))
	}
	for i := range messages {
		if req.Messages[i].Content != messages[i].Content {
			t.Fatalf("message %d changed: cache prefix broken", i)
		}
	}
}

func TestFallbackSummaryKeepsTruncatedToolEvidence(t *testing.T) {
	c := NewCompactor(0.8, "", nil)
	output := "Accepted password for backdoor from 198.51.100.9" + strings.Repeat(" noise", 2000) + " TAIL-MARKER uid=0"
	middle := []internal.Message{
		{Role: "user", Content: "check auth logs"},
		{Role: "assistant", Content: "looking", ToolCalls: []internal.ToolCall{{ID: "c1", Name: "bash", Arguments: json.RawMessage(`{"command":"grep Accepted /var/log/auth.log"}`)}}},
		{Role: "user", ToolResults: []internal.ToolResult{{ToolCallID: "c1", Content: output}}},
		{Role: "user", ToolResults: []internal.ToolResult{{ToolCallID: "c2", Content: "permission denied", IsError: true}}},
	}
	summary := c.fallbackSummary(middle, 128_000)
	for _, want := range []string{"grep Accepted /var/log/auth.log", "Tool result bash: Accepted password for backdoor from 198.51.100.9", "TAIL-MARKER uid=0", "Tool result (error): permission denied"} {
		if !strings.Contains(summary, want) {
			t.Fatalf("fallback summary lacks %q:\n%s", want, summary)
		}
	}
	if len(summary) > 4000 {
		t.Fatalf("tool output not truncated: %d bytes", len(summary))
	}

	// The digest is bounded by the window, newest lines kept.
	var many []internal.Message
	for i := 0; i < 2000; i++ {
		many = append(many, internal.Message{Role: "user", Content: fmt.Sprintf("line %d %s", i, strings.Repeat("x", 300))})
	}
	bounded := c.fallbackSummary(many, 32_000)
	if tokens := estimateTextTokens(bounded); tokens > 3_400 {
		t.Fatalf("fallback summary is %d tokens for a 32k window", tokens)
	}
	if !strings.Contains(bounded, "line 1999") || !strings.Contains(bounded, "earlier entries omitted") {
		t.Fatalf("bounded digest should keep the newest lines")
	}
}

func TestRawTailBudgetFollowsWindowForAutomaticCompaction(t *testing.T) {
	messages := longConversation(60, strings.Repeat("evidence ", 1200))
	for _, tc := range []struct {
		name   string
		manual bool
		want   int64
	}{
		{"automatic", false, 25_000},
		{"manual", true, manualCompactionTriggerTokens / 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := NewCompactor(0.8, "", nil)
			p := newCompactionTestProvider([][]provider.StreamEvent{simpleTextResponse("summary")})
			report, err := c.CompactWithReport(context.Background(), p, "s", "r", messages, CompactOptions{ActiveModel: "m", ContextWindow: 100_000, Manual: tc.manual})
			if err != nil {
				t.Fatal(err)
			}
			if report.RawTailBudget != tc.want {
				t.Fatalf("raw tail budget = %d, want %d", report.RawTailBudget, tc.want)
			}
		})
	}
}

func TestCompactionSummaryExcludesReasoning(t *testing.T) {
	c := NewCompactor(0.8, "", nil)
	p := newCompactionTestProvider([][]provider.StreamEvent{{
		{Type: provider.EventToken, Channel: provider.ChannelReasoning, Content: "PRIVATE-THINKING"},
		{Type: provider.EventToken, Content: "the summary"},
		{Type: provider.EventDone},
	}})
	report, err := c.CompactWithReport(context.Background(), p, "s", "r", longConversation(30, strings.Repeat("e ", 400)), CompactOptions{ActiveModel: "m", ContextWindow: 8000, Manual: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(report.SummaryContent, "PRIVATE-THINKING") || report.SummaryContent != "the summary" {
		t.Fatalf("summary = %q", report.SummaryContent)
	}
}

func TestNormalizeToolArgumentsKeepsMalformedArgumentsAsJSONString(t *testing.T) {
	truncated := `{"command":"go build ./... 2>`
	args := normalizeToolArguments(truncated)
	if !json.Valid(args) {
		t.Fatalf("not valid JSON: %s", args)
	}
	var kept string
	if err := json.Unmarshal(args, &kept); err != nil || kept != truncated {
		t.Fatalf("arguments not preserved: %s", args)
	}
	if !malformedToolArguments(args) || malformedToolArguments(normalizeToolArguments(`{"a":1}`)) {
		t.Fatal("malformedToolArguments misclassifies")
	}
}

func TestLoopWithMalformedToolArgumentsProducesPersistableTranscript(t *testing.T) {
	ec := &eventCollector{}
	var checkpoints [][]byte
	mp := newMockProvider([][]provider.StreamEvent{
		toolCallResponse("tc_bad", "read_file", `{"path":"/var/log/au`),
		simpleTextResponse("done"),
	})
	loop := NewLoop(tools.NewRegistry(), newAllowAllToolGuard(), nil, ec.sink)
	cfg := buildRunConfig(mp, []internal.ToolDefinition{{Name: "read_file"}})
	result, err := loop.Run(context.Background(), cfg, "test", nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	encoded, err := json.Marshal(result.Messages)
	if err != nil {
		t.Fatalf("transcript with malformed tool arguments cannot be encoded: %v", err)
	}
	checkpoints = append(checkpoints, encoded)
	var sawError bool
	for _, m := range result.Messages {
		for _, r := range m.ToolResults {
			if r.ToolCallID == "tc_bad" && r.IsError && strings.Contains(r.Content, "not valid JSON") {
				sawError = true
			}
		}
	}
	if !sawError || len(checkpoints) != 1 {
		t.Fatalf("malformed call was not answered with an error result: %s", encoded)
	}
}

func TestLoopCheckpointsRawMessagesBeforeCompacting(t *testing.T) {
	c := NewCompactor(0.5, "", nil)
	p := newCompactionTestProvider([][]provider.StreamEvent{simpleTextResponse("summary"), simpleTextResponse("answer")})
	loop := NewLoop(tools.NewRegistry(), newAllowAllToolGuard(), c, nil)
	cfg := buildRunConfig(p, nil)
	cfg.TokenBudget = 4000
	cfg.ModelName = "m"
	cfg.Messages = longConversation(20, strings.Repeat("evidence ", 60))
	var saved [][]internal.Message
	cfg.SaveCheckpoint = func(messages []internal.Message) error {
		saved = append(saved, append([]internal.Message(nil), messages...))
		return nil
	}
	result, err := loop.Run(context.Background(), cfg, "next question", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Compacted {
		t.Fatal("fixture did not compact")
	}
	if len(saved) == 0 {
		t.Fatal("no checkpoint before compaction")
	}
	first := saved[0]
	if len(first) != len(cfg.Messages)+1 || first[len(first)-1].Content != "next question" {
		t.Fatalf("checkpoint before compaction holds %d messages", len(first))
	}
	for _, m := range first {
		if IsCompactionSummary(m.Content) {
			t.Fatal("checkpoint was taken after compaction")
		}
	}
}

func TestSummaryRequestFitsCompactionModelWindow(t *testing.T) {
	// The session has a 400k window; summaries go to gpt-4o (128k).
	c := NewCompactor(0.8, "gpt-4o", nil)
	p := newCompactionTestProvider([][]provider.StreamEvent{simpleTextResponse("summary")})
	messages := longConversation(60, strings.Repeat("evidence ", 2500))
	if total := countMessageTokens(messages); total < 140_000 {
		t.Fatalf("fixture too small: %d", total)
	}
	report, err := c.CompactWithReport(context.Background(), p, "s", "r", messages, CompactOptions{ActiveModel: "gpt-5.4", ContextWindow: 400_000, Automatic: true})
	if err != nil {
		t.Fatal(err)
	}
	req := p.requests[0]
	if req.Model != "gpt-4o" {
		t.Fatalf("summary model = %s", req.Model)
	}
	if sent := estimateRequestInputTokens(req.Messages, req.Tools, req.SystemPrompt); sent+int64(req.MaxTokens) > 128_000 {
		t.Fatalf("summary request %d + %d does not fit the compaction model's 128k window", sent, req.MaxTokens)
	}
	if report.SummaryInputBudget > 128_000 {
		t.Fatalf("summary input budget %d sized for the session model", report.SummaryInputBudget)
	}
}

func TestTrimmedSummaryInputKeepsEarlierSummaryWhole(t *testing.T) {
	// A full-size earlier summary (~16k chars) among messages that must be
	// dropped to fit, and one still in the kept part.
	body := "START-OF-SUMMARY " + strings.Repeat("finding detail ", 1000) + "END-OF-SUMMARY"
	var messages []internal.Message
	messages = append(messages, internal.Message{ID: internal.NewMessageID(), Role: "user", Content: "[Compacted context — 9 messages summarized]\n" + body})
	messages = append(messages, longConversation(40, strings.Repeat("evidence ", 1500))...)
	fitted := fitSummaryInput(messages, nil, "", 40_000)
	var all strings.Builder
	for _, m := range fitted {
		all.WriteString(m.Content)
	}
	if !strings.Contains(all.String(), "START-OF-SUMMARY") || !strings.Contains(all.String(), "END-OF-SUMMARY") || strings.Contains(all.String(), "bytes cut]… finding") {
		t.Fatal("earlier summary was cut in the omitted-messages note")
	}

	kept := []internal.Message{messages[0], {ID: internal.NewMessageID(), Role: "user", Content: strings.Repeat("noise ", 30_000)}}
	fitted = fitSummaryInput(kept, nil, "", 20_000)
	if fitted[0].Content != messages[0].Content {
		t.Fatal("earlier summary in the kept part was trimmed")
	}
}
