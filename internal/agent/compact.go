package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	internal "github.com/Problem99-io/kodeblue/internal"
	"github.com/Problem99-io/kodeblue/internal/provider"
	"github.com/Problem99-io/kodeblue/internal/tokenestimate"
)

const (
	// frozenPrefixSize is the number of messages at the start of the
	// conversation that are never compacted.
	//
	// The system prompt is sent separately from the message list (see
	// Loop.Run / provider.Request.SystemPrompt), so message index 0 is the
	// first *user* message — i.e. the original task. We deliberately keep this
	// at 0 so the original task is NOT pinned in the active context forever:
	// it is summarized like any other middle message (the raw message is
	// always retained in the message store, just flagged compacted=1). The
	// system prompt itself remains the stable cache prefix regardless of this
	// value.
	frozenPrefixSize              = 0
	manualCompactionTriggerTokens = int64(25_000)

	// recentMessageCap bounds the raw recent tail kept by the configured
	// (active) compaction path to at most this many messages, in addition to
	// the token budget. The tail is the smaller of "fits in rawTailRatio of the
	// context window" and "the last recentMessageCap messages". Set to 0 to
	// disable the message-count cap and rely solely on the token budget.
	recentMessageCap = 10

	// summaryMaxOutputTokens is the output budget of the summary request,
	// capped to a quarter of very small windows.
	summaryMaxOutputTokens = int64(4096)

	// Fallback summary limits: each digest line keeps at most this much of a
	// message, tool call or tool result, and the whole digest at most
	// fallbackSummaryWindowShare of the window (most recent lines win).
	fallbackTextChars          = 400
	fallbackToolArgsChars      = 300
	fallbackToolResultChars    = 600
	fallbackSummaryWindowShare = 0.10

	// trimmedMessageChars is how much of each long message body or tool result
	// the summary request keeps when the full conversation does not fit.
	trimmedMessageChars = 4000

	compactedContextPrefix = "[Compacted context"
	defaultRawTailRatio    = 0.25

	// compactionUserPrompt is appended as a synthetic user turn at the end
	// of the live conversation when compaction is triggered. The model
	// receives the entire conversation so far (prefix + middle + recent)
	// and is asked to produce the handoff summary in-context. This keeps
	// the request prefix identical to the live agent's last request, so
	// provider-side prompt caching continues to hit.
	compactionUserPrompt = `The conversation so far is approaching the context window. Produce a compact, structured handoff summary that another assistant can use to continue this exact task without re-reading the discarded turns.

Output ONLY the summary using this exact structure:

Current Task:
- what we are trying to accomplish

Current Status:
- what is happening now
- what has already been completed

Key Findings:
- important discoveries from code, logs, tests, searches, or commands

Related Files:
- relevant files and why they matter

Code Changes:
- what changed in code or config
- what behavior those changes affect

Decisions and Rationale:
- decisions made and why
- rejected or deferred alternatives if relevant

Evidence:
- important command outputs, test results, logs, or observed behavior

Open Questions:
- unresolved uncertainty or assumptions
- if none, write: - none

Remaining Tasks:
- unfinished task 1
- unfinished task 2

If there are no remaining tasks, write:
- none

Be specific. Include file paths, function names, test names, error messages, and concrete evidence. Do not output private chain-of-thought. Do not preface with greetings or restate this instruction.`
)

// Compactor handles context window compaction using a prefix-stable strategy.
//
// Layout after compaction:
//
//	[frozen prefix (first N msgs)] + [LLM summary msg] + [raw recent tail within token budget]
//
// The frozen prefix is never modified, so provider-side prompt caching
// (OpenAI prefix caching, Anthropic cache_control) continues to hit across
// compaction boundaries.
type Compactor struct {
	thresholdRatio float64 // e.g. 0.90 = compact when 90% of budget used
	summaryModel   string
	rawTailRatio   float64
	eventSink      EventSink
}

type CompactOptions struct {
	ActiveModel        string
	ContextWindow      int64
	CurrentInputTokens int64
	// Automatic marks a compaction the run loop triggered after a tool turn;
	// it is reported in the compaction event.
	Automatic bool
	// Manual marks an explicit compaction request (POST /compact). Only these
	// plan the raw tail against manualCompactionTriggerTokens instead of the
	// context window, so a conversation far below the automatic threshold
	// can still be compacted on request.
	Manual       bool
	SystemPrompt string
	Tools        []internal.ToolDefinition
	// PromptCacheKey mirrors the live agent's prompt cache key (typically
	// the session ID). Compaction sends the full conversation through the
	// same provider+model with this key so the cached prefix hits.
	PromptCacheKey string
}

type CompactionReport struct {
	Messages            []internal.Message
	Automatic           bool
	CompactedMessages   int
	RemainingMessages   int
	FrozenPrefix        int
	RecentMessages      int
	RawTailBudget       int64
	RawTailTokens       int64
	UsedLLMSummary      bool
	UsedFallbackSummary bool
	SummaryModel        string
	SummaryInputBudget  int64
	SummaryInputTokens  int64
	SummaryUsage        *internal.MessageUsage
	SummaryContent      string
}

// NewCompactor returns a compactor that triggers automatic compaction once
// the context reaches thresholdRatio of the window (out-of-range values fall
// back to 0.80). summaryModel, when set, overrides the model used to write
// summaries (the compaction_model setting); empty uses the session's active
// model, which shares the live conversation's prompt cache. sink receives
// compaction events and may be nil.
func NewCompactor(thresholdRatio float64, summaryModel string, sink EventSink) *Compactor {
	if thresholdRatio <= 0 || thresholdRatio > 1 {
		thresholdRatio = 0.80
	}
	return &Compactor{
		thresholdRatio: thresholdRatio,
		summaryModel:   strings.TrimSpace(summaryModel),
		rawTailRatio:   defaultRawTailRatio,
		eventSink:      sink,
	}
}

// NeedsCompaction checks if context has crossed the threshold.
func (c *Compactor) NeedsCompaction(tokensUsed, contextWindow int64) bool {
	if tokensUsed <= 0 || contextWindow <= 0 {
		return false
	}
	return float64(tokensUsed)/float64(contextWindow) >= c.thresholdRatio
}

// Compact performs prefix-stable compaction. It keeps the frozen prefix and
// raw recent tail intact and uses the provider LLM to summarize the middle
// portion of the conversation.
func (c *Compactor) Compact(ctx context.Context, p provider.Provider, sessionID internal.SessionID, runID internal.RunID, messages []internal.Message, opts CompactOptions) ([]internal.Message, error) {
	report, err := c.CompactWithReport(ctx, p, sessionID, runID, messages, opts)
	if err != nil {
		return nil, err
	}
	return report.Messages, nil
}

// CompactWithReport is Compact plus the details of what was compacted.
func (c *Compactor) CompactWithReport(ctx context.Context, p provider.Provider, sessionID internal.SessionID, runID internal.RunID, messages []internal.Message, opts CompactOptions) (CompactionReport, error) {
	if len(messages) <= frozenPrefixSize+1 {
		return CompactionReport{Messages: messages}, nil
	}
	return c.compactConfiguredWindow(ctx, p, sessionID, runID, messages, opts)
}

func (c *Compactor) compactConfiguredWindow(ctx context.Context, p provider.Provider, sessionID internal.SessionID, runID internal.RunID, messages []internal.Message, options CompactOptions) (CompactionReport, error) {

	// Partition: [frozen | middle | recent], but only cut at boundaries that do
	// not separate structured tool-call messages from their tool results.
	prefixEnd := adjustCompactionBoundaryForward(messages, frozenPrefixSize)
	// Never let a leading system message fall into the compactable middle.
	if sys := leadingSystemPrefix(messages); sys > prefixEnd {
		prefixEnd = adjustCompactionBoundaryForward(messages, sys)
	}
	if prefixEnd >= len(messages)-1 {
		return CompactionReport{Messages: messages}, nil
	}

	effectiveWindow := options.ContextWindow
	if effectiveWindow <= 0 {
		effectiveWindow = provider.ResolveContextWindow(ctx, p, options.ActiveModel)
	}
	if effectiveWindow <= 0 {
		effectiveWindow = provider.DefaultContextWindow
	}
	totalTokens := options.CurrentInputTokens
	if totalTokens <= 0 {
		totalTokens = countMessageTokens(messages)
	}
	// Plan the tail against a smaller window only for an explicit request;
	// automatic compaction keeps rawTailRatio of the real window.
	planningWindow := effectiveWindow
	if options.Manual && totalTokens > manualCompactionTriggerTokens && planningWindow > manualCompactionTriggerTokens {
		planningWindow = manualCompactionTriggerTokens
	}

	rawTailBudget := c.rawTailTokenBudget(planningWindow)
	recentStart, rawTailTokens := c.selectRecentTailStart(messages, prefixEnd, rawTailBudget)
	if recentStart <= prefixEnd {
		return CompactionReport{Messages: messages}, nil
	}

	prefix := messages[:prefixEnd]
	recent := messages[recentStart:]
	middle := messages[prefixEnd:recentStart]

	// New flow: send the full live conversation (prefix + middle + recent)
	// through the active model with a synthetic user message asking for the
	// handoff summary. This keeps the request prefix byte-identical to the
	// live agent's previous request, so the provider's prompt cache hits.
	usedLLMSummary := false
	usedFallbackSummary := false
	summaryModel := c.summaryModelName(options.ActiveModel)
	// The summary request goes to summaryModel, so it must fit that model's
	// window: a compaction_model smaller than the session's model would
	// otherwise be sent a request sized for the larger one.
	summaryWindow := effectiveWindow
	if summaryModel != options.ActiveModel {
		if window := provider.ResolveContextWindow(ctx, p, summaryModel); window > 0 {
			summaryWindow = window
		}
	}
	maxOutput := summaryMaxOutputTokens
	if quarter := summaryWindow / 4; quarter < maxOutput {
		maxOutput = max(quarter, 1)
	}
	// The request (input plus its output budget) must fit the window, with a
	// tenth of it as margin for tokenizer differences. Compaction runs when
	// the conversation is already near the limit, so the full live context
	// plus the prompt and output budget is the request most likely to
	// overflow.
	summaryInputBudget := summaryWindow - maxOutput - summaryWindow/10
	summaryMessages := fitSummaryInput(messages, options.Tools, options.SystemPrompt, summaryInputBudget)
	summaryInputTokens := estimateRequestInputTokens(summaryMessages, options.Tools, options.SystemPrompt) +
		estimateMessageTokens(compactionPromptMessage())

	var summaryUsage *internal.MessageUsage
	summaryContent, streamUsage, summaryErr := c.summarizeViaLiveContext(
		ctx,
		p,
		summaryModel,
		options.SystemPrompt,
		options.Tools,
		options.PromptCacheKey,
		summaryMessages,
		maxOutput,
	)
	switch {
	case ctx.Err() != nil:
		// Stopped while the summary was streaming: whatever arrived is a
		// truncated summary. Keep the uncompacted history.
		return CompactionReport{}, fmt.Errorf("compaction summary: %w", ctx.Err())
	case summaryErr == nil:
		usedLLMSummary = true
		summaryUsage = streamUsage
	default:
		summaryContent = c.fallbackSummary(middle, effectiveWindow)
		usedFallbackSummary = true
	}

	if strings.TrimSpace(summaryContent) == "" {
		return CompactionReport{Messages: messages}, nil
	}

	combinedSummary := strings.TrimSpace(summaryContent)

	summaryMsg := internal.Message{
		Internal: internal.HasInternalContent(messages),
		ID:       internal.NewMessageID(),
		Role:     "user",
		Content:  fmt.Sprintf("[Compacted context — %d messages summarized]\n%s", len(middle), combinedSummary),
		// Transcript order comes from the message's position in the active
		// set (messages.position), not from this timestamp.
		CreatedAt: time.Now(),
	}

	result := make([]internal.Message, 0, len(prefix)+1+len(recent))
	result = append(result, prefix...)
	result = append(result, summaryMsg)
	result = append(result, recent...)

	report := CompactionReport{
		Messages:            result,
		Automatic:           options.Automatic,
		CompactedMessages:   len(middle),
		RemainingMessages:   len(result),
		FrozenPrefix:        frozenPrefixSize,
		RecentMessages:      len(recent),
		RawTailBudget:       rawTailBudget,
		RawTailTokens:       rawTailTokens,
		UsedLLMSummary:      usedLLMSummary,
		UsedFallbackSummary: usedFallbackSummary,
		SummaryModel:        summaryModel,
		SummaryInputBudget:  summaryInputBudget,
		SummaryInputTokens:  summaryInputTokens,
		SummaryUsage:        summaryUsage,
		SummaryContent:      combinedSummary,
	}

	if c.eventSink != nil {
		data, _ := json.Marshal(map[string]any{
			"automatic":            options.Automatic,
			"compacted_messages":   len(middle),
			"remaining_messages":   len(result),
			"frozen_prefix":        frozenPrefixSize,
			"recent_messages":      len(recent),
			"raw_tail_budget":      rawTailBudget,
			"raw_tail_tokens":      rawTailTokens,
			"used_llm_summary":     usedLLMSummary,
			"used_fallback":        usedFallbackSummary,
			"summary_model":        summaryModel,
			"summary_input_budget": summaryInputBudget,
			"summary_input_tokens": summaryInputTokens,
			"summary_content":      combinedSummary,
			"internal_summary":     summaryMsg.Internal,
			"summary_usage":        summaryUsage,
		})
		c.eventSink(internal.Event{
			Type:      internal.EventCompactionPerformed,
			Timestamp: time.Now(),
			SessionID: sessionID,
			RunID:     runID,
			Payload:   json.RawMessage(data),
		})
	}

	return report, nil
}

func (c *Compactor) rawTailTokenBudget(contextWindow int64) int64 {
	if contextWindow <= 0 {
		return 1
	}
	budget := int64(float64(contextWindow) * c.rawTailRatio)
	if budget < 1 {
		return 1
	}
	return budget
}

func (c *Compactor) summaryModelName(activeModel string) string {
	if c.summaryModel != "" {
		return c.summaryModel
	}
	return activeModel
}

// leadingSystemPrefix returns the number of consecutive system-role messages at
// the head of the slice. The system prompt is normally sent separately from the
// message list (see Loop.Run / provider.Request.SystemPrompt) and never appears
// here, but this guards against any caller that places system messages at the
// head: such messages must always be pinned into the frozen prefix so they are
// sent verbatim and never summarized away.
func leadingSystemPrefix(messages []internal.Message) int {
	n := 0
	for n < len(messages) && messages[n].Role == "system" {
		n++
	}
	return n
}

func adjustCompactionBoundaryForward(messages []internal.Message, idx int) int {
	if idx < 0 {
		idx = 0
	}
	for idx < len(messages) && isUnsafeCompactionBoundary(messages, idx) {
		idx++
	}
	return idx
}

func isUnsafeCompactionBoundary(messages []internal.Message, idx int) bool {
	if idx <= 0 || idx >= len(messages) {
		return false
	}
	if len(messages[idx].ToolResults) > 0 {
		return true
	}
	if len(messages[idx-1].ToolCalls) > 0 {
		return true
	}
	return false
}

func (c *Compactor) selectRecentTailStart(messages []internal.Message, prefixEnd int, budget int64) (int, int64) {
	candidateStarts := coherentTailStarts(messages, prefixEnd)
	if len(candidateStarts) == 0 {
		return len(messages), 0
	}

	selectedStart := candidateStarts[len(candidateStarts)-1]
	selectedTokens := countMessageTokens(messages[selectedStart:])

	for idx := len(candidateStarts) - 1; idx >= 0; idx-- {
		start := candidateStarts[idx]
		tokens := countMessageTokens(messages[start:])
		if tokens > budget {
			break
		}
		selectedStart = start
		selectedTokens = tokens
	}

	// Apply the recent-message cap only when the token budget already forced a
	// cut (selectedStart could not reach the earliest candidate). This trims an
	// already-shrinking tail down to at most recentMessageCap messages, but
	// never manufactures a compaction for a conversation that fully fits the
	// budget — in that case there is nothing useful to summarize.
	if recentMessageCap > 0 &&
		selectedStart > candidateStarts[0] &&
		len(messages)-selectedStart > recentMessageCap {
		for idx := len(candidateStarts) - 1; idx >= 0; idx-- {
			start := candidateStarts[idx]
			if len(messages)-start > recentMessageCap {
				break
			}
			selectedStart = start
		}
		selectedTokens = countMessageTokens(messages[selectedStart:])
	}

	return selectedStart, selectedTokens
}

func coherentTailStarts(messages []internal.Message, prefixEnd int) []int {
	starts := make([]int, 0, len(messages)-prefixEnd)
	for idx := prefixEnd; idx < len(messages); idx++ {
		if !isUnsafeCompactionBoundary(messages, idx) {
			starts = append(starts, idx)
		}
	}
	return starts
}

// compactionSummaryIndices returns the positions of compaction summaries in a
// request's messages. They stay byte-identical until the next compaction, so
// they are good prompt-cache anchors.
func compactionSummaryIndices(messages []internal.Message) []int {
	var indices []int
	for i, message := range messages {
		if IsCompactionSummary(message.Content) {
			indices = append(indices, i)
		}
	}
	return indices
}

// IsCompactionSummary reports whether a message's content is a compaction
// summary produced by the compactor (it starts with compactedContextPrefix).
// Exposed so persistence layers can detect that a run compacted structurally,
// instead of relying solely on the RunResult.Compacted flag.
func IsCompactionSummary(content string) bool {
	_, ok := compactedSummaryBody(content)
	return ok
}

func compactedSummaryBody(content string) (string, bool) {
	trimmed := strings.TrimSpace(content)
	if !strings.HasPrefix(trimmed, compactedContextPrefix) {
		return "", false
	}
	parts := strings.SplitN(trimmed, "\n", 2)
	if len(parts) == 1 {
		return "", true
	}
	return strings.TrimSpace(parts[1]), true
}

// compactionPromptMessage is the synthetic user turn that asks for the summary.
func compactionPromptMessage() internal.Message {
	return internal.Message{ID: internal.NewMessageID(), Role: "user", Content: compactionUserPrompt, CreatedAt: time.Now()}
}

// countMessageTokens is the local token estimate of a message list alone.
func countMessageTokens(messages []internal.Message) int64 {
	return estimateRequestInputTokens(messages, nil, "")
}

// fitSummaryInput returns the conversation to send with the summary prompt so
// that the request fits budget tokens.
//
// When the full live context fits it is sent unchanged, which keeps the
// request prefix identical to the live chat's and the prompt cache warm. When
// it does not, long message bodies and tool results are cut down first
// (oldest first); if that is still too much, the oldest exchanges are
// replaced by one note carrying a short digest of them. Cuts only fall on
// boundaries that keep tool calls next to their results.
func fitSummaryInput(messages []internal.Message, tools []internal.ToolDefinition, systemPrompt string, budget int64) []internal.Message {
	fixed := estimateRequestInputTokens(nil, tools, systemPrompt) + estimateMessageTokens(compactionPromptMessage())
	// Per-message estimates, kept current as messages are trimmed, so each
	// step costs one message's tokenization rather than the conversation's.
	tokens := make([]int64, len(messages))
	var total int64
	for i := range messages {
		tokens[i] = estimateMessageTokens(messages[i])
		total += tokens[i]
	}
	if fixed+total <= budget {
		return messages
	}

	trimmed := make([]internal.Message, len(messages))
	copy(trimmed, messages)
	for i := range trimmed {
		trimmed[i] = trimMessageForSummary(trimmed[i])
		after := estimateMessageTokens(trimmed[i])
		total += after - tokens[i]
		tokens[i] = after
		if fixed+total <= budget {
			return trimmed
		}
	}

	// Drop the oldest exchanges. Each candidate start keeps tool calls and
	// results together; leading system messages are always kept.
	prefixEnd := leadingSystemPrefix(trimmed)
	starts := coherentTailStarts(trimmed, prefixEnd)
	digestBudget := max(budget/8, 64)
	// An earlier summary is kept whole up to a quarter of the budget (about
	// four characters a token); a normal one, at most summaryMaxOutputTokens,
	// always fits a real window.
	summaryChars := int(max(budget/4, 1000) * 4)
	var pinned int64
	for i := 0; i < prefixEnd; i++ {
		pinned += tokens[i]
	}
	kept := total - pinned
	next := prefixEnd
	for _, start := range starts {
		for ; next < start; next++ {
			kept -= tokens[next]
		}
		if start == prefixEnd {
			continue
		}
		note := internal.Message{
			ID:        internal.NewMessageID(),
			Role:      "user",
			Content:   omittedMessagesNote(messages[prefixEnd:start], digestBudget, summaryChars),
			CreatedAt: time.Now(),
		}
		if fixed+pinned+estimateMessageTokens(note)+kept > budget && start != starts[len(starts)-1] {
			continue
		}
		candidate := make([]internal.Message, 0, prefixEnd+1+len(trimmed)-start)
		candidate = append(candidate, trimmed[:prefixEnd]...)
		candidate = append(candidate, note)
		return append(candidate, trimmed[start:]...)
	}
	return trimmed
}

// omittedMessagesNote stands in for messages dropped from the summary request.
// An earlier compaction summary among them is the condensed history before
// them, so it is carried whole (up to summaryChars, beyond which its head and
// tail are kept); the rest is digested.
func omittedMessagesNote(dropped []internal.Message, digestBudget int64, summaryChars int) string {
	var b strings.Builder
	var rest []internal.Message
	for _, m := range dropped {
		if body, ok := compactedSummaryBody(m.Content); ok {
			b.WriteString("Earlier summary:\n")
			b.WriteString(truncateMiddle(body, summaryChars))
			b.WriteString("\n\n")
			continue
		}
		rest = append(rest, m)
	}
	header := fmt.Sprintf("[%d earlier messages omitted to fit the context window.]\n", len(dropped))
	if len(rest) > 0 {
		b.WriteString("Digest of the other omitted messages:\n")
		b.WriteString(digestMessages(rest, digestBudget))
	}
	return header + strings.TrimSpace(b.String())
}

// trimMessageForSummary shortens a message's long text and tool results for
// the summary request. The stored message is not changed.
func trimMessageForSummary(m internal.Message) internal.Message {
	// An earlier summary is the condensed history; it is not cut here.
	if !IsCompactionSummary(m.Content) {
		m.Content = truncateMiddle(m.Content, trimmedMessageChars)
	}
	m.ReasoningContent = ""
	m.ReasoningDetails = nil
	if len(m.ToolResults) > 0 {
		results := make([]internal.ToolResult, len(m.ToolResults))
		for i, r := range m.ToolResults {
			r.Content = truncateMiddle(r.Content, trimmedMessageChars)
			r.Metadata = nil
			results[i] = r
		}
		m.ToolResults = results
	}
	if len(m.Attachments) > 0 {
		attachments := make([]internal.Attachment, len(m.Attachments))
		for i, a := range m.Attachments {
			a.Data = ""
			attachments[i] = a
		}
		m.Attachments = attachments
	}
	return m
}

func (c *Compactor) summarizeViaLiveContext(
	ctx context.Context,
	p provider.Provider,
	model, systemPrompt string,
	tools []internal.ToolDefinition,
	cacheKey string,
	messages []internal.Message,
	maxOutputTokens int64,
) (string, *internal.MessageUsage, error) {
	if strings.TrimSpace(model) == "" {
		return "", nil, fmt.Errorf("compaction summary: missing active model")
	}

	syntheticMessages := make([]internal.Message, 0, len(messages)+1)
	syntheticMessages = append(syntheticMessages, messages...)
	syntheticMessages = append(syntheticMessages, compactionPromptMessage())

	req := &provider.Request{
		Model:          model,
		Messages:       syntheticMessages,
		Tools:          tools,
		SystemPrompt:   systemPrompt,
		PromptCacheKey: cacheKey,
		MaxTokens:      int(maxOutputTokens),
		Temperature:    0.2,
	}

	ch, err := p.Stream(ctx, req)
	if err != nil {
		return "", nil, fmt.Errorf("compaction summary stream: %w", err)
	}

	var buf strings.Builder
	var finalUsage *internal.MessageUsage
	done := false
	for event := range ch {
		switch event.Type {
		case provider.EventToken:
			// Reasoning is the model thinking, not part of the summary.
			if event.Channel != provider.ChannelReasoning {
				buf.WriteString(event.Content)
			}
		case provider.EventDone:
			done = true
			if event.Usage != nil {
				u := messageUsageFromProviderUsage(*event.Usage)
				finalUsage = u
			}
		case provider.EventError:
			if event.Error != nil {
				return "", nil, event.Error
			}
		}
	}
	// A stream that ends without its done event was cut off — by a stop, a
	// dropped connection or a provider failure — and its text is a truncated
	// summary that must not replace the history.
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	if !done {
		return "", nil, fmt.Errorf("compaction summary stream ended before completion")
	}

	summary := strings.TrimSpace(buf.String())
	if summary == "" {
		return "", nil, fmt.Errorf("empty summary returned")
	}
	return summary, finalUsage, nil
}

func estimateRequestInputTokens(messages []internal.Message, toolDefs []internal.ToolDefinition, systemPrompt string) int64 {
	var total int64
	if strings.TrimSpace(systemPrompt) != "" {
		total += estimateTextTokens(systemPrompt)
	}
	for _, toolDef := range toolDefs {
		total += estimateTextTokens(toolDef.Description)
		total += estimateJSONTokens(toolDef.Parameters)
		total += estimateTextTokens(string(toolDef.Name))
	}
	for _, message := range messages {
		total += estimateMessageTokens(message)
	}
	if total < 1 {
		return 1
	}
	return total
}

// estimateAttachmentPayloadTokens approximates what an attachment costs the
// model, which is nothing like what its base64 costs as text.
//
// Vision models bill an image by its pixel area (roughly width*height/750), so
// a 300 KB screenshot is on the order of a thousand tokens — while tokenizing
// its base64 as prose would score it near a hundred thousand and trip
// compaction on the very turn the image arrives. Images are therefore charged a
// flat per-image estimate; other files (which the relay parses into text
// upstream) are charged against their decoded size.
const (
	imageAttachmentTokenEstimate = 1600
	// Base64 inflates by 4/3, and a parsed document yields far less text than
	// its raw bytes, so decoded bytes are discounted before tokenizing.
	documentAttachmentBytesPerToken = 12
)

func estimateAttachmentPayloadTokens(attachment internal.Attachment) int64 {
	if attachment.Data == "" {
		return 0
	}
	if strings.HasPrefix(attachment.MediaType, "image/") {
		return imageAttachmentTokenEstimate
	}
	decodedBytes := int64(len(attachment.Data)) * 3 / 4
	tokens := decodedBytes / documentAttachmentBytesPerToken
	if tokens < 1 {
		return 1
	}
	return tokens
}

func estimateMessageTokens(message internal.Message) int64 {
	var total int64
	total += estimateTextTokens(message.Role)
	total += estimateTextTokens(message.Content)
	total += estimateTextTokens(message.ReasoningContent)
	for _, attachment := range message.Attachments {
		total += estimateTextTokens(attachment.MediaType)
		total += estimateTextTokens(attachment.FileName)
		total += estimateTextTokens(attachment.URL)
		total += estimateAttachmentPayloadTokens(attachment)
	}
	for _, toolCall := range message.ToolCalls {
		total += estimateTextTokens(string(toolCall.Name))
		total += estimateJSONTokens(toolCall.Arguments)
	}
	for _, toolResult := range message.ToolResults {
		total += estimateTextTokens(toolResult.ToolCallID)
		total += estimateTextTokens(toolResult.Content)
		if len(toolResult.Metadata) > 0 {
			metadataJSON, _ := json.Marshal(toolResult.Metadata)
			total += estimateJSONTokens(metadataJSON)
		}
	}
	return total
}

func estimateTextTokens(text string) int64 {
	return tokenestimate.EstimateText(text)
}

func estimateJSONTokens(raw json.RawMessage) int64 {
	if len(raw) == 0 {
		return 0
	}
	return estimateTextTokens(string(raw))
}

// fallbackSummary is the summary used when the model could not write one: a
// digest of the replaced messages that keeps what the model said, which tools
// it called with what arguments, and the head and tail of what each returned —
// the evidence a blue-team investigation must not lose. It is bounded to a
// tenth of the context window, keeping the most recent lines.
func (c *Compactor) fallbackSummary(middle []internal.Message, contextWindow int64) string {
	budget := int64(float64(contextWindow) * fallbackSummaryWindowShare)
	return digestMessages(middle, max(budget, 256))
}

// digestMessages renders messages as one line per message, tool call and tool
// result, dropping the oldest lines once the digest exceeds budget tokens.
func digestMessages(messages []internal.Message, budget int64) string {
	toolNames := map[string]string{}
	var lines []string
	for _, m := range messages {
		switch m.Role {
		case "user":
			if m.Content != "" {
				lines = append(lines, "User: "+truncateMiddle(oneLine(m.Content), fallbackTextChars))
			}
		case "assistant":
			if m.Content != "" {
				lines = append(lines, "Assistant: "+truncateMiddle(oneLine(m.Content), fallbackTextChars))
			}
		}
		for _, tc := range m.ToolCalls {
			toolNames[tc.ID] = string(tc.Name)
			lines = append(lines, fmt.Sprintf("Tool call %s(%s)", tc.Name, truncateMiddle(oneLine(string(tc.Arguments)), fallbackToolArgsChars)))
		}
		for _, tr := range m.ToolResults {
			label := "Tool result"
			if name := toolNames[tr.ToolCallID]; name != "" {
				label += " " + name
			}
			if tr.IsError {
				label += " (error)"
			}
			lines = append(lines, fmt.Sprintf("%s: %s", label, truncateMiddle(oneLine(tr.Content), fallbackToolResultChars)))
		}
	}

	// Keep the newest lines that fit.
	var used int64
	first := len(lines)
	for first > 0 {
		cost := estimateTextTokens(lines[first-1]) + 1
		if used+cost > budget {
			break
		}
		used += cost
		first--
	}
	kept := lines[first:]
	if first > 0 {
		kept = append([]string{fmt.Sprintf("(%d earlier entries omitted)", first)}, kept...)
	}
	return strings.Join(kept, "\n")
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// truncateMiddle keeps the head and tail of s within maxLen bytes (plus a
// marker), on UTF-8 boundaries: the end of a command's output often holds the
// part that matters.
func truncateMiddle(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	head := maxLen * 2 / 3
	tail := maxLen - head
	for head > 0 && !utf8.RuneStart(s[head]) {
		head--
	}
	start := len(s) - tail
	for start < len(s) && !utf8.RuneStart(s[start]) {
		start++
	}
	return s[:head] + fmt.Sprintf(" …[%d bytes cut]… ", start-head) + s[start:]
}
