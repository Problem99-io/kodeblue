package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	internal "github.com/Problem99-io/kodeblue/internal"
	"github.com/Problem99-io/kodeblue/internal/policy"
	"github.com/Problem99-io/kodeblue/internal/provider"
	"github.com/Problem99-io/kodeblue/internal/tools"
)

// ErrAborted is returned by Run when the run is cancelled via Abort.
var ErrAborted = fmt.Errorf("run aborted")

// ErrInterrupted is returned by Run when a caller steers a run via Interrupt.
// It is deliberately distinct from ErrAborted: interruption preserves a safe
// transcript boundary for immediate continuation, whereas Abort is a stop.
var ErrInterrupted = fmt.Errorf("run interrupted")

var promptNow = time.Now

func messageUsageFromProviderUsage(usage provider.Usage) *internal.MessageUsage {
	if usage.InputTokens == 0 && usage.OutputTokens == 0 && usage.CacheCreationInputTokens == 0 && usage.CacheReadInputTokens == 0 && usage.Cost == nil {
		return nil
	}
	messageUsage := &internal.MessageUsage{
		InputTokens:              usage.InputTokens,
		OutputTokens:             usage.OutputTokens,
		CacheCreationInputTokens: usage.CacheCreationInputTokens,
		CacheReadInputTokens:     usage.CacheReadInputTokens,
	}
	if usage.Cost != nil {
		messageUsage.Cost = &internal.MessageCost{
			RequestID:            usage.Cost.RequestID,
			InputCostUSD:         usage.Cost.InputCostUSD,
			OutputCostUSD:        usage.Cost.OutputCostUSD,
			CacheCreationCostUSD: usage.Cost.CacheCreationCostUSD,
			CacheReadCostUSD:     usage.Cost.CacheReadCostUSD,
			RawTotalUSD:          usage.Cost.RawTotalUSD,
			BilledTotalUSD:       usage.Cost.BilledTotalUSD,
		}
	}
	return messageUsage
}

func messageUsageWithContext(usage provider.Usage, contextWindow int64) *internal.MessageUsage {
	messageUsage := messageUsageFromProviderUsage(usage)
	if messageUsage == nil {
		return nil
	}
	if contextWindow > 0 {
		messageUsage.ContextWindow = contextWindow
		messageUsage.ContextUtilizationPercent = contextUtilizationPercent(effectiveContextTokens(usage), contextWindow)
	}
	return messageUsage
}

func addUsageCost(left, right *provider.CostBreakdown) *provider.CostBreakdown {
	if left == nil {
		if right == nil {
			return nil
		}
		copy := *right
		return &copy
	}
	if right == nil {
		return left
	}
	left.InputCostUSD += right.InputCostUSD
	left.OutputCostUSD += right.OutputCostUSD
	left.CacheCreationCostUSD += right.CacheCreationCostUSD
	left.CacheReadCostUSD += right.CacheReadCostUSD
	left.RawTotalUSD += right.RawTotalUSD
	left.BilledTotalUSD += right.BilledTotalUSD
	return left
}

// EventSink receives events from the agent loop
type EventSink func(event internal.Event)

// ContinuationGate is called when a run reaches a continuation checkpoint —
// RunConfig.MaxIterations tool-calling turns without the model finishing. It
// blocks until the user decides whether the run should keep going.
//
// The checkpoint sits between a completed tool turn and the next request: the
// tool results are already in the transcript but have not been sent to the
// model yet. Answering "yes" simply releases them, so the model resumes exactly
// where it left off with nothing artificial ("continue", "proceed") injected
// into the conversation.
type ContinuationGate func(ctx context.Context, req ContinuationRequest) (ContinuationDecision, error)

// ContinuationRequest describes the run asking to keep going.
type ContinuationRequest struct {
	SessionID  internal.SessionID
	RunID      internal.RunID
	Iterations int // tool-calling turns completed so far in this run
	ToolCalls  int // tool calls executed so far in this run
}

// ContinuationDecision is the user's answer to a continuation checkpoint.
type ContinuationDecision struct {
	// Continue reports whether the run may proceed. False ends the run the same
	// way a manual stop does, with the pending tool results left in place.
	Continue bool
	// Guidance is optional free-text steering typed instead of a plain yes. It is
	// appended as a user message alongside the held tool results, so the model
	// sees the correction on its very next turn.
	Guidance string
}

// AvailableSkill describes a skill the agent can load via the skill tool.
type AvailableSkill struct {
	Name        string
	Description string
}

type AvailableDefinition struct {
	ID        string
	Title     string
	Snippet   string
	Content   string
	Important bool
	Scope     []string
	Notes     []AvailableDefinitionItem
	Rules     []AvailableDefinitionItem
}

type AvailableDefinitionItem struct {
	ID      string
	Title   string
	Content string
}

// RunConfig configures a single agent run.
type RunConfig struct {
	// SaveCheckpoint persists the full active transcript before a continuation question is exposed.
	SaveCheckpoint       func([]internal.Message) error
	SessionID            internal.SessionID
	RunID                internal.RunID
	Provider             provider.Provider
	Messages             []internal.Message // Existing conversation context
	BaseDirectory        string             // Effective base directory for this run
	SystemPrompt         string
	Instructions         []string
	Tools                []internal.ToolDefinition
	AvailableSkills      []AvailableSkill      // Skills the agent can load via the skill tool
	AvailableDefinitions []AvailableDefinition // Persisted definitions loaded into the prompt
	// MaxIterations is the number of tool-calling turns the run may take before
	// it stops and asks the user whether to keep going. It is a checkpoint, not
	// a cap: answering yes buys another MaxIterations turns. 0 — or a run with
	// no ContinuationGate installed — never interrupts the run.
	MaxIterations int
	// MaxOutputTokens caps a normal model response. 0 uses the historical
	// default of 32768; -1 omits the engine's cap and leaves the boundary to the
	// provider. Compaction summary request limits remain independent.
	MaxOutputTokens int
	// TokenBudget optionally caps the effective context window below the
	// model's real one. Production leaves it 0 — the context window is
	// dictated by the provider (ResolveContextWindow).
	// Only tests set it, to force compaction with small fake windows.
	TokenBudget     int64
	ModelName       string // Model identifier used for context window lookup
	ReasoningEffort string // OpenAI reasoning_effort for this run; empty = provider/model default
	// UserMessageID and UserMessageCreatedAt let the API durably persist the
	// incoming turn before the asynchronous loop begins. When empty, the loop
	// generates them on entry.
	UserMessageID        string
	UserMessageCreatedAt time.Time
	// InputSource is direct_message for interactive turns. Other sources do not
	// receive the internal suspicious-input reporting tool.
	InputSource string
	QuestionID  string
}

// Loop is the main agent orchestrator
type Loop struct {
	toolRegistry     *tools.Registry
	toolGuard        *policy.ToolGuard
	compactor        *Compactor
	eventSink        EventSink
	continuationGate ContinuationGate
	mu               sync.Mutex
	activeRuns       map[internal.RunID]*runControl
	// pendingRuns holds runs that have been dispatched but have not yet entered
	// Run; abortedBeforeStart holds those a user stopped while still pending.
	// Together they close the window where an abort would otherwise be dropped.
	pendingRuns            map[internal.RunID]bool
	abortedBeforeStart     map[internal.RunID]bool
	interruptedBeforeStart map[internal.RunID]bool
}

type runPhase uint8

const (
	runPhaseIdle runPhase = iota
	runPhaseProvider
	runPhaseTool
)

// runControl separates a hard abort (which cancels the whole run context)
// from a steer interrupt. An interrupt cancels only an in-flight provider
// stream; while a tool is active it is recorded and observed at the next safe
// post-tool/pre-provider boundary.
type runControl struct {
	cancel       context.CancelFunc
	cancelStream context.CancelFunc
	phase        runPhase
	interrupted  bool
}

// SetContinuationGate installs the checkpoint asked when a run passes
// RunConfig.MaxIterations tool-calling turns. Leave it nil (the default) for
// runs that have nobody to ask, such as tests; those runs are never
// interrupted.
func (l *Loop) SetContinuationGate(gate ContinuationGate) {
	l.continuationGate = gate
}

func NewLoop(
	toolRegistry *tools.Registry,
	toolGuard *policy.ToolGuard,
	compactor *Compactor,
	eventSink EventSink,
) *Loop {
	return &Loop{
		toolRegistry: toolRegistry,
		toolGuard:    toolGuard,
		compactor:    compactor,
		eventSink:    eventSink,
		activeRuns:   make(map[internal.RunID]*runControl),

		pendingRuns:            make(map[internal.RunID]bool),
		abortedBeforeStart:     make(map[internal.RunID]bool),
		interruptedBeforeStart: make(map[internal.RunID]bool),
	}
}

// RunResult holds the output of an agent Run.
type RunResult struct {
	Messages  []internal.Message
	Compacted bool // true if context compaction was performed during this run
	Usage     provider.Usage
}

// Run executes the agent loop for a user message. Returns the accumulated messages.
func (l *Loop) Run(ctx context.Context, cfg RunConfig, userMessage string, attachments []internal.Attachment) (runResult RunResult, runErr error) {
	s := &runState{cfg: cfg}
	defer func() {
		if value := recover(); value != nil {
			runErr = errors.New("agent run panicked")
			runResult = s.result()
			l.emitEvent(cfg, internal.EventRunFailed, map[string]any{"reason": runErr.Error(), "category": "panic"})
		}
	}()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	l.mu.Lock()
	abortedBeforeStart := l.abortedBeforeStart[cfg.RunID]
	interruptedBeforeStart := l.interruptedBeforeStart[cfg.RunID]
	delete(l.abortedBeforeStart, cfg.RunID)
	delete(l.interruptedBeforeStart, cfg.RunID)
	delete(l.pendingRuns, cfg.RunID)
	l.activeRuns[cfg.RunID] = &runControl{cancel: cancel}
	l.mu.Unlock()
	defer func() {
		l.mu.Lock()
		delete(l.activeRuns, cfg.RunID)
		l.mu.Unlock()
	}()

	// A stop that arrived while this run was still being dispatched already
	// counts. Cancelling here rather than returning early means the run takes
	// the ordinary abort path at its first checkpoint — same run.aborted event,
	// and the user's message is still recorded, exactly as for a stop pressed a
	// moment later.
	if abortedBeforeStart {
		cancel()
	}

	l.startRun(ctx, s, userMessage, attachments)

	// Agent loop. There is no iteration cap: a run ends when the model stops
	// asking for tools, errors, is aborted, or the user declines a
	// continuation checkpoint.
	for iteration := 0; ; iteration++ {
		if ctx.Err() != nil {
			return l.endAborted(s).values()
		}
		if interruptedBeforeStart || l.isInterrupted(cfg.RunID) {
			return l.endInterrupted(s, "", "", nil).values()
		}
		l.compactIfNeeded(ctx, s, false)

		turn, end := l.streamModelTurn(ctx, s)
		if end != nil {
			return end.values()
		}
		if end := l.recordModelTurn(ctx, s, &turn); end != nil {
			return end.values()
		}

		// A turn that reasoned but gave neither text nor a tool call is not
		// an answer: the reply was cut off while the model was still
		// reasoning. Ask it to go on instead of ending the run with nothing.
		if len(turn.toolCalls) == 0 && strings.TrimSpace(turn.content) == "" && strings.TrimSpace(turn.reasoning) != "" && s.emptyTurns < maxEmptyTurns {
			s.emptyTurns++
			s.appendMessage(turn.assistantMessage())
			s.appendMessage(internal.Message{ID: internal.NewMessageID(), Role: "user", Content: emptyTurnNudge, Internal: true, CreatedAt: time.Now()})
			continue
		}

		// No tool calls: the model has answered and the run is done.
		if len(turn.toolCalls) == 0 {
			s.appendMessage(turn.assistantMessage())
			l.emitEvent(cfg, internal.EventRunCompleted, map[string]any{
				"iterations":    iteration + 1,
				"final_content": turn.content,
			})
			return s.result(), nil
		}

		assistantMsg := turn.assistantMessage()
		s.appendMessage(assistantMsg)
		// If steering arrives after the provider has finished its tool request but
		// before execution begins, do not start new work. Complete the protocol
		// transcript with explicit non-executed results and stop at this safe
		// boundary.
		if l.isInterrupted(cfg.RunID) {
			s.messages = appendToolResultsMessage(s.messages, completePendingToolResults(turn.toolCalls, nil, "tool execution interrupted before start"))
			return l.endInterrupted(s, "", "", nil).values()
		}

		if end := l.runToolTurn(ctx, s, assistantMsg.ID, turn.toolCalls); end != nil {
			return end.values()
		}
		s.emptyTurns = 0

		// A steer requested while a tool was executing deliberately lands here:
		// all tool results are durably represented, but they have not been sent
		// to the provider for another model turn.
		if l.isInterrupted(cfg.RunID) {
			return l.endInterrupted(s, "", "", nil).values()
		}

		l.compactIfNeeded(ctx, s, true)

		if end := l.continuationCheckpoint(ctx, s, iteration); end != nil {
			return end.values()
		}
	}
}

func contextUtilizationPercent(inputTokens, contextWindow int64) float64 {
	if inputTokens <= 0 || contextWindow <= 0 {
		return 0
	}
	return (float64(inputTokens) / float64(contextWindow)) * 100
}

func effectiveContextTokens(usage provider.Usage) int64 {
	total := usage.InputTokens + usage.CacheCreationInputTokens + usage.CacheReadInputTokens
	if total > 0 {
		return total
	}
	return usage.InputTokens
}

func appendToolResultsMessage(messages []internal.Message, toolResults []internal.ToolResult) []internal.Message {
	if len(toolResults) == 0 {
		return messages
	}
	toolMsg := internal.Message{
		ID:          internal.NewMessageID(),
		Role:        "user",
		ToolResults: toolResults,
		CreatedAt:   time.Now(),
	}
	return append(messages, toolMsg)
}

func repairDanglingToolCallHistory(messages []internal.Message) ([]internal.Message, int) {
	if len(messages) == 0 {
		return messages, 0
	}

	repaired := make([]internal.Message, 0, len(messages)+1)
	repairedCount := 0

	for i := 0; i < len(messages); i++ {
		message := messages[i]
		repaired = append(repaired, message)
		if len(message.ToolCalls) == 0 {
			continue
		}

		pending := make(map[string]internal.ToolCall, len(message.ToolCalls))
		for _, call := range message.ToolCalls {
			pending[call.ID] = call
		}

		j := i + 1
		for ; j < len(messages) && len(messages[j].ToolResults) > 0; j++ {
			repaired = append(repaired, messages[j])
			for _, result := range messages[j].ToolResults {
				delete(pending, result.ToolCallID)
			}
		}

		if len(pending) > 0 {
			repaired = append(repaired, internal.Message{
				ID:          internal.NewMessageID(),
				Role:        "user",
				ToolResults: buildRecoveredToolResults(pending),
				CreatedAt:   time.Now(),
			})
			repairedCount += len(pending)
		}

		i = j - 1
	}

	return repaired, repairedCount
}

func buildRecoveredToolResults(pending map[string]internal.ToolCall) []internal.ToolResult {
	ids := make([]string, 0, len(pending))
	for id := range pending {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	results := make([]internal.ToolResult, 0, len(ids))
	for _, id := range ids {
		call := pending[id]
		results = append(results, internal.ToolResult{
			ToolCallID: id,
			Content:    fmt.Sprintf("Recovered missing tool result for interrupted tool call %s. A previous run left this call without a matching tool response in history.", call.Name),
			IsError:    true,
			Internal:   call.Internal,
		})
	}
	return results
}

func completePendingToolResults(toolCalls []internal.ToolCall, toolResults []internal.ToolResult, content string) []internal.ToolResult {
	resolved := make(map[string]struct{}, len(toolResults))
	for _, result := range toolResults {
		resolved[result.ToolCallID] = struct{}{}
	}
	for _, call := range toolCalls {
		if _, ok := resolved[call.ID]; ok {
			continue
		}
		toolResults = append(toolResults, internal.ToolResult{
			ToolCallID: call.ID,
			Content:    content,
			IsError:    true,
			Internal:   call.Internal,
		})
	}
	return toolResults
}

func (l *Loop) beginProvider(runID internal.RunID, cancelStream context.CancelFunc) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if control := l.activeRuns[runID]; control != nil {
		control.phase = runPhaseProvider
		control.cancelStream = cancelStream
	}
}

func (l *Loop) endProvider(runID internal.RunID) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if control := l.activeRuns[runID]; control != nil && control.phase == runPhaseProvider {
		control.cancelStream = nil
		control.phase = runPhaseIdle
	}
}

func (l *Loop) beginTool(runID internal.RunID) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if control := l.activeRuns[runID]; control != nil {
		control.phase = runPhaseTool
		control.cancelStream = nil
	}
}

func (l *Loop) endTool(runID internal.RunID) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if control := l.activeRuns[runID]; control != nil && control.phase == runPhaseTool {
		control.phase = runPhaseIdle
	}
}

func (l *Loop) isInterrupted(runID internal.RunID) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.activeRuns[runID] != nil && l.activeRuns[runID].interrupted
}

// interruptedResult emits the terminal steer event. A provider prefix is
// represented as an ordinary assistant message so persisted history and the
// next queued continuation do not lose text the user already saw streamed.
func (l *Loop) interruptedResult(cfg RunConfig, messages []internal.Message, compacted bool, usage provider.Usage, content, reasoning string, reasoningDetails json.RawMessage) (RunResult, error) {
	if content != "" || reasoning != "" {
		messages = append(messages, internal.Message{
			ID:               internal.NewMessageID(),
			Role:             "assistant",
			Content:          content,
			ReasoningContent: reasoning,
			ReasoningDetails: reasoningDetails,
			CreatedAt:        time.Now(),
		})
	}
	l.emitEvent(cfg, internal.EventRunInterrupted, map[string]any{
		"reason": "run interrupted for steering",
	})
	return RunResult{Messages: messages, Compacted: compacted, Usage: usage}, ErrInterrupted
}

// MarkRunPending declares that runID has been dispatched and will shortly enter
// Run. It must be called synchronously, before any dispatch work that can take
// time (provider resolution, history load) and before the
// goroutine that calls Run is spawned.
//
// Without it there is a window in which the run is already advertised as
// running (the store row exists and a client may already ask to stop it) but
// no cancel func is registered yet, so Abort returns
// false and the stop request is silently dropped. Callers must pair this with a
// Run (which consumes the marker) or ClearRunPending if dispatch fails.
func (l *Loop) MarkRunPending(runID internal.RunID) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.pendingRuns == nil {
		l.pendingRuns = make(map[internal.RunID]bool)
	}
	l.pendingRuns[runID] = true
}

// ClearRunPending drops a pending marker for a run that will never reach Run.
func (l *Loop) ClearRunPending(runID internal.RunID) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.pendingRuns, runID)
	delete(l.abortedBeforeStart, runID)
	delete(l.interruptedBeforeStart, runID)
}

// Abort cancels a running agent loop. A run that has been dispatched but has not
// yet entered Run is recorded as aborted-before-start; Run then starts with an
// already-cancelled context and stops at its first checkpoint, instead of
// executing a turn the user already stopped.
func (l *Loop) Abort(runID internal.RunID) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if control, ok := l.activeRuns[runID]; ok {
		control.cancel()
		return true
	}
	if l.pendingRuns[runID] {
		if l.abortedBeforeStart == nil {
			l.abortedBeforeStart = make(map[internal.RunID]bool)
		}
		l.abortedBeforeStart[runID] = true
		return true
	}
	return false
}

// Interrupt requests a cooperative steering interruption. During provider
// generation it cancels that stream promptly. During tool execution it leaves
// the tool's context alive and returns only at the next post-tool boundary.
// Like Abort, it also covers the dispatch window after MarkRunPending.
func (l *Loop) Interrupt(runID internal.RunID) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if control, ok := l.activeRuns[runID]; ok {
		control.interrupted = true
		if control.phase == runPhaseProvider && control.cancelStream != nil {
			control.cancelStream()
		}
		return true
	}
	if l.pendingRuns[runID] {
		if l.interruptedBeforeStart == nil {
			l.interruptedBeforeStart = make(map[internal.RunID]bool)
		}
		l.interruptedBeforeStart[runID] = true
		return true
	}
	return false
}

// IsRunning checks if a run is active. A dispatched-but-not-yet-started run
// counts as running: it is about to execute, so treating it as idle would let a
// second run start on the same session and would make abort look like a no-op.
func (l *Loop) IsRunning(runID internal.RunID) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.activeRuns[runID]; ok {
		return true
	}
	return l.pendingRuns[runID]
}

func (l *Loop) buildSystemPromptAt(cfg RunConfig, now time.Time) string {
	return BuildSystemPromptAt(cfg, now)
}

func BuildSystemPrompt(cfg RunConfig) string {
	return BuildSystemPromptAt(cfg, promptNow().UTC())
}

func BuildSystemPromptAt(cfg RunConfig, now time.Time) string {
	runtimeSection := "Runtime context:\n- Base directory: " + fallbackString(cfg.BaseDirectory, ".")

	baseInstructions := BaseInstructions()
	systemPrompt := strings.TrimSpace(cfg.SystemPrompt)
	instructions := make([]string, 0, len(cfg.Instructions))
	for _, section := range cfg.Instructions {
		if section = strings.TrimSpace(section); section != "" {
			instructions = append(instructions, section)
		}
	}
	instructionParts := make([]string, 0, 2+len(cfg.Instructions))
	if !containsInstructionSection(systemPrompt, instructions, baseInstructions) {
		instructionParts = append(instructionParts, baseInstructions)
	}
	if systemPrompt != "" {
		instructionParts = append(instructionParts, systemPrompt)
	}
	instructionParts = append(instructionParts, instructions...)
	instructionsSection := "Base instructions:\n\n" + strings.Join(instructionParts, "\n\n")

	skillsSection := buildSkillsSection(cfg.AvailableSkills)
	definitionsSection := buildDefinitionsSection(cfg.AvailableDefinitions)

	sections := []string{runtimeSection, instructionsSection}
	if strings.TrimSpace(definitionsSection) != "" {
		sections = append(sections, definitionsSection)
	}
	sections = append(sections, skillsSection)

	// Drop the guidance that names tools this agent was not given.
	return ResolveToolBlocks(strings.Join(sections, "\n\n"), AvailableToolSet(cfg.Tools))
}

func buildSkillsSection(skills []AvailableSkill) string {
	if len(skills) == 0 {
		return "Available skills:\n- None"
	}

	sortedSkills := append([]AvailableSkill(nil), skills...)
	sort.Slice(sortedSkills, func(i, j int) bool {
		return sortedSkills[i].Name < sortedSkills[j].Name
	})

	var sb strings.Builder
	sb.WriteString("Available skills:\nYou have access to a 'skill' tool that loads specialized instructions.\n\n")
	sb.WriteString("<available_skills>\n")
	for _, sk := range sortedSkills {
		sb.WriteString(fmt.Sprintf("  <skill>\n    <name>%s</name>\n    <description>%s</description>\n  </skill>\n", sk.Name, fallbackString(sk.Description, "(no description)")))
	}
	sb.WriteString("</available_skills>\n\n")
	sb.WriteString("Load a skill when its specialization matches the current task: skill({ name: \"<skill-name>\" })")

	return sb.String()
}

func buildDefinitionsSection(defs []AvailableDefinition) string {
	if len(defs) == 0 {
		return ""
	}

	sortedDefs := append([]AvailableDefinition(nil), defs...)
	sort.Slice(sortedDefs, func(i, j int) bool {
		return strings.ToLower(sortedDefs[i].Title) < strings.ToLower(sortedDefs[j].Title)
	})

	var sb strings.Builder
	sb.WriteString("Definitions:\n")
	for _, def := range sortedDefs {
		sb.WriteString("\n")
		if !def.Important {
			sb.WriteString(fmt.Sprintf("- %s [%s]\n", fallbackString(def.Title, "(untitled)"), def.ID))
			sb.WriteString(fmt.Sprintf("  Snippet: %s\n", fallbackString(def.Snippet, "(no snippet)")))
			continue
		}
		sb.WriteString(fmt.Sprintf("- %s [%s] IMPORTANT\n", fallbackString(def.Title, "(untitled)"), def.ID))
		sb.WriteString(fmt.Sprintf("  Snippet: %s\n", fallbackString(def.Snippet, "(no snippet)")))
		if len(def.Scope) > 0 {
			sortedScope := append([]string(nil), def.Scope...)
			sort.Strings(sortedScope)
			sb.WriteString(fmt.Sprintf("  Scope: %s\n", strings.Join(sortedScope, ", ")))
		}
		for _, rule := range sortDefinitionItems(def.Rules) {
			sb.WriteString(fmt.Sprintf("  Rule %s (%s): %s\n", fallbackString(rule.Title, "(untitled)"), rule.ID, fallbackString(rule.Content, "(empty)")))
		}
		for _, note := range sortDefinitionItems(def.Notes) {
			sb.WriteString(fmt.Sprintf("  Note %s (%s): %s\n", fallbackString(note.Title, "(untitled)"), note.ID, fallbackString(note.Content, "(empty)")))
		}
	}
	return strings.TrimRight(sb.String(), "\n")
}

func sortDefinitionItems(items []AvailableDefinitionItem) []AvailableDefinitionItem {
	sorted := append([]AvailableDefinitionItem(nil), items...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].ID < sorted[j].ID
	})
	return sorted
}

func fallbackString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func containsInstructionSection(systemPrompt string, instructions []string, target string) bool {
	target = strings.TrimSpace(target)
	if target == "" {
		return false
	}

	if strings.Contains(strings.TrimSpace(systemPrompt), target) {
		return true
	}

	for _, section := range instructions {
		if strings.Contains(strings.TrimSpace(section), target) {
			return true
		}
	}

	return false
}

func (l *Loop) emitEvent(cfg RunConfig, eventType string, payload map[string]any) {
	if l.eventSink == nil {
		return
	}
	if eventType == internal.EventRunFailed || eventType == internal.EventToolFinished || eventType == "provider.connection" {
		payload["model"] = cfg.ModelName
		if cfg.Provider != nil {
			payload["provider"] = cfg.Provider.Name()
		}
	}
	data, _ := json.Marshal(payload)
	l.eventSink(internal.Event{
		Type:      eventType,
		Timestamp: time.Now(),
		SessionID: cfg.SessionID,
		RunID:     cfg.RunID,
		Payload:   json.RawMessage(data),
	})
}

// toolInvocation identifies one tool call for failure reporting.
func toolInvocation(cfg RunConfig, callID, batchID string, batchIndex, batchSize int) tools.Invocation {
	providerName := ""
	if cfg.Provider != nil {
		providerName = cfg.Provider.Name()
	}
	return tools.Invocation{
		ID: string(cfg.RunID) + ":" + callID, ToolCallID: callID, RunID: string(cfg.RunID),
		BatchID: batchID, BatchIndex: batchIndex, BatchSize: batchSize,
		Provider: providerName, Model: cfg.ModelName,
	}
}

func (l *Loop) emitToolFailed(cfg RunConfig, tc internal.ToolCall, reason, batchID string, batchIndex, batchSize int) {
	status, phase, category, ruleID, retryable := classifyToolFailure(reason)
	payload := toolTerminalPayload(tc, status, phase, category, ruleID, retryable, reason, batchID, batchIndex, batchSize, -1)
	payload["before_dispatch"] = true
	l.emitEvent(cfg, internal.EventToolFinished, payload)
}

func (l *Loop) emitToolExecutionFinished(cfg RunConfig, tc internal.ToolCall, status, phase, category, ruleID string, retryable bool, batchID string, batchIndex, batchSize int, durationMS int64) {
	reason := ""
	if status != "success" {
		reason = "tool execution failed"
		if category == "cancelled" {
			reason = "tool execution cancelled"
		}
	}
	payload := toolTerminalPayload(tc, status, phase, category, ruleID, retryable, reason, batchID, batchIndex, batchSize, durationMS)
	l.emitEvent(cfg, internal.EventToolFinished, payload)
}

func (l *Loop) emitPendingToolFailures(cfg RunConfig, pending []internal.ToolCall, reason, batchID string, firstIndex, batchSize int) {
	for offset, tc := range pending {
		l.emitToolFailed(cfg, tc, reason, batchID, firstIndex+offset, batchSize)
	}
}

func toolTerminalPayload(tc internal.ToolCall, status, phase, category, ruleID string, retryable bool, reason, batchID string, batchIndex, batchSize int, durationMS int64) map[string]any {
	payload := map[string]any{
		"tool_call_id": tc.ID,
		"tool_name":    string(tc.Name),
		"status":       status,
		"phase":        phase,
		"category":     category,
		"retryable":    retryable,
		"batch_id":     batchID,
		"batch_index":  batchIndex,
		"batch_size":   batchSize,
	}
	if ruleID != "" {
		payload["rule_id"] = ruleID
	}
	if reason != "" {
		payload["reason"] = reason
	}
	if durationMS >= 0 {
		payload["duration_ms"] = durationMS
	}
	if paths := toolArgumentPaths(tc.Arguments); len(paths) > 0 {
		payload["requested_paths"] = paths
		payload["requested_path"] = paths[0]
	}
	return payload
}

func classifyToolFailure(reason string) (status, phase, category, ruleID string, retryable bool) {
	lower := strings.ToLower(reason)
	switch {
	case strings.Contains(lower, "tool denied"):
		if strings.Contains(lower, "path") {
			return "denied", "policy", "path_outside_scope", "filesystem.path_scope", true
		}
		return "denied", "policy", "tool_not_allowed", "tools.allowlist", false
	case strings.Contains(lower, "policy error"):
		return "error", "policy", "policy_evaluation_error", "", true
	case strings.Contains(lower, "aborted") || strings.Contains(lower, "cancel"):
		return "error", "execution", "cancelled", "", true
	default:
		return "error", "execution", "tool_error", "", true
	}
}

// toolArgumentPaths deliberately exposes only path-like values, never the full
// arguments blob (which can contain secrets). It supports scalar and common
// batch forms so a failure remains actionable without losing redaction.
func toolArgumentPaths(arguments json.RawMessage) []string {
	var raw map[string]any
	if json.Unmarshal(arguments, &raw) != nil {
		return nil
	}
	var paths []string
	if path, _ := raw["path"].(string); path != "" {
		paths = append(paths, path)
	}
	for _, key := range []string{"reads", "writes", "edits"} {
		items, _ := raw[key].([]any)
		for _, item := range items {
			entry, _ := item.(map[string]any)
			if path, _ := entry["path"].(string); path != "" {
				paths = append(paths, path)
			}
		}
	}
	return paths
}

// maxEmptyTurns is how many replies in a row may come back with neither
// text nor a tool call before the run ends anyway.
const maxEmptyTurns = 2

const emptyTurnNudge = "Your last reply had no answer and no tool call; it was probably cut off while reasoning. Continue: make the next tool call now, or give your final answer."

// runAllowedToolSet builds the canonical allowlist for a run from its configured
// tool definitions. It returns nil when the run has no tool list (nil), which
// callers treat as "no restriction" (all enabled tools allowed). A non-nil
// empty list allows nothing: an agent's allowlist that matched no registered
// tool must not turn into access to every tool.
func runAllowedToolSet(defs []internal.ToolDefinition) map[string]bool {
	if defs == nil {
		return nil
	}
	allowed := make(map[string]bool, len(defs))
	for _, def := range defs {
		allowed[string(internal.CanonicalToolName(def.Name))] = true
	}
	return allowed
}

// promptCacheKey identifies one conversation for prompt caching and sticky
// routing.
func promptCacheKey(cfg RunConfig) string {
	return string(cfg.SessionID)
}

// normalizeToolArguments makes a streamed tool call's arguments valid JSON so
// the call can always be persisted and replayed. An empty string — which some
// models emit for tools without parameters — becomes an empty object. A
// non-empty blob that is not valid JSON (a generation cut off mid-value, a lost
// stream fragment) is wrapped as a JSON string: json.Marshal refuses an invalid
// json.RawMessage, so storing it raw failed the transcript save and lost the
// whole run, while the wrapped form keeps exactly what the model sent. Such a
// call is refused before dispatch (see malformedToolArguments).
func normalizeToolArguments(raw string) json.RawMessage {
	if strings.TrimSpace(raw) == "" {
		return json.RawMessage("{}")
	}
	if json.Valid([]byte(raw)) {
		return json.RawMessage(raw)
	}
	quoted, _ := json.Marshal(raw)
	return json.RawMessage(quoted)
}

// malformedToolArguments reports whether normalizeToolArguments had to wrap a
// call's arguments. Tool arguments are always a JSON object, so a JSON string
// can only be that wrapping.
func malformedToolArguments(args json.RawMessage) bool {
	trimmed := bytes.TrimSpace(args)
	return len(trimmed) > 0 && trimmed[0] == '"'
}
