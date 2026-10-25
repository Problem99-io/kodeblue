package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	internal "github.com/Problem99-io/kodeblue/internal"
	"github.com/Problem99-io/kodeblue/internal/agent"
	"github.com/Problem99-io/kodeblue/internal/api"
	"github.com/Problem99-io/kodeblue/internal/logging"
	"github.com/Problem99-io/kodeblue/internal/policy"
	"github.com/Problem99-io/kodeblue/internal/provider"
	"github.com/Problem99-io/kodeblue/internal/skill"
	"github.com/Problem99-io/kodeblue/internal/state"
	"github.com/Problem99-io/kodeblue/internal/tools"
)

// agentLoopAdapter bridges between the API interface and the real agent loop.
type agentLoopAdapter struct {
	loop             *agent.Loop
	compactor        *agent.Compactor
	providerRegistry *provider.Registry
	toolRegistry     *tools.Registry
	cfg              *policy.Config
	definitionsRoot  string
	sessionRepo      *state.SessionRepo
	agentRepo        *state.AgentRepo
	runRepo          *state.RunRepo
	messageRepo      *state.MessageRepo
	skillRegistry    *skill.Registry
	eventSink        agent.EventSink
	logger           *logging.Logger
	queueRepo        *state.QueueRepo

	// maxIterations is the config's turn limit: how many tool-calling turns a
	// run takes before asking whether to keep going.
	maxIterations int

	// queueMu serializes the busy-check/enqueue/claim/dispatch decision inside
	// this process. QueueRepo transactions provide the cross-process boundary.
	queueMu           sync.Mutex
	queueRetryPending map[internal.SessionID]bool
	// queueFailures tracks consecutive dispatch failures per session for
	// retry backoff and the grace window before a failure pauses the inbox.
	queueFailures map[internal.SessionID]*queueDispatchFailure
	// queueFailureGrace overrides defaultQueueFailureGrace (tests only).
	queueFailureGrace time.Duration
}

func (a *agentLoopAdapter) RunAsync(sessionID, runID string, message string, attachments []internal.Attachment, opts api.RunOptions) error {
	return a.runAsyncWithLease(sessionID, runID, message, attachments, opts, nil)
}

// runAsyncWithLease prepares a run (selection, history, prompt, the user's
// turn) synchronously, so every rejection reaches the caller, then runs the
// loop in the background. lease is nil unless the queue already holds the
// session's run lease.
func (a *agentLoopAdapter) runAsyncWithLease(sessionID, runID string, message string, attachments []internal.Attachment, opts api.RunOptions, lease *state.SessionRunLease) error {
	acquiredHere := lease == nil
	if lease == nil {
		var err error
		lease, err = a.runRepo.TryAcquireSessionRunLease(internal.SessionID(sessionID))
		if err != nil {
			return err
		}
		if lease == nil {
			return fmt.Errorf("session is already running in another runtime")
		}
	}
	// The run row is already persisted as running before we get here. Claim
	// the run with the loop up front so an abort arriving during the dispatch
	// work below (history load, provider resolution) is honoured.
	a.loop.MarkRunPending(internal.RunID(runID))
	dispatched := false
	defer func() {
		if !dispatched {
			a.loop.ClearRunPending(internal.RunID(runID))
			if acquiredHere {
				lease.Release()
			}
		}
	}()

	session, err := a.sessionRepo.Get(internal.SessionID(sessionID))
	if err != nil {
		return fmt.Errorf("load session %s: %w", sessionID, err)
	}
	if session == nil {
		return rejectRun(fmt.Errorf("session not found: %s", sessionID))
	}
	agentDef := a.agentFor(session)

	providerName := selectedProvider(opts, session, agentDef)
	if providerName == "" {
		return rejectRun(fmt.Errorf("no provider selected for session %s", sessionID))
	}
	history := a.historyForRun(session.ID, opts.PersistedUserMessage)
	a.logger.Info("starting run",
		"session_id", sessionID,
		"run_id", runID,
		"requested_provider", providerName,
		"session_model", session.Model,
		"agent_id", session.AgentID,
		"history_messages", len(history),
		"available_providers", a.providerRegistry.List(),
	)
	p, ok := api.ResolveConfiguredProvider(a.providerRegistry, a.cfg, a.logger.Logger, providerName, opts.Model)
	if !ok {
		err := fmt.Errorf("provider not available: %s (available: %v)", providerName, a.providerRegistry.List())
		a.logger.Error("cannot start run", "session_id", sessionID, "run_id", runID, "error", err)
		return &runRejectedError{err: err, providerUnavailable: true}
	}
	modelName := selectedModel(opts, session, agentDef, p)
	history, err = a.applySelection(session, runID, opts, providerName, modelName, p, history)
	if err != nil {
		return err
	}

	runCfg := a.promptConfig(session, agentDef)
	// The run may rewrite only what it was given and what it wrote itself
	// (its user turn, checkpoints, summaries): see MessageRepo.CompactSnapshot.
	snapshot := make([]string, len(history))
	for i := range history {
		snapshot[i] = history[i].ID
	}
	runCfg.SaveCheckpoint = func(messages []internal.Message) error {
		return a.messageRepo.CompactSnapshot(internal.SessionID(sessionID), internal.RunID(runID), snapshot, messages)
	}
	runCfg.SessionID = internal.SessionID(sessionID)
	runCfg.RunID = internal.RunID(runID)
	runCfg.Provider = p
	runCfg.Messages = history
	runCfg.ModelName = modelName
	runCfg.InputSource = opts.InputSource
	runCfg.QuestionID = opts.QuestionID
	// How many tool-calling turns this run takes before it stops and asks
	// whether to keep going. An agent definition may set its own threshold.
	runCfg.MaxIterations = a.maxIterations
	runCfg.ReasoningEffort = strings.TrimSpace(opts.ReasoningEffort)
	if agentDef != nil {
		if agentDef.MaxIterations > 0 {
			runCfg.MaxIterations = agentDef.MaxIterations
		}
		runCfg.MaxOutputTokens = agentDef.MaxOutputTokens
		if runCfg.ReasoningEffort == "" {
			runCfg.ReasoningEffort = strings.TrimSpace(agentDef.ReasoningEffort)
		}
	}

	userMessage, err := a.persistUserTurn(sessionID, runID, message, attachments, opts)
	if err != nil {
		return err
	}
	runCfg.UserMessageID = userMessage.ID
	runCfg.UserMessageCreatedAt = userMessage.CreatedAt

	dispatched = true
	go a.execute(lease, session, runCfg, message, attachments)
	return nil
}

// agentFor returns the session's agent definition, or nil when it has none.
func (a *agentLoopAdapter) agentFor(session *internal.Session) *internal.AgentDefinition {
	if session.AgentID == "" {
		return nil
	}
	agentDef, _ := a.agentRepo.Get(session.AgentID)
	return agentDef
}

// historyForRun loads the session's active history. A user message that was
// persisted before dispatch is dropped here; the loop appends it itself.
func (a *agentLoopAdapter) historyForRun(sessionID internal.SessionID, persisted *internal.Message) []internal.Message {
	history, err := a.messageRepo.GetBySession(sessionID)
	if err != nil {
		a.logger.Warn("failed to load session history, continuing with empty history", "session_id", sessionID, "error", err)
		return nil
	}
	if persisted == nil {
		return history
	}
	filtered := history[:0]
	for i := range history {
		if history[i].ID != persisted.ID {
			filtered = append(filtered, history[i])
		}
	}
	return filtered
}

// applySelection handles an explicit provider or model switch: it refuses a
// target model too small for the conversation, drops model-bound reasoning,
// and saves the new selection on the session. It returns the history to send.
func (a *agentLoopAdapter) applySelection(session *internal.Session, runID string, opts api.RunOptions, providerName, modelName string, p provider.Provider, history []internal.Message) ([]internal.Message, error) {
	providerChanged := strings.TrimSpace(opts.Provider) != "" &&
		!strings.EqualFold(strings.TrimSpace(session.Provider), strings.TrimSpace(providerName))
	modelChanged := strings.TrimSpace(opts.Model) != "" &&
		!strings.EqualFold(strings.TrimSpace(session.Model), strings.TrimSpace(modelName))

	// Refuse to switch to a model whose context window cannot hold the
	// conversation so far, and leave the session on its current model. Only
	// fires when the target model's window is authoritatively known.
	if modelChanged {
		if err := guardModelSwitchContextWindow(p, modelName, history); err != nil {
			a.logger.Warn("blocked model switch: target context window too small",
				"session_id", session.ID, "run_id", runID,
				"from_model", session.Model, "to_model", modelName, "error", err)
			return nil, rejectRun(err)
		}
	}
	if providerChanged || modelChanged {
		// Chat text and completed tool interactions are portable across
		// models; reasoning_content/reasoning_details are not. Persist the
		// boundary so later turns on the newly selected model cannot replay an
		// encrypted block from the old provider/model after this run succeeds.
		if err := a.messageRepo.ClearReasoningBySession(session.ID); err != nil {
			return nil, fmt.Errorf("clear model-bound reasoning for selection switch: %w", err)
		}
		history = clearModelBoundReasoning(history)
		a.logger.Info("cleared model-bound reasoning for selection switch",
			"session_id", session.ID, "run_id", runID,
			"from_provider", session.Provider, "to_provider", providerName,
			"from_model", session.Model, "to_model", modelName)
	}

	persist := false
	if providerChanged {
		session.Provider = providerName
		persist = true
	}
	if strings.TrimSpace(opts.Model) != "" && strings.TrimSpace(session.Model) != strings.TrimSpace(modelName) {
		session.Model = modelName
		persist = true
	}
	if persist {
		if err := a.sessionRepo.Update(session); err != nil {
			return nil, fmt.Errorf("persist session selection: %w", err)
		}
	}
	return history, nil
}

// persistUserTurn saves the user's message before the run goes to the
// background. A crash can kill the loop without running its completion
// block, and the message must survive that.
func (a *agentLoopAdapter) persistUserTurn(sessionID, runID, message string, attachments []internal.Attachment, opts api.RunOptions) (internal.Message, error) {
	if opts.PersistedUserMessage != nil {
		return *opts.PersistedUserMessage, nil
	}
	userMessage := internal.Message{
		ID:          internal.NewMessageID(),
		Role:        "user",
		Content:     message,
		Attachments: attachments,
		CreatedAt:   time.Now(),
	}
	persist := opts.PersistUserMessage
	if persist == nil {
		persist = func(message *internal.Message) error {
			return a.messageRepo.Create(internal.SessionID(sessionID), internal.RunID(runID), message)
		}
	}
	if err := persist(&userMessage); err != nil {
		return internal.Message{}, fmt.Errorf("persist user message before run: %w", err)
	}
	return userMessage, nil
}

// execute runs the loop, saves the transcript and the run's final status,
// then releases the session and drains its queue.
func (a *agentLoopAdapter) execute(lease *state.SessionRunLease, session *internal.Session, runCfg agent.RunConfig, message string, attachments []internal.Attachment) {
	defer lease.Release()
	runID := runCfg.RunID
	a.logger.Info("agent loop starting", "run_id", runID)
	ctx := context.Background()
	if session.CWD != "" {
		ctx = tools.WithSessionCWD(ctx, session.CWD)
	}
	result, err := a.loop.Run(ctx, runCfg, message, attachments)

	// Checkpoints may have persisted an earlier prefix already. An atomic,
	// idempotent active snapshot avoids duplicate inserts after continuing.
	if len(result.Messages) > 0 {
		if persistErr := runCfg.SaveCheckpoint(result.Messages); persistErr != nil {
			// The run's work is lost from the transcript: fail the run loudly
			// rather than report it completed.
			a.logger.Error("failed to persist run transcript", "session_id", session.ID, "run_id", runID, "error", persistErr)
			payload, _ := json.Marshal(map[string]any{
				"reason":   "failed to persist run transcript: " + persistErr.Error(),
				"category": "persistence",
			})
			a.eventSink(internal.Event{Type: internal.EventRunFailed, Timestamp: time.Now(), SessionID: session.ID, RunID: runID, Payload: payload})
			err = fmt.Errorf("persist run transcript: %w", persistErr)
		}
	}
	a.finishRun(runID, err, result.Usage.InputTokens+result.Usage.OutputTokens)

	// The session is now idle. Stop has already paused the queue; normal
	// completion and steer interruption drain one atomic snapshot.
	lease.Release()
	a.drainQueue(session.ID)
}

// finishRun records how a run ended.
func (a *agentLoopAdapter) finishRun(runID internal.RunID, runErr error, tokens int64) {
	status := internal.RunCompleted
	switch {
	case errors.Is(runErr, agent.ErrAborted):
		a.logger.Info("agent run aborted", "run_id", runID)
		status = internal.RunAborted
	case errors.Is(runErr, agent.ErrInterrupted):
		a.logger.Info("agent run interrupted for steering", "run_id", runID)
		status = internal.RunInterrupted
	case runErr != nil:
		a.logger.Error("agent run failed", "run_id", runID, "error", runErr)
		status = internal.RunFailed
	}
	run, _ := a.runRepo.Get(runID)
	if run == nil {
		return
	}
	run.Status = status
	run.TokensUsed = tokens
	now := time.Now()
	run.CompletedAt = &now
	a.runRepo.Update(run)
}

func (a *agentLoopAdapter) Abort(runID string) bool {
	return a.loop.Abort(internal.RunID(runID))
}

func (a *agentLoopAdapter) Interrupt(runID string) bool {
	return a.loop.Interrupt(internal.RunID(runID))
}

func (a *agentLoopAdapter) IsRunning(runID string) bool {
	return a.loop.IsRunning(internal.RunID(runID))
}
