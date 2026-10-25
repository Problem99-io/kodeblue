package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	internal "github.com/Problem99-io/kodeblue/internal"
	"github.com/Problem99-io/kodeblue/internal/api"
)

type queuedRunOptions struct {
	InputSource     string `json:"input_source,omitempty"`
	Model           string `json:"model,omitempty"`
	Provider        string `json:"provider,omitempty"`
	ReasoningEffort string `json:"reasoning_effort,omitempty"`
}

// LockSessionDispatch lets lifecycle readers observe the queue and loop claim
// on the same side of a dispatch. Keep the queue -> task-engine lock order used
// by dispatch, stop, and completion delivery.
func (a *agentLoopAdapter) LockSessionDispatch() func() {
	a.queueMu.Lock()
	return a.queueMu.Unlock
}

const (
	// defaultQueueFailureGrace is how long a missing provider may keep failing
	// before the inbox pauses; dynamic providers register shortly after start.
	defaultQueueFailureGrace = time.Minute
	maxQueueRetryDelay       = time.Minute
)

// runRejectedError marks RunAsync failures that retrying cannot fix, such as
// a blocked model switch. A missing provider may still appear once dynamic
// providers finish registering, so it is retried during a grace window first.
type runRejectedError struct {
	err                 error
	providerUnavailable bool
}

func (e *runRejectedError) Error() string { return e.err.Error() }
func (e *runRejectedError) Unwrap() error { return e.err }

func rejectRun(err error) error { return &runRejectedError{err: err} }

type queueDispatchFailure struct {
	attempts int
	first    time.Time
}

func encodeQueuedRunOptions(opts api.RunOptions) json.RawMessage {
	encoded, _ := json.Marshal(queuedRunOptions{
		InputSource: opts.InputSource, Model: opts.Model, Provider: opts.Provider, ReasoningEffort: opts.ReasoningEffort,
	})
	return encoded
}

func decodeQueuedRunOptions(raw json.RawMessage) api.RunOptions {
	var stored queuedRunOptions
	_ = json.Unmarshal(raw, &stored)
	return api.RunOptions{InputSource: stored.InputSource, Model: stored.Model, Provider: stored.Provider, ReasoningEffort: stored.ReasoningEffort}
}

// SubmitUser starts an ordinary turn when the session is free. While another
// turn is active (or Stop has paused delivery), it durably appends the message
// to the session inbox instead of returning the historical 409 conflict.
func (a *agentLoopAdapter) SubmitUser(sessionID internal.SessionID, content, clientMessageID string, attachments []internal.Attachment, opts api.RunOptions) (api.QueueSubmitResult, error) {
	a.queueMu.Lock()
	defer a.queueMu.Unlock()

	// Callers that need a started run, not a queued acceptance, are refused
	// while the session is busy or still has queued messages.
	if opts.RejectIfBusy {
		if a.sessionBusyLocked(sessionID) {
			return api.QueueSubmitResult{}, fmt.Errorf("session busy or queue pending")
		}
		pending, err := a.queueRepo.ListPending(sessionID)
		if err != nil {
			return api.QueueSubmitResult{}, err
		}
		if len(pending) > 0 {
			return api.QueueSubmitResult{}, fmt.Errorf("session busy or queue pending")
		}
		if err := a.queueRepo.SetPaused(sessionID, false); err != nil {
			return api.QueueSubmitResult{}, err
		}
	}
	enqueue := a.queueRepo.EnqueueUnique
	if opts.Resume || opts.SteerNow {
		enqueue = a.queueRepo.EnqueueUserAndResume
	}
	item, inserted, err := enqueue(&internal.QueueItem{
		SessionID:       sessionID,
		Source:          internal.QueueItemSourceUser,
		Heading:         "User message",
		Content:         content,
		ClientMessageID: clientMessageID,
		Metadata:        encodeQueuedRunOptions(opts),
		Attachments:     attachments,
	})
	if err != nil {
		return api.QueueSubmitResult{}, err
	}
	if !inserted && (!(opts.Resume || opts.SteerNow) || item.State != internal.QueueItemPending) {
		result := api.QueueSubmitResult{Status: string(item.State), SessionID: sessionID, Item: item}
		if item.ClaimRunID != "" {
			result.RunID = item.ClaimRunID
		}
		return result, nil
	}
	paused, err := a.queueRepo.IsPaused(sessionID)
	if err != nil {
		return api.QueueSubmitResult{}, err
	}
	a.emitQueueEvent(sessionID, internal.EventQueueItemEnqueued, map[string]any{
		"item_id": item.ID, "source": item.Source,
	})

	result := api.QueueSubmitResult{Status: "queued", SessionID: sessionID, Item: item}
	if opts.SteerNow {
		if activeID, ok := a.activeRunLocked(sessionID); ok {
			a.loop.Interrupt(activeID)
		}
	}
	if !paused && !a.sessionBusyLocked(sessionID) {
		runID, started, err := a.startQueuedRunLocked(sessionID)
		if err != nil {
			// The input is durable. A failed launch must not be presented as a
			// lost send: retry it, or report the pause if it cannot be delivered.
			if a.handleDispatchFailureLocked(sessionID, err) {
				result.Status = "paused"
				result.Error = err.Error()
			}
			return result, nil
		}
		if started {
			result.Status = "started"
			result.RunID = runID
			result.Item = nil
		}
	}
	return result, nil
}

func (a *agentLoopAdapter) UpdateQueuedUser(sessionID internal.SessionID, itemID internal.QueueItemID, content, expectedContent string) (bool, error) {
	a.queueMu.Lock()
	defer a.queueMu.Unlock()
	updated, err := a.queueRepo.UpdatePendingUser(sessionID, itemID, content, expectedContent)
	if updated {
		a.emitQueueEvent(sessionID, "queue.item_updated", map[string]any{"item_id": itemID})
	}
	return updated, err
}

func (a *agentLoopAdapter) RemoveQueuedUser(sessionID internal.SessionID, itemID internal.QueueItemID) (bool, error) {
	a.queueMu.Lock()
	defer a.queueMu.Unlock()
	items, err := a.queueRepo.ListPending(sessionID)
	if err != nil {
		return false, err
	}
	for i := range items {
		if items[i].ID != itemID {
			continue
		}
		if items[i].Source != internal.QueueItemSourceUser {
			return false, nil
		}
		removed, err := a.queueRepo.RemovePending(sessionID, itemID)
		if removed {
			a.emitQueueEvent(sessionID, internal.EventQueueItemRemoved, map[string]any{"item_id": itemID})
		}
		return removed, err
	}
	return false, nil
}

func (a *agentLoopAdapter) Steer(sessionID internal.SessionID) (api.QueueActionResult, error) {
	a.queueMu.Lock()
	defer a.queueMu.Unlock()
	if err := a.queueRepo.SetPaused(sessionID, false); err != nil {
		return api.QueueActionResult{}, err
	}
	count, err := a.queueRepo.PendingCount(sessionID)
	if err != nil {
		return api.QueueActionResult{}, err
	}
	if count == 0 {
		return api.QueueActionResult{Status: "empty"}, nil
	}
	if runID, ok := a.activeRunLocked(sessionID); ok {
		if a.loop.Interrupt(runID) {
			a.emitQueueEvent(sessionID, internal.EventQueueSteerRequested, map[string]any{"run_id": runID, "pending_count": count})
			return api.QueueActionResult{Status: "interrupting", RunID: runID, PendingCount: count}, nil
		}
	}
	runID, started, err := a.startQueuedRunLocked(sessionID)
	if err != nil {
		a.handleDispatchFailureLocked(sessionID, err)
		return api.QueueActionResult{}, err
	}
	status := "queued"
	if started {
		status = "started"
		count = 0
	}
	return api.QueueActionResult{Status: status, RunID: runID, PendingCount: count}, nil
}

func (a *agentLoopAdapter) Continue(sessionID internal.SessionID) (api.QueueActionResult, error) {
	a.queueMu.Lock()
	defer a.queueMu.Unlock()
	if err := a.queueRepo.SetPaused(sessionID, false); err != nil {
		return api.QueueActionResult{}, err
	}
	count, err := a.queueRepo.PendingCount(sessionID)
	if err != nil {
		return api.QueueActionResult{}, err
	}
	a.emitQueueEvent(sessionID, internal.EventQueueDeliveryResumed, map[string]any{"pending_count": count})
	if count == 0 {
		return api.QueueActionResult{Status: "idle", PendingCount: count}, nil
	}
	if a.sessionBusyLocked(sessionID) {
		return api.QueueActionResult{Status: "queued", PendingCount: count}, nil
	}
	runID, started, err := a.startQueuedRunLocked(sessionID)
	if err != nil {
		a.handleDispatchFailureLocked(sessionID, err)
		return api.QueueActionResult{}, err
	}
	status := "queued"
	if started {
		status = "started"
		count = 0
	}
	return api.QueueActionResult{Status: status, RunID: runID, PendingCount: count}, nil
}

func (a *agentLoopAdapter) Pause(sessionID internal.SessionID) error {
	a.queueMu.Lock()
	defer a.queueMu.Unlock()
	if err := a.queueRepo.SetPaused(sessionID, true); err != nil {
		return err
	}
	count, _ := a.queueRepo.PendingCount(sessionID)
	a.emitQueueEvent(sessionID, internal.EventQueueDeliveryPaused, map[string]any{"pending_count": count})
	return nil
}

func (a *agentLoopAdapter) startQueuedRunLocked(sessionID internal.SessionID) (internal.RunID, bool, error) {
	if a.sessionBusyLocked(sessionID) {
		return "", false, nil
	}
	lease, err := a.runRepo.TryAcquireSessionRunLease(sessionID)
	if err != nil || lease == nil {
		return "", false, err
	}
	transferred := false
	defer func() {
		if !transferred {
			lease.Release()
		}
	}()
	recovered, err := a.runRepo.RecoverOrphanedSessionRuns(lease)
	if err != nil {
		return "", false, err
	}
	for _, id := range recovered {
		a.logger.Warn("recovered run left by exited runtime", "session_id", sessionID, "run_id", id)
		payload, _ := json.Marshal(map[string]any{"error": "Runtime exited before the run completed", "recovered": true})
		a.eventSink(internal.Event{Type: internal.EventRunFailed, Timestamp: time.Now(), SessionID: sessionID, RunID: id, Payload: payload})
	}
	runID := internal.NewRunID()
	run := &internal.Run{ID: runID, SessionID: sessionID, Status: internal.RunRunning, CreatedAt: time.Now()}
	var content string
	var attachments []internal.Attachment
	var opts api.RunOptions
	var persisted *internal.Message
	items, err := a.queueRepo.DispatchPending(sessionID, run, func(batch []internal.QueueItem) (*internal.Message, error) {
		content, attachments, opts = formatQueuedBatch(batch)
		persisted = &internal.Message{ID: internal.NewMessageID(), Role: "user", Content: content, Attachments: attachments, CreatedAt: time.Now()}
		return persisted, nil
	})
	if err != nil {
		return "", false, err
	}
	if len(items) == 0 {
		delete(a.queueFailures, sessionID)
		return "", false, nil
	}
	opts.PersistedUserMessage = persisted
	if err := a.runAsyncWithLease(string(sessionID), string(runID), content, attachments, opts, lease); err != nil {
		if restoreErr := a.queueRepo.RestoreUndispatched(sessionID, runID, items); restoreErr != nil {
			return "", false, fmt.Errorf("start queued run: %w; restore inbox: %v", err, restoreErr)
		}
		return "", false, err
	}
	transferred = true
	delete(a.queueFailures, sessionID)
	ids := make([]internal.QueueItemID, 0, len(items))
	for i := range items {
		ids = append(ids, items[i].ID)
	}
	a.emitQueueEvent(sessionID, internal.EventQueueBatchStarted, map[string]any{"run_id": runID, "item_ids": ids, "count": len(ids)})
	return runID, true, nil
}

func (a *agentLoopAdapter) drainQueue(sessionID internal.SessionID) {
	a.queueMu.Lock()
	defer a.queueMu.Unlock()
	paused, err := a.queueRepo.IsPaused(sessionID)
	if err != nil {
		a.scheduleQueueRetryLocked(sessionID, time.Second)
		return
	}
	if paused || a.sessionBusyLocked(sessionID) {
		return
	}
	if _, _, err := a.startQueuedRunLocked(sessionID); err != nil {
		a.handleDispatchFailureLocked(sessionID, err)
	}
}

// handleDispatchFailureLocked decides between retrying a failed dispatch and
// pausing the inbox. Undeliverable input pauses at once with its reason shown
// in the queue; a missing provider pauses after the grace window; anything
// else (e.g. a busy database) retries with exponential backoff up to a minute.
// It reports whether the inbox was paused.
func (a *agentLoopAdapter) handleDispatchFailureLocked(sessionID internal.SessionID, err error) bool {
	if a.queueFailures == nil {
		a.queueFailures = make(map[internal.SessionID]*queueDispatchFailure)
	}
	failure := a.queueFailures[sessionID]
	if failure == nil {
		failure = &queueDispatchFailure{first: time.Now()}
		a.queueFailures[sessionID] = failure
	}
	failure.attempts++
	grace := a.queueFailureGrace
	if grace <= 0 {
		grace = defaultQueueFailureGrace
	}
	var rejected *runRejectedError
	if errors.As(err, &rejected) && (!rejected.providerUnavailable || time.Since(failure.first) >= grace) {
		reason := err.Error()
		if pauseErr := a.queueRepo.PauseWithFailure(sessionID, reason); pauseErr != nil {
			a.logger.Error("failed to pause undeliverable session queue; retrying", "session_id", sessionID, "error", pauseErr)
			a.scheduleQueueRetryLocked(sessionID, time.Second)
			return false
		}
		delete(a.queueFailures, sessionID)
		count, _ := a.queueRepo.PendingCount(sessionID)
		a.logger.Warn("queued input cannot be delivered; paused session queue", "session_id", sessionID, "reason", reason)
		a.emitQueueEvent(sessionID, internal.EventQueueDeliveryPaused, map[string]any{"pending_count": count, "reason": reason})
		return true
	}
	delay := maxQueueRetryDelay
	if failure.attempts <= 6 {
		delay = min(time.Second<<(failure.attempts-1), maxQueueRetryDelay)
	}
	a.logger.Error("failed to dispatch session queue; retrying", "session_id", sessionID, "error", err, "attempt", failure.attempts, "retry_after", delay)
	a.scheduleQueueRetryLocked(sessionID, delay)
	return false
}

// A report accepted while the parent was busy must also survive a failed
// later drain; its original completion callback has already returned.
func (a *agentLoopAdapter) scheduleQueueRetryLocked(sessionID internal.SessionID, delay time.Duration) {
	if a.queueRetryPending == nil {
		a.queueRetryPending = make(map[internal.SessionID]bool)
	}
	if a.queueRetryPending[sessionID] {
		return
	}
	a.queueRetryPending[sessionID] = true
	time.AfterFunc(delay, func() {
		a.queueMu.Lock()
		delete(a.queueRetryPending, sessionID)
		a.queueMu.Unlock()
		a.drainQueue(sessionID)
	})
}

func (a *agentLoopAdapter) activeRunLocked(sessionID internal.SessionID) (internal.RunID, bool) {
	runs, err := a.runRepo.GetBySession(sessionID)
	if err != nil {
		return "", false
	}
	for _, run := range runs {
		if run.Status == internal.RunRunning && a.loop.IsRunning(run.ID) {
			return run.ID, true
		}
	}
	return "", false
}

func (a *agentLoopAdapter) sessionBusyLocked(sessionID internal.SessionID) bool {
	runs, err := a.runRepo.GetBySession(sessionID)
	if err != nil {
		return true
	}
	for _, run := range runs {
		if run.Status == internal.RunRunning && a.loop.IsRunning(run.ID) {
			return true
		}
	}
	// No run of this process is live, but the session lease may still be
	// held: by a manual compaction, or by a run in another runtime sharing the
	// database. Callers never hold the lease themselves when they ask.
	lease, err := a.runRepo.TryAcquireSessionRunLease(sessionID)
	if err != nil || lease == nil {
		return true
	}
	lease.Release()
	return false
}

func (a *agentLoopAdapter) emitQueueEvent(sessionID internal.SessionID, eventType string, payload map[string]any) {
	encoded, _ := json.Marshal(payload)
	a.eventSink(internal.Event{Type: eventType, Timestamp: time.Now(), SessionID: sessionID, Payload: encoded})
}

func formatQueuedBatch(items []internal.QueueItem) (string, []internal.Attachment, api.RunOptions) {
	if len(items) == 1 {
		return items[0].Content, append([]internal.Attachment(nil), items[0].Attachments...), decodeQueuedRunOptions(items[0].Metadata)
	}
	var body strings.Builder
	body.WriteString("The following messages arrived while you were busy. Handle them together in chronological order.\n")
	attachments := make([]internal.Attachment, 0)
	var opts api.RunOptions
	for index, item := range items {
		body.WriteString("\n## ")
		body.WriteString(fmt.Sprintf("%d. ", index+1))
		body.WriteString("User message")
		queuedOpts := decodeQueuedRunOptions(item.Metadata)
		opts.InputSource = queuedOpts.InputSource
		if queuedOpts.Model != "" {
			opts.Model = queuedOpts.Model
		}
		if queuedOpts.Provider != "" {
			opts.Provider = queuedOpts.Provider
		}
		if queuedOpts.ReasoningEffort != "" {
			opts.ReasoningEffort = queuedOpts.ReasoningEffort
		}
		body.WriteString("\n\n")
		body.WriteString(strings.TrimSpace(item.Content))
		if len(item.Attachments) > 0 {
			body.WriteString("\n\nAttachments for this queued message:")
			for _, attachment := range item.Attachments {
				body.WriteString("\n- ")
				body.WriteString(attachment.FileName)
			}
			attachments = append(attachments, item.Attachments...)
		}
		body.WriteString("\n")
	}
	return body.String(), attachments, opts
}

// Serialize Stop with user enqueue and resume. Pause is written even when no
// run is active.
func (a *agentLoopAdapter) StopSession(sessionID internal.SessionID, stop func() error) error {

	a.queueMu.Lock()
	defer a.queueMu.Unlock()
	if err := a.queueRepo.SetPaused(sessionID, true); err != nil {
		return err
	}
	return stop()
}
