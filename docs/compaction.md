# Context Compaction

This document explains how the engine compacts a long session, and why it is implemented this way.

## Goal

Compaction exists to shrink the active prompt for a session without losing the working state needed to continue the task.

The required behavior is:

1. Use the same live conversation context the assistant would normally send.
2. Append one synthetic user message that asks for a compact handoff summary.
3. Send that request with the same active model (unless `compaction_model` names another), the same generated system prompt, the same tool definitions, and the same prompt cache key as the live chat.
4. Take the assistant response from that request.
5. Replace the older part of the active session with that response, while keeping a recent raw tail.

That means compaction is treated as a normal continuation of the chat, not as a separate summarization workflow with a reconstructed transcript. Because the request prefix is the same as the live conversation prefix, provider-side prompt caching can reuse the already-cached prompt and only pay for the small synthetic tail.

## Current Behavior

The implementation lives in [internal/agent/compact.go](../internal/agent/compact.go).

Every caller goes through `Compact` / `CompactWithReport` with a `CompactOptions` value, which runs `compactConfiguredWindow`.

At a high level, the compactor produces this active layout after success:

`[frozen prefix] + [one compacted summary message] + [recent raw tail]`

The current constants are:

- `frozenPrefixSize = 0` — no conversation message is pinned. The system prompt is sent separately and is the stable cache prefix; the original task is summarized like any other message. Leading system-role messages, if a caller ever places them in the message list, are always kept in the prefix.
- `defaultRawTailRatio = 0.25`
- `recentMessageCap = 10`
- `manualCompactionTriggerTokens = 25_000` (manual compaction only, see below)
- `summaryMaxOutputTokens = 4096` (capped to a quarter of very small windows)

The full raw history is not deleted. Only the active set changes.

## Trigger Paths

There are two normal ways compaction happens.

### Automatic compaction inside the run loop

Automatic compaction is triggered by `compactIfNeeded` in [internal/agent/model_turn.go](../internal/agent/model_turn.go), called from the run loop in [internal/agent/loop.go](../internal/agent/loop.go), when estimated prompt usage crosses the configured threshold (`NeedsCompaction`).

There are two trigger points:

- Before a provider call, if the next normal request would exceed the threshold.
- After tool results are appended, if the tool output pushes the context over the threshold.

In both cases the loop calls the compactor with:

- `ActiveModel = cfg.ModelName`
- `Manual = false`
- `ContextWindow` = the run's effective context window
- `SystemPrompt` = the run's generated system prompt
- `Tools = cfg.Tools`
- `PromptCacheKey` = the run's prompt cache key (the session ID)

This is important because the compaction request must share the same cached prefix as the live chat request.

### Manual compaction through the API

Manual compaction is exposed at `POST /v1/sessions/{id}/compact` and is handled by `CompactSession` in [cmd/kodeblue-engine/compact_session.go](../cmd/kodeblue-engine/compact_session.go).

The manual path:

1. Takes the session's run lease, as a run does, and holds it until it is done. If a run holds it (in this or another runtime sharing the database) the request gets `409`. A message sent meanwhile is queued, and delivered when the lease is released.
2. Loads the active session history with `GetBySession`.
3. Resolves the effective provider and active model.
4. Rebuilds the same run system prompt and tool list the live agent would use.
5. Passes the session ID as the prompt cache key, and `Manual = true`.
6. Runs the same compactor used by the automatic path, on the request's context: a client that disconnects cancels the summary and the history is left as it was.
7. Persists the compacted active set with `CompactSnapshot`, which can only hide messages that were in the history it summarized.

## Exact Request That Gets Sent

Instead of building a synthetic transcript such as `User: ... Assistant: ...` and summarizing that with a separate model, the engine sends:

- the full current active message list
- plus one final synthetic user message containing `compactionUserPrompt`

That request is built in `summarizeViaLiveContext` in [internal/agent/compact.go](../internal/agent/compact.go).

The request fields are:

- `Model`: `compaction_model` when set, otherwise the active session model. A separate compaction model cannot reuse the live chat's prompt cache, so leave it empty unless a cheaper summarizer is worth paying for the uncached input.
- `Messages`: the live conversation plus the synthetic compaction prompt
- `SystemPrompt`: the same generated run system prompt used by normal chat requests
- `Tools`: the same active tool definitions used by normal chat requests
- `PromptCacheKey`: the session ID
- `MaxTokens`: `summaryMaxOutputTokens`

### Fitting the request into the window

Compaction runs when the conversation is already near the limit, so the full live context plus the synthetic prompt plus the output budget is exactly the request most likely to overflow. `fitSummaryInput` keeps the input within `window - MaxTokens - window/10`:

1. If the full live context fits, it is sent unchanged (and the prompt cache hits).
2. Otherwise long message bodies and tool results are cut to their head and tail (`trimmedMessageChars`), oldest first, until it fits.
3. If that is still too much, the oldest exchanges are replaced by one note: any earlier compaction summary among them is carried whole, up to a quarter of the request budget (beyond that its head and tail are kept), and the rest as a short digest. Cuts never separate a tool call from its result.

An earlier summary still in the request is never cut by step 2. The budget is sized against the window of the model that writes the summary: `compaction_model`'s when that is set, otherwise the session's.

Any earlier compaction summary that is still in the active history is part of that live context, so the model folds it into the fresh summary rather than the engine concatenating old summary bodies verbatim. This keeps stale task descriptions from surviving across later compactions.

## How the Active Session Is Rewritten

Once the compaction request returns, the assistant output is wrapped into a single active message with content shaped like:

`[Compacted context — N messages summarized]\n<summary>`

That message is stored with role `user`.

The final active message slice becomes:

- the frozen prefix (empty unless leading system messages are present)
- the compacted summary message
- the recent raw tail selected as described below

The persistence logic lives in [internal/state/messages_repo.go](../internal/state/messages_repo.go).

`GetBySession` only returns messages where `compacted = 0`.

Messages are ordered by an explicit per-session `position` column, not by `created_at`: the summary is written now but belongs before a raw tail written earlier. Plain appends get the next position from a trigger; databases from older engines are backfilled in their old order, moving an active summary that had sorted after its tail back in front of it.

`CompactMessages` / `CompactSnapshot` do the rewrite in one transaction:

1. Mark the active messages that are not in the new active set as `compacted = 1`. `CompactSnapshot` (used by runs and manual compaction) only touches messages in the snapshot it was given or written by its own run, so a message another writer added meanwhile stays active.
2. Unmark the kept messages that still belong in the active set.
3. Insert new messages (the summary) at their place in the active set: in front of the next stored message, so the summary lands after the messages it replaced and before the kept tail.

Tool-call arguments that are not valid JSON (a generation cut off mid-call) are stored as a JSON string rather than failing the save; the loop refuses to execute such a call and answers it with an error result. If saving a run's transcript still fails, the run is marked failed with a `run.failed` event instead of being reported completed.

`GetAllBySession` still returns the full historical transcript, including compacted rows, so the full history stays available.

## Tail Selection Logic

Compaction does not summarize the whole conversation into one summary and throw everything else away.

It keeps a recent raw tail so the model still sees the latest literal exchanges, tool calls, and tool results.

The recent tail is selected by `selectRecentTailStart`.

Important details:

- The tail budget is `25%` of the effective context window.
- When the budget forces a cut, the tail is further capped at the last `recentMessageCap` (10) messages. A conversation that fits the budget entirely is not compacted.
- Compaction boundaries are adjusted so a tool call and its tool result are never split apart.
- For manual compactions only, planning clamps the window to `25,000` tokens when the current input and window are both larger than that threshold (a raw tail of about 6,250 tokens). Without it a conversation well below the automatic threshold would fit the 25% tail entirely and a manual request could never compact it. Automatic compaction always uses 25% of the real window.

That clamp is only used to size the recent raw tail. It does not change how the summary request is built.

## Fallback Behavior

The preferred path is the live-context compaction request described above.

If that request fails, ends without its completion event, or returns an empty summary, the compactor falls back to a local digest of the messages being replaced: what the user and assistant said, each tool call with its arguments, and the head and tail of each tool result (errors flagged), bounded to a tenth of the window with the most recent lines kept. Tool results are the evidence of an investigation, so the fallback keeps them rather than only tool names.

If the run is stopped (or a manual request cancelled) while the summary streams, nothing is compacted: a partial summary is never accepted, and the uncompacted history is kept.

That fallback is a safety net, not the intended steady-state path.

When the live provider call succeeds, compaction behaves exactly as a normal chat continuation with one extra synthetic user message at the end.

## Resulting Mental Model

The simplest correct way to think about compaction is:

1. Take the current active chat context.
2. Pretend the user sent one more message asking for a handoff summary.
3. Send that request through the same provider, same model, same generated system prompt, same tool set, and same prompt cache key.
4. Take the assistant reply from that request.
5. Replace the older part of the session with that reply while preserving a recent raw tail.
