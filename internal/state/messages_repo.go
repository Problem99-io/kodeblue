package state

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	internal "github.com/Problem99-io/kodeblue/internal"
)

type MessageRepo struct {
	db *DB
}

func NewMessageRepo(db *DB) *MessageRepo {
	return &MessageRepo{db: db}
}

func marshalMessageUsage(usage *internal.MessageUsage) (string, error) {
	if usage == nil {
		return "", nil
	}
	encoded, err := json.Marshal(usage)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func parseMessageUsage(raw string) *internal.MessageUsage {
	if raw == "" {
		return nil
	}
	var usage internal.MessageUsage
	if err := json.Unmarshal([]byte(raw), &usage); err != nil {
		return nil
	}
	if usage.InputTokens == 0 && usage.OutputTokens == 0 && usage.CacheCreationInputTokens == 0 && usage.CacheReadInputTokens == 0 && usage.Cost == nil {
		return nil
	}
	return &usage
}

// marshalAttachmentsForStorage encodes a message's attachments with their
// payloads stripped.
//
// Attachment bodies are base64 images and documents — a single screenshot is
// hundreds of kilobytes, and the session database would grow without bound if
// every turn kept one. They are only needed for the provider request of the run
// that carried them, which holds the messages in memory, so what is persisted
// is the descriptor alone: enough for the transcript to show what was sent, and
// enough for a replayed history to name the file, without the bytes.
func marshalAttachmentsForStorage(attachments []internal.Attachment) (string, error) {
	if len(attachments) == 0 {
		encoded, err := json.Marshal(attachments)
		return string(encoded), err
	}
	stripped := make([]internal.Attachment, len(attachments))
	for i, attachment := range attachments {
		attachment.Data = ""
		stripped[i] = attachment
	}
	encoded, err := json.Marshal(stripped)
	return string(encoded), err
}

// marshalToolCallsForStorage encodes a message's tool calls so the encoding
// cannot fail.
//
// Arguments are a json.RawMessage holding whatever the model streamed. A
// truncated or otherwise malformed blob is not valid JSON, and json.Marshal
// refuses to embed it — which used to fail the whole transcript save and lose
// the run. Empty arguments become "{}" (what a parameterless call means);
// anything else that is not valid JSON is kept as a JSON string, so the
// transcript still shows exactly what the model sent.
func marshalToolCallsForStorage(calls []internal.ToolCall) (string, error) {
	sanitized, copied := calls, false
	for i, call := range calls {
		args := SanitizeStoredToolArguments(call.Arguments)
		if string(args) == string(call.Arguments) {
			continue
		}
		if !copied {
			sanitized, copied = append([]internal.ToolCall(nil), calls...), true
		}
		sanitized[i].Arguments = args
	}
	encoded, err := json.Marshal(sanitized)
	return string(encoded), err
}

// SanitizeStoredToolArguments returns tool-call arguments that are always
// valid JSON: empty becomes {}, and invalid JSON is wrapped as a JSON string.
func SanitizeStoredToolArguments(raw json.RawMessage) json.RawMessage {
	if len(bytes.TrimSpace(raw)) == 0 {
		return json.RawMessage("{}")
	}
	if json.Valid(raw) {
		return raw
	}
	quoted, _ := json.Marshal(string(raw))
	return json.RawMessage(quoted)
}

// marshalToolResultsForStorage encodes tool results, dropping the metadata of
// any result whose metadata cannot be encoded rather than failing the save.
func marshalToolResultsForStorage(results []internal.ToolResult) (string, error) {
	encoded, err := json.Marshal(results)
	if err == nil {
		return string(encoded), nil
	}
	sanitized := append([]internal.ToolResult(nil), results...)
	for i := range sanitized {
		if _, err := json.Marshal(sanitized[i].Metadata); err != nil {
			sanitized[i].Metadata = map[string]any{"metadata_error": err.Error()}
		}
	}
	encoded, err = json.Marshal(sanitized)
	return string(encoded), err
}

// encodedMessage is a message's columns in their stored form.
type encodedMessage struct {
	toolCalls, toolResults, attachments, usage string
}

func encodeMessageForStorage(m *internal.Message) (encodedMessage, error) {
	var e encodedMessage
	var err error
	if e.toolCalls, err = marshalToolCallsForStorage(m.ToolCalls); err != nil {
		return e, fmt.Errorf("encode tool calls of message %s: %w", m.ID, err)
	}
	if e.toolResults, err = marshalToolResultsForStorage(m.ToolResults); err != nil {
		return e, fmt.Errorf("encode tool results of message %s: %w", m.ID, err)
	}
	if e.attachments, err = marshalAttachmentsForStorage(m.Attachments); err != nil {
		return e, fmt.Errorf("encode attachments of message %s: %w", m.ID, err)
	}
	if e.usage, err = marshalMessageUsage(m.Usage); err != nil {
		return e, fmt.Errorf("encode usage of message %s: %w", m.ID, err)
	}
	return e, nil
}

// insertMessageTx inserts one message. position 0 lets the
// messages_assign_position trigger append it to its session.
func insertMessageTx(exec interface {
	Exec(string, ...any) (sql.Result, error)
}, sessionID internal.SessionID, runID internal.RunID, m *internal.Message, position int64) error {
	e, err := encodeMessageForStorage(m)
	if err != nil {
		return err
	}
	_, err = exec.Exec(
		`INSERT INTO messages (id, session_id, run_id, role, content, reasoning_content, reasoning_details, attachments, tool_calls, tool_results, usage, internal, compacted, position, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)`,
		m.ID, string(sessionID), string(runID), m.Role, m.Content, m.ReasoningContent, string(m.ReasoningDetails),
		e.attachments, e.toolCalls, e.toolResults, e.usage, m.Internal, position, m.CreatedAt.Unix(),
	)
	return err
}

func (r *MessageRepo) Create(sessionID internal.SessionID, runID internal.RunID, m *internal.Message) error {
	return insertMessageTx(r.db, sessionID, runID, m, 0)
}

func parseReasoningDetails(raw string) json.RawMessage {
	if raw == "" {
		return nil
	}
	return json.RawMessage(raw)
}

func (r *MessageRepo) GetBySession(sessionID internal.SessionID) ([]internal.Message, error) {
	rows, err := r.db.conn.Query(
		`SELECT id, role, content, reasoning_content, reasoning_details, attachments, tool_calls, tool_results, usage, internal, created_at
		 FROM messages WHERE session_id = ? AND compacted = 0 ORDER BY position ASC, rowid ASC`,
		string(sessionID),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	messages := make([]internal.Message, 0)
	for rows.Next() {
		var m internal.Message
		var reasoningDetailsStr, attachmentsStr, toolCallsStr, toolResultsStr, usageStr string
		var createdAt int64
		if err := rows.Scan(&m.ID, &m.Role, &m.Content, &m.ReasoningContent, &reasoningDetailsStr, &attachmentsStr, &toolCallsStr, &toolResultsStr, &usageStr, &m.Internal, &createdAt); err != nil {
			return nil, err
		}
		m.ReasoningDetails = parseReasoningDetails(reasoningDetailsStr)
		m.CreatedAt = time.Unix(createdAt, 0)
		if err := json.Unmarshal([]byte(attachmentsStr), &m.Attachments); err != nil {
			m.Attachments = nil
		}
		if err := json.Unmarshal([]byte(toolCallsStr), &m.ToolCalls); err != nil {
			m.ToolCalls = nil
		}
		if err := json.Unmarshal([]byte(toolResultsStr), &m.ToolResults); err != nil {
			m.ToolResults = nil
		}
		m.Usage = parseMessageUsage(usageStr)
		messages = append(messages, m)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return messages, nil
}

// GetAllBySession returns every message for a session including compacted ones.
// Used by the UI/API to display full chat history.
func (r *MessageRepo) GetAllBySession(sessionID internal.SessionID) ([]internal.Message, error) {
	rows, err := r.db.conn.Query(
		`SELECT id, role, content, reasoning_content, reasoning_details, attachments, tool_calls, tool_results, usage, internal, created_at
		 FROM messages WHERE session_id = ? ORDER BY position ASC, rowid ASC`,
		string(sessionID),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	messages := make([]internal.Message, 0)
	for rows.Next() {
		var m internal.Message
		var reasoningDetailsStr, attachmentsStr, toolCallsStr, toolResultsStr, usageStr string
		var createdAt int64
		if err := rows.Scan(&m.ID, &m.Role, &m.Content, &m.ReasoningContent, &reasoningDetailsStr, &attachmentsStr, &toolCallsStr, &toolResultsStr, &usageStr, &m.Internal, &createdAt); err != nil {
			return nil, err
		}
		m.ReasoningDetails = parseReasoningDetails(reasoningDetailsStr)
		m.CreatedAt = time.Unix(createdAt, 0)
		if err := json.Unmarshal([]byte(attachmentsStr), &m.Attachments); err != nil {
			m.Attachments = nil
		}
		if err := json.Unmarshal([]byte(toolCallsStr), &m.ToolCalls); err != nil {
			m.ToolCalls = nil
		}
		if err := json.Unmarshal([]byte(toolResultsStr), &m.ToolResults); err != nil {
			m.ToolResults = nil
		}
		m.Usage = parseMessageUsage(usageStr)
		messages = append(messages, m)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return messages, nil
}

// ClearReasoningBySession removes provider-private continuation state while
// preserving the portable conversation: visible text, attachments, tool calls,
// tool results, usage, and compaction markers. Opaque reasoning details and
// plaintext interleaved-thinking fields are only valid for the model/provider
// chain that produced them and must not survive an explicit selection switch.
func (r *MessageRepo) ClearReasoningBySession(sessionID internal.SessionID) error {
	_, err := r.db.conn.Exec(
		`UPDATE messages
		 SET reasoning_content = '', reasoning_details = ''
		 WHERE session_id = ? AND (reasoning_content != '' OR reasoning_details != '')`,
		string(sessionID),
	)
	return err
}

// CompactMessages makes compactedMessages, in that order, the session's active
// transcript: every other active message is marked compacted and messages not
// stored yet (e.g. the summary) are inserted. Full history stays in the DB.
func (r *MessageRepo) CompactMessages(sessionID internal.SessionID, runID internal.RunID, compactedMessages []internal.Message) error {
	return r.db.WithTx(func(tx *sql.Tx) error {
		return compactMessagesTx(tx, sessionID, runID, nil, compactedMessages)
	})
}

// CompactSnapshot is CompactMessages for a caller that worked from a snapshot
// of the active history: only messages in snapshotIDs, or written by runID
// itself, may be marked compacted. A message another writer added after the
// snapshot was taken stays active, after the compacted set.
func (r *MessageRepo) CompactSnapshot(sessionID internal.SessionID, runID internal.RunID, snapshotIDs []string, compactedMessages []internal.Message) error {
	snapshot := make(map[string]bool, len(snapshotIDs))
	for _, id := range snapshotIDs {
		snapshot[id] = true
	}
	return r.db.WithTx(func(tx *sql.Tx) error {
		return compactMessagesTx(tx, sessionID, runID, snapshot, compactedMessages)
	})
}

// compactMessagesTx also lets inbox delivery persist its exact active transcript
// and acknowledgement in one transaction. A nil snapshot lets it hide any
// active message of the session.
func compactMessagesTx(tx *sql.Tx, sessionID internal.SessionID, runID internal.RunID, snapshot map[string]bool, active []internal.Message) error {
	keep := make(map[string]bool, len(active))
	for _, m := range active {
		keep[m.ID] = true
	}

	// Hide the active messages that are not in the new active set.
	rows, err := tx.Query(`SELECT id, run_id FROM messages WHERE session_id = ? AND compacted = 0`, string(sessionID))
	if err != nil {
		return err
	}
	var hide []string
	for rows.Next() {
		var id, rowRunID string
		if err := rows.Scan(&id, &rowRunID); err != nil {
			rows.Close()
			return err
		}
		if keep[id] {
			continue
		}
		if snapshot == nil || snapshot[id] || (runID != "" && rowRunID == string(runID)) {
			hide = append(hide, id)
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, id := range hide {
		if _, err := tx.Exec(`UPDATE messages SET compacted = 1 WHERE id = ? AND session_id = ?`, id, string(sessionID)); err != nil {
			return err
		}
	}

	// Which of the new active set are stored already. Kept messages are
	// (re)activated; the rest are inserted below.
	stored := make([]bool, len(active))
	foreign := make([]bool, len(active))
	for i := range active {
		result, err := tx.Exec(`UPDATE messages SET compacted = 0 WHERE id = ? AND session_id = ?`, active[i].ID, string(sessionID))
		if err != nil {
			return err
		}
		if n, _ := result.RowsAffected(); n > 0 {
			stored[i] = true
			continue
		}
		var exists int
		if err := tx.QueryRow(`SELECT COUNT(1) FROM messages WHERE id = ?`, active[i].ID).Scan(&exists); err != nil {
			return err
		}
		// An ID owned by another session is never overwritten or duplicated.
		foreign[i] = exists > 0
	}
	nextStored := make([]int, len(active))
	next := -1
	for i := len(active) - 1; i >= 0; i-- {
		nextStored[i] = next
		if stored[i] {
			next = i
		}
	}

	// Insert new messages where they sit in the active set: in front of the
	// next stored message (shifting it and everything after it down one), or
	// appended when nothing stored follows. A summary therefore lands after the
	// messages it replaced and before the raw tail it precedes.
	for i := range active {
		if stored[i] || foreign[i] {
			continue
		}
		var position int64
		if j := nextStored[i]; j >= 0 {
			if err := tx.QueryRow(`SELECT position FROM messages WHERE id = ? AND session_id = ?`, active[j].ID, string(sessionID)).Scan(&position); err != nil {
				return err
			}
			if position > 0 {
				if _, err := tx.Exec(`UPDATE messages SET position = position + 1 WHERE session_id = ? AND position >= ?`, string(sessionID), position); err != nil {
					return err
				}
			}
		}
		if err := insertMessageTx(tx, sessionID, runID, &active[i], position); err != nil {
			return err
		}
	}

	return nil
}
