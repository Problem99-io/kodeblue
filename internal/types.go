package internal

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"time"
)

// ID types
type SessionID string
type RunID string
type ToolCallID string
type ToolName string
type QueueItemID string

// Status types
type SessionStatus string

const (
	SessionActive    SessionStatus = "active"
	SessionCompleted SessionStatus = "completed"
	SessionAborted   SessionStatus = "aborted"
)

type RunStatus string

const (
	RunRunning   RunStatus = "running"
	RunPaused    RunStatus = "paused"
	RunCompleted RunStatus = "completed"
	RunFailed    RunStatus = "failed"
	RunAborted   RunStatus = "aborted"
	// RunInterrupted is a cooperative steering interruption. Unlike an abort,
	// it preserves a completed tool turn or streamed assistant prefix so a
	// caller can immediately continue with queued guidance.
	RunInterrupted RunStatus = "interrupted"
)

// QueueItemSource identifies the producer of a session inbox item.
type QueueItemSource string

const (
	QueueItemSourceUser QueueItemSource = "user"
)

// QueueItemState is the durable delivery lifecycle for an inbox item.
type QueueItemState string

const (
	QueueItemPending   QueueItemState = "pending"
	QueueItemClaimed   QueueItemState = "claimed"
	QueueItemDelivered QueueItemState = "delivered"
	QueueItemRemoved   QueueItemState = "removed"
)

// Event type constants
const (
	EventMessageStarted     = "message.started"
	EventModelToken         = "model.token"
	EventModelCompleted     = "model.completed"
	EventToolCallStreaming  = "tool.streaming"
	EventToolRequested      = "tool.requested"
	EventQuestionAsked      = "question.asked"
	EventQuestionBatchAsked = "question.batch_asked"
	EventQuestionAnswered   = "question.answered"
	EventToolStarted        = "tool.started"
	EventToolOutput         = "tool.output"
	// EventToolFinished is the canonical terminal event for a requested tool
	// call. Its payload carries status: success, error, denied, rejected, or
	// partial.
	EventToolFinished         = "tool.finished"
	EventCompactionPerformed  = "compaction.performed"
	EventRunCompleted         = "run.completed"
	EventRunFailed            = "run.failed"
	EventRunAborted           = "run.aborted"
	EventRunInterrupted       = "run.interrupted"
	EventQueueItemEnqueued    = "queue.item_enqueued"
	EventQueueItemRemoved     = "queue.item_removed"
	EventQueueDeliveryPaused  = "queue.delivery_paused"
	EventQueueDeliveryResumed = "queue.delivery_resumed"
	EventQueueSteerRequested  = "queue.steer_requested"
	EventQueueBatchStarted    = "queue.batch_started"
)

// Event represents a server-sent event in the agent lifecycle.
type Event struct {
	Type      string            `json:"type"`
	Timestamp time.Time         `json:"timestamp"`
	SessionID SessionID         `json:"session_id"`
	RunID     RunID             `json:"run_id"`
	Seq       int64             `json:"seq"`
	Payload   json.RawMessage   `json:"payload"`
	Meta      map[string]string `json:"meta,omitempty"`
}

// Message represents a conversation message.
// Attachment represents a file attached to a message (image, document, etc.).
type Attachment struct {
	MediaType string `json:"media_type"`          // MIME type, e.g. "image/png", "application/pdf"
	FileName  string `json:"file_name,omitempty"` // Original file name
	Data      string `json:"data,omitempty"`      // Base64-encoded content
	URL       string `json:"url,omitempty"`       // URL alternative to inline data
}

type Message struct {
	ID               string `json:"id"`
	Role             string `json:"role"`
	Content          string `json:"content"`
	ReasoningContent string `json:"reasoning_content,omitempty"`
	// ReasoningDetails is the raw reasoning_details array returned by
	// OpenRouter-compatible routes (summary/encrypted/text blocks). It must be
	// replayed verbatim — same sequence, all fields intact — so it is kept as
	// opaque JSON rather than parsed into typed structs.
	ReasoningDetails json.RawMessage `json:"reasoning_details,omitempty"`
	Attachments      []Attachment    `json:"attachments,omitempty"`
	ToolCalls        []ToolCall      `json:"tool_calls,omitempty"`
	ToolResults      []ToolResult    `json:"tool_results,omitempty"`
	Usage            *MessageUsage   `json:"usage,omitempty"`
	CreatedAt        time.Time       `json:"created_at"`
	Internal         bool            `json:"internal,omitempty"`
}

// QueueItem is a durable, ordered message waiting to be delivered to a main
// session run. Attachments retain their payload only until delivery; callers
// that expose an item outside the repository should use its sanitized form.
type QueueItem struct {
	ID              QueueItemID     `json:"id"`
	SessionID       SessionID       `json:"session_id"`
	Source          QueueItemSource `json:"source"`
	Heading         string          `json:"heading"`
	Content         string          `json:"content"`
	ClientMessageID string          `json:"client_message_id,omitempty"`
	SourceRunID     RunID           `json:"source_run_id,omitempty"`
	// Metadata is opaque producer/coordinator state such as user-requested run
	// options. It is persisted without interpretation by the queue repository.
	Metadata    json.RawMessage `json:"metadata,omitempty"`
	Attachments []Attachment    `json:"attachments,omitempty"`
	State       QueueItemState  `json:"state"`
	ClaimRunID  RunID           `json:"claim_run_id,omitempty"`
	Sequence    int64           `json:"sequence"`
	CreatedAt   time.Time       `json:"created_at"`
	ClaimedAt   *time.Time      `json:"claimed_at,omitempty"`
	DeliveredAt *time.Time      `json:"delivered_at,omitempty"`
	RemovedAt   *time.Time      `json:"removed_at,omitempty"`
}

type MessageUsage struct {
	InputTokens               int64        `json:"input_tokens"`
	OutputTokens              int64        `json:"output_tokens"`
	CacheCreationInputTokens  int64        `json:"cache_creation_input_tokens"`
	CacheReadInputTokens      int64        `json:"cache_read_input_tokens"`
	ContextWindow             int64        `json:"context_window,omitempty"`
	ContextUtilizationPercent float64      `json:"context_utilization_percent,omitempty"`
	Cost                      *MessageCost `json:"cost,omitempty"`
}

type MessageCost struct {
	RequestID            string  `json:"request_id,omitempty"`
	InputCostUSD         float64 `json:"input_cost_usd"`
	OutputCostUSD        float64 `json:"output_cost_usd"`
	CacheCreationCostUSD float64 `json:"cache_creation_cost_usd"`
	CacheReadCostUSD     float64 `json:"cache_read_cost_usd"`
	RawTotalUSD          float64 `json:"raw_total_usd"`
	BilledTotalUSD       float64 `json:"billed_total_usd"`
}

// ToolCall represents a tool invocation by the model.
type ToolCall struct {
	ID        string          `json:"id"`
	Name      ToolName        `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
	Internal  bool            `json:"internal,omitempty"`
}

// ToolResult represents the result of a tool execution.
type ToolResult struct {
	ToolCallID string         `json:"tool_call_id"`
	Content    string         `json:"content"`
	IsError    bool           `json:"is_error,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
	Internal   bool           `json:"internal,omitempty"`
}

// ToolDefinition describes a tool available to the agent.
type ToolDefinition struct {
	Name        ToolName        `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"`
}

// IsInternalToolCall recognizes hidden tool calls in stored history (written
// by older engine versions).
func IsInternalToolCall(call ToolCall) bool {
	return call.Internal || CanonicalToolName(call.Name) == "report_suspicious_input"
}

// HasInternalContent determines whether a summary may include private report context.
func HasInternalContent(messages []Message) bool {
	for _, message := range messages {
		if message.Internal {
			return true
		}
		for _, call := range message.ToolCalls {
			if IsInternalToolCall(call) {
				return true
			}
		}
		for _, result := range message.ToolResults {
			if result.Internal {
				return true
			}
		}
	}
	return false
}

// VisibleMessages is an output projection for public APIs only. Persistence,
// checkpoints and compaction must always receive the full agent history.
func VisibleMessages(messages []Message) []Message {
	privateCalls := make(map[string]bool)
	for _, message := range messages {
		for _, call := range message.ToolCalls {
			if IsInternalToolCall(call) {
				privateCalls[call.ID] = true
			}
		}
	}
	visible := make([]Message, 0, len(messages))
	for _, message := range messages {
		if message.Internal {
			continue
		}
		copyMessage := message
		hadInternalPart := false
		copyMessage.ToolCalls = nil
		for _, call := range message.ToolCalls {
			if IsInternalToolCall(call) {
				hadInternalPart = true
			} else {
				copyMessage.ToolCalls = append(copyMessage.ToolCalls, call)
			}
		}
		copyMessage.ToolResults = nil
		for _, result := range message.ToolResults {
			if result.Internal || privateCalls[result.ToolCallID] {
				hadInternalPart = true
			} else {
				copyMessage.ToolResults = append(copyMessage.ToolResults, result)
			}
		}
		// Pure reporting turns, including legacy rows without a message flag,
		// cannot become a visible empty tool card or incidental assistant text.
		if hadInternalPart && len(copyMessage.ToolCalls) == 0 && len(copyMessage.ToolResults) == 0 {
			continue
		}
		visible = append(visible, copyMessage)
	}
	return visible
}

// AgentDefinition describes a named agent with its own tools, model, and instructions.
type AgentDefinition struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Disabled     bool     `json:"disabled"`
	Description  string   `json:"description"` // Brief explanation of what the agent does
	Instructions string   `json:"instructions"`
	Tools        []string `json:"tools"`    // Allowed tool names (empty = all enabled tools)
	Provider     string   `json:"provider"` // Default provider (empty = session/config default)
	Model        string   `json:"model"`    // Default model (empty = session/config default)
	// ReasoningEffort is forwarded to providers and models that support it. Empty keeps the model/provider default.
	ReasoningEffort string `json:"reasoning_effort,omitempty"`
	// MaxIterations is this agent's own continue-prompt threshold: how many
	// tool-calling turns a run takes before asking the user whether to keep
	// going. 0 = use the config default.
	MaxIterations int `json:"max_iterations"`
	// MaxOutputTokens caps a single normal model response. 0 keeps the
	// deployment default of 32768 tokens. -1 omits the engine's response-token
	// cap and lets the provider enforce only its own model/context boundaries.
	MaxOutputTokens int       `json:"max_output_tokens"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// Session represents an agent conversation session.
type Session struct {
	ID           SessionID     `json:"id"`
	Status       SessionStatus `json:"status"`
	Provider     string        `json:"provider"`
	Model        string        `json:"model"`
	AgentID      string        `json:"agent_id,omitempty"`
	CWD          string        `json:"cwd,omitempty"`
	Instructions []string      `json:"instructions,omitempty"`
	CreatedAt    time.Time     `json:"created_at"`
	UpdatedAt    time.Time     `json:"updated_at"`
}

// Run represents a single execution run within a session.
type Run struct {
	ID          RunID      `json:"id"`
	SessionID   SessionID  `json:"session_id"`
	Status      RunStatus  `json:"status"`
	ToolCalls   int        `json:"tool_calls"`
	TokensUsed  int64      `json:"tokens_used"`
	CreatedAt   time.Time  `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// QuestionAnswer is a user response to an ask_user tool prompt.
type QuestionAnswer struct {
	QuestionID string    `json:"question_id"`
	Mode       string    `json:"mode"`
	Text       string    `json:"text,omitempty"`
	Choices    []string  `json:"choices,omitempty"`
	AnsweredAt time.Time `json:"answered_at"`
}

// PendingQuestion represents a user-facing structured question waiting for input.
type PendingQuestion struct {
	QuestionID string    `json:"question_id"`
	SessionID  SessionID `json:"session_id"`
	RunID      RunID     `json:"run_id"`
	Title      string    `json:"title,omitempty"`
	Question   string    `json:"question"`
	Mode       string    `json:"mode"`
	Options    []string  `json:"options,omitempty"`
	Custom     bool      `json:"custom"`
	// Kind is QuestionKindAskUser for questions the model asked and
	// QuestionKindContinuation for the system's "keep going?" checkpoint. Empty
	// values from older rows read as QuestionKindAskUser.
	Kind               string    `json:"kind,omitempty"`
	Recommended        string    `json:"recommended,omitempty"`
	RecommendedChoices []string  `json:"recommended_choices,omitempty"`
	CreatedAt          time.Time `json:"created_at"`
}

// newPrefixedID generates a random ID with the given prefix (e.g. "sess_a1b2c3d4").
func newPrefixedID(prefix string) string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic("engine: failed to generate random ID: " + err.Error())
	}
	return prefix + "_" + hex.EncodeToString(b)
}

// NewSessionID generates a new session ID.
func NewSessionID() SessionID { return SessionID(newPrefixedID("sess")) }

// NewAgentDefinitionID generates a new agent definition ID.
func NewAgentDefinitionID() string { return newPrefixedID("agnt") }

// NewRunID generates a new run ID.
func NewRunID() RunID { return RunID(newPrefixedID("run")) }

// NewMessageID generates a new message ID.
func NewMessageID() string { return newPrefixedID("msg") }

// NewQueueItemID generates a durable session-inbox item ID.
func NewQueueItemID() QueueItemID { return QueueItemID(newPrefixedID("qmsg")) }

// NewID generates a generic prefixed ID.
func NewID(prefix string) string { return newPrefixedID(prefix) }
