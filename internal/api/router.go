package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	internal "github.com/Problem99-io/kodeblue/internal"
	"github.com/Problem99-io/kodeblue/internal/mcp"
	"github.com/Problem99-io/kodeblue/internal/policy"
	"github.com/Problem99-io/kodeblue/internal/provider"
	"github.com/Problem99-io/kodeblue/internal/state"
)

type Dependencies struct {
	DB              *state.DB
	Sessions        *state.SessionRepo
	Runs            *state.RunRepo
	Messages        *state.MessageRepo
	Queue           *state.QueueRepo
	Events          *state.EventRepo
	Questions       *state.PendingQuestionRepo
	Agents          *state.AgentRepo
	Providers       *provider.Registry
	AgentLoop       AgentLoopInterface
	MessageQueue    SessionMessageQueueInterface
	EventHub        *EventHub
	Logger          *slog.Logger
	ProjectRoot     string
	DefinitionsRoot string
	Config          *policy.Config
	// ToolNames lists the registered tools, for GET /v1/tools.
	ToolNames []string
	MCP       *mcp.Manager
	// APIKey, when non-empty, is required on every request except the health
	// probe. The supervisor (kodeblue) mints one per start so another local
	// process that can reach this loopback port cannot drive its sessions.
	APIKey string
}

// RunOptions carries per-message overrides for the agent loop.
type RunOptions struct {
	Resume       bool   // Explicit user input resumes delivery atomically with enqueue.
	SteerNow     bool   // Interrupt the current turn after accepting the new input.
	RejectIfBusy bool   // Compatibility for callers that cannot track queued acceptance.
	Model        string // Override model for this run (empty = use session default)
	Provider     string // Override provider for this run (empty = use session default)
	// ReasoningEffort overrides the OpenAI reasoning_effort for this run
	// (none/minimal/low/medium/high). Empty = provider/model default.
	ReasoningEffort string
	// PersistUserMessage, when set by the durable queue coordinator, atomically
	// persists the user turn and finalizes its queue claim at the dispatch
	// boundary. Other internal callers use the ordinary message repository.
	PersistUserMessage   func(*internal.Message) error
	PersistedUserMessage *internal.Message
	// InputSource controls system-owned capabilities. Interactive API messages
	// use direct_message; scheduled and background runs use non-interactive tags.
	InputSource string
	QuestionID  string
}

type CompactionSummaryResult struct {
	Content string                 `json:"content"`
	Model   string                 `json:"model,omitempty"`
	Usage   *internal.MessageUsage `json:"usage,omitempty"`
}

// CompactResult contains the outcome of a manual session compaction request.
type CompactResult struct {
	Compacted          bool                     `json:"compacted"`
	BeforeActive       int                      `json:"before_active"`
	AfterActive        int                      `json:"after_active"`
	TotalHistory       int                      `json:"total_history"`
	InputTokens        int64                    `json:"input_tokens"`
	AfterInputTokens   int64                    `json:"after_input_tokens,omitempty"`
	ContextWindow      int64                    `json:"context_window,omitempty"`
	CompactedMessages  int                      `json:"compacted_messages,omitempty"`
	SummaryInputTokens int64                    `json:"summary_input_tokens,omitempty"`
	UsedLLMSummary     bool                     `json:"used_llm_summary,omitempty"`
	UsedFallback       bool                     `json:"used_fallback,omitempty"`
	Summary            *CompactionSummaryResult `json:"summary,omitempty"`
}

type AgentLoopInterface interface {
	RunAsync(sessionID, runID string, message string, attachments []internal.Attachment, opts RunOptions) error
	// CompactSession compacts a session's history outside a run. It returns
	// an error wrapping ErrSessionBusy when a run holds the session, and
	// stops (keeping the history) when ctx is cancelled.
	CompactSession(ctx context.Context, sessionID string, opts RunOptions) (CompactResult, error)
	Abort(runID string) bool
	Interrupt(runID string) bool
	IsRunning(runID string) bool
}

type QueueSubmitResult struct {
	Status    string              `json:"status"`
	SessionID internal.SessionID  `json:"session_id"`
	RunID     internal.RunID      `json:"run_id,omitempty"`
	Item      *internal.QueueItem `json:"queue_item,omitempty"`
	// Error explains a "paused" status: the queued input cannot be delivered.
	Error string `json:"error,omitempty"`
}

type QueueActionResult struct {
	Status       string         `json:"status"`
	RunID        internal.RunID `json:"run_id,omitempty"`
	PendingCount int            `json:"pending_count"`
}

// SessionMessageQueueInterface is implemented by the server's durable
// per-session inbox coordinator. HTTP handlers depend on the interface so the
// ordering and steer semantics can be exercised without starting a provider.
type SessionMessageQueueInterface interface {
	SubmitUser(sessionID internal.SessionID, content, clientMessageID string, attachments []internal.Attachment, opts RunOptions) (QueueSubmitResult, error)
	RemoveQueuedUser(sessionID internal.SessionID, itemID internal.QueueItemID) (bool, error)
	UpdateQueuedUser(sessionID internal.SessionID, itemID internal.QueueItemID, content, expectedContent string) (bool, error)
	Steer(sessionID internal.SessionID) (QueueActionResult, error)
	Continue(sessionID internal.SessionID) (QueueActionResult, error)
	Pause(sessionID internal.SessionID) error
}

func NewRouter(deps *Dependencies) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", handleHealth(deps))
	mux.HandleFunc("GET /v1/build-info", handleBuildInfo(deps))
	mux.HandleFunc("GET /v1/tools", handleListTools(deps))
	mux.HandleFunc("GET /v1/providers/models", handleListProviderModels(deps))
	mux.HandleFunc("GET /v1/mcp/servers", handleListMCPServers(deps))

	// Sessions and their messages, queue, state and history
	mux.HandleFunc("POST /v1/sessions", handleCreateSession(deps))
	mux.HandleFunc("GET /v1/sessions/{id}", handleGetSession(deps))
	mux.HandleFunc("GET /v1/sessions", handleListSessions(deps))
	mux.HandleFunc("POST /v1/sessions/{id}/messages", handleSendMessage(deps))
	mux.HandleFunc("GET /v1/sessions/{id}/messages", handleGetSessionMessages(deps))
	mux.HandleFunc("GET /v1/sessions/{id}/queue", handleGetSessionQueue(deps))
	mux.HandleFunc("DELETE /v1/sessions/{id}/queue/{itemId}", handleRemoveSessionQueueItem(deps))
	mux.HandleFunc("PATCH /v1/sessions/{id}/queue/{itemId}", handleUpdateSessionQueueItem(deps))
	mux.HandleFunc("POST /v1/sessions/{id}/queue/steer", handleSteerSessionQueue(deps))
	mux.HandleFunc("POST /v1/sessions/{id}/queue/continue", handleContinueSessionQueue(deps))
	mux.HandleFunc("POST /v1/sessions/{id}/compact", handleCompactSession(deps))
	mux.HandleFunc("GET /v1/sessions/{id}/status", handleGetSessionStatus(deps))
	mux.HandleFunc("GET /v1/sessions/{id}/state", handleGetSessionState(deps))
	mux.HandleFunc("GET /v1/sessions/{id}/pending", handleGetSessionPending(deps))
	mux.HandleFunc("DELETE /v1/sessions/{id}/pending/questions/{questionId}", handleIgnorePendingQuestion(deps))
	mux.HandleFunc("POST /v1/sessions/{id}/abort", handleAbort(deps))
	mux.HandleFunc("GET /v1/sessions/{id}/events/history", handleGetSessionEventHistory(deps))
	mux.HandleFunc("GET /v1/sessions/{id}/runs/{runId}/outcome", handleGetRunOutcome(deps))
	mux.HandleFunc("POST /v1/questions/{questionId}/answer", handleQuestionAnswer(deps))

	// Agent definitions
	mux.HandleFunc("GET /v1/agents", handleListAgents(deps))
	mux.HandleFunc("POST /v1/agents", handleCreateAgent(deps))
	mux.HandleFunc("GET /v1/agents/{agentId}", handleGetAgent(deps))
	mux.HandleFunc("PATCH /v1/agents/{agentId}", handleUpdateAgent(deps))
	mux.HandleFunc("DELETE /v1/agents/{agentId}", handleDeleteAgent(deps))

	// Definitions (the agents' knowledge base)
	mux.HandleFunc("GET /v1/definitions", handleListDefinitions(deps))
	mux.HandleFunc("POST /v1/definitions", handleCreateDefinition(deps))
	mux.HandleFunc("GET /v1/definitions/{id}", handleGetDefinition(deps))
	mux.HandleFunc("PUT /v1/definitions/{id}", handleUpdateDefinition(deps))
	mux.HandleFunc("DELETE /v1/definitions/{id}", handleDeleteDefinition(deps))

	return withMiddleware(mux, deps.Logger, deps.APIKey)
}

func withMiddleware(next http.Handler, logger *slog.Logger, apiKey string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if value := recover(); value != nil {
				if value == http.ErrAbortHandler {
					panic(value)
				}
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
			}
		}()
		w.Header().Set("Content-Type", "application/json")
		logger.Info("request", "method", r.Method, "path", r.URL.Path)
		// /v1/health stays open: it is a liveness probe carrying no session data,
		// and the supervisor polls it before it could know the key took effect.
		if apiKey != "" && r.URL.Path != "/v1/health" && !requestAuthorized(r, apiKey) {
			writeError(w, http.StatusUnauthorized, "missing or invalid API key")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requestAuthorized accepts the instance key as a Bearer token, an X-API-Key
// header, or an api_key query parameter (the latter for WebSocket/SSE clients
// that cannot set headers). Comparisons are constant-time.
func requestAuthorized(r *http.Request, apiKey string) bool {
	candidates := make([]string, 0, 3)
	if auth := r.Header.Get("Authorization"); auth != "" {
		if token, ok := strings.CutPrefix(auth, "Bearer "); ok {
			candidates = append(candidates, token)
		}
	}
	if header := r.Header.Get("X-API-Key"); header != "" {
		candidates = append(candidates, header)
	}
	if query := r.URL.Query().Get("api_key"); query != "" {
		candidates = append(candidates, query)
	}
	for _, candidate := range candidates {
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(apiKey)) == 1 {
			return true
		}
	}
	return false
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

// writeStoreError turns a repository failure into a response the caller can act
// on. A database-busy failure means another engine process sharing this file
// won the write race — the request is worth retrying, so it gets a 503 and
// Retry-After rather than a 500 that reads as a bug. Every other failure keeps
// its status but now carries the underlying error: these endpoints are
// loopback-only and API-key gated, and "failed to update agent" with the cause
// thrown away was undiagnosable from a bug report.
func writeStoreError(w http.ResponseWriter, logger *slog.Logger, status int, message string, err error) {
	if logger != nil {
		logger.Error(message, "error", err)
	}
	if state.IsBusyErr(err) {
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusServiceUnavailable,
			message+": database is busy (another engine instance holds the write lock); retry")
		return
	}
	writeError(w, status, message+": "+err.Error())
}

func readJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(v)
}
