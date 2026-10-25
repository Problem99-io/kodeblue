package openai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Problem99-io/kodeblue/internal"
	"github.com/Problem99-io/kodeblue/internal/provider"
)

const defaultBaseURL = "https://api.openai.com"

// Client implements provider.Provider for the OpenAI Chat Completions API.
type Client struct {
	apiKey                 string
	model                  string
	httpClient             *http.Client
	baseURL                string
	name                   string
	supportsPromptCacheKey bool
	chatCompletionsPath    string
	modelsPath             string
	authHeaderName         string
	authHeaderValuePrefix  string
	// cacheCaps is the per-model prompt-cache capability published by the
	// gateway; nil when it publishes none.
	cacheCaps map[string]CacheCaps

	// The model catalog, kept for modelsTTL: context windows are read from
	// it on every turn, and a catalog like OpenRouter's is hundreds of models.
	// modelsMu guards the cache only, never the request: one fetch is in
	// flight at a time (modelsCall). A caller with an expired catalog gets it
	// at once while the fetch refreshes it; a caller with none waits on the
	// fetch under its own context.
	modelsMu   sync.Mutex
	modelsAt   time.Time
	modelsOut  *modelsResponse
	modelsErr  error
	modelsRest time.Time // no new fetch before this, after a failure
	modelsCall *modelsFetch
}

// modelsTTL bounds how stale a catalog value (a context window) may be.
const modelsTTL = time.Minute

// Variables rather than constants so tests can shorten them.
var (
	// modelsFetchTimeout bounds one catalog request, whoever is waiting on
	// it. Run start and compaction read the catalog, so a gateway whose
	// /v1/models hangs must not hold them for the transport's two-minute
	// header timeout.
	modelsFetchTimeout = 15 * time.Second
	// modelsFailTTL is how long a catalog fetch that timed out is remembered
	// before it is retried, so a hanging catalog costs one timeout, not one
	// per caller.
	modelsFailTTL = 30 * time.Second
	// modelsQuickFailTTL is the same for a fetch that failed fast (an HTTP
	// error, a refused connection): retrying is cheap and the failure is
	// often transient, and a run reads the context window only at its start.
	modelsQuickFailTTL = 2 * time.Second
)

// modelsFetch is one in-flight catalog request; done closes when out/err are
// set. It carries the timings it was started with.
type modelsFetch struct {
	done                           chan struct{}
	out                            *modelsResponse
	err                            error
	timeout, failTTL, quickFailTTL time.Duration
}

// ClientOptions customizes endpoint and auth settings for OpenAI-compatible backends.
type ClientOptions struct {
	BaseURL                string
	Name                   string
	SupportsPromptCacheKey bool
	ChatCompletionsPath    string
	ModelsPath             string
	AuthHeaderName         string
	AuthHeaderValuePrefix  string
	// CacheCaps carries the gateway's per-model cache capabilities (from
	// /v1/models). When set, the client places cache markers.
	CacheCaps map[string]CacheCaps
}

// NewClient creates a new OpenAI provider client.
func NewClient(apiKey, model string) *Client {
	return NewClientWithOptions(apiKey, model, defaultBaseURL, "openai")
}

// NewClientWithOptions creates a client with a custom base URL and name.
// Used for OpenAI-compatible APIs like vLLM.
func NewClientWithOptions(apiKey, model, baseURL, name string) *Client {
	return NewClientWithAdvancedOptions(apiKey, model, ClientOptions{
		BaseURL:                baseURL,
		Name:                   name,
		SupportsPromptCacheKey: name == "openai",
		ChatCompletionsPath:    "/v1/chat/completions",
		ModelsPath:             "/v1/models",
		AuthHeaderName:         "Authorization",
		AuthHeaderValuePrefix:  "Bearer ",
	})
}

// NewClientWithAdvancedOptions creates a client with custom endpoint and auth settings.
func NewClientWithAdvancedOptions(apiKey, model string, opts ClientOptions) *Client {
	transport := &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: responseHeaderTimeout(),
		IdleConnTimeout:       90 * time.Second,
	}
	if opts.BaseURL == "" {
		opts.BaseURL = defaultBaseURL
	}
	if opts.Name == "" {
		opts.Name = "openai"
	}
	if opts.ChatCompletionsPath == "" {
		opts.ChatCompletionsPath = "/v1/chat/completions"
	}
	if opts.AuthHeaderName == "" {
		opts.AuthHeaderName = "Authorization"
	}
	if opts.AuthHeaderValuePrefix == "" {
		opts.AuthHeaderValuePrefix = "Bearer "
	}
	return &Client{
		apiKey:                 apiKey,
		model:                  model,
		httpClient:             &http.Client{Transport: transport, CheckRedirect: sameOriginRedirectsOnly},
		baseURL:                opts.BaseURL,
		name:                   opts.Name,
		supportsPromptCacheKey: opts.SupportsPromptCacheKey,
		chatCompletionsPath:    opts.ChatCompletionsPath,
		modelsPath:             opts.ModelsPath,
		authHeaderName:         opts.AuthHeaderName,
		authHeaderValuePrefix:  opts.AuthHeaderValuePrefix,
		cacheCaps:              opts.CacheCaps,
	}
}

// sameOriginRedirectsOnly keeps every request on the configured endpoint's
// origin. Requests carry the gateway key (possibly under a custom header the
// standard library does not strip) and the full conversation body, so a
// redirect to another host or a scheme downgrade is refused instead of
// followed. Same-origin redirects keep the standard library's limit of 10.
func sameOriginRedirectsOnly(req *http.Request, via []*http.Request) error {
	if len(via) == 0 {
		return nil
	}
	origin := via[0].URL
	if !strings.EqualFold(req.URL.Scheme, origin.Scheme) || !strings.EqualFold(req.URL.Host, origin.Host) {
		return fmt.Errorf("refusing redirect from %s://%s to %s://%s", origin.Scheme, origin.Host, req.URL.Scheme, req.URL.Host)
	}
	if len(via) >= 10 {
		return fmt.Errorf("stopped after 10 redirects")
	}
	return nil
}

// responseHeaderTimeout allows an operator to accommodate slow local inference
// without disabling deadlines or changing the normal two-minute default.
func responseHeaderTimeout() time.Duration {
	d, err := time.ParseDuration(strings.TrimSpace(os.Getenv("KODEBLUE_PROVIDER_RESPONSE_HEADER_TIMEOUT")))
	if err != nil || d < time.Second || d > 2*time.Hour {
		return 120 * time.Second
	}
	return d
}

func (c *Client) Name() string { return c.name }

func (c *Client) DefaultModel() string { return c.model }

func (c *Client) ContextWindow(ctx context.Context, model string) (int64, error) {
	resolvedModel := strings.TrimSpace(model)
	if resolvedModel == "" {
		resolvedModel = c.model
	}
	if resolvedModel == "" {
		return 0, fmt.Errorf("model is required")
	}

	if window, ok := c.ReportedContextWindow(ctx, resolvedModel); ok {
		return window, nil
	}
	return provider.GetContextWindow(resolvedModel), nil
}

// ReportedContextWindow returns the context window the gateway catalog
// currently reports for the model, and whether the catalog actually carried a
// positive value. The catalog is re-read once modelsTTL has passed, so an admin
// edit to a model's context window in the gateway takes effect within a minute
// without a restart.
//
// Unlike ContextWindow it performs NO built-in fallback: a false return means the
// catalog does not report a window for this model. Callers making safety
// decisions (the model-switch safeguard) rely on that distinction so they never
// block on the conservative default guess.
func (c *Client) ReportedContextWindow(ctx context.Context, model string) (int64, bool) {
	resolvedModel := strings.TrimSpace(model)
	if resolvedModel == "" {
		resolvedModel = c.model
	}
	if resolvedModel == "" {
		return 0, false
	}

	modelsPath := strings.TrimSpace(c.modelsPath)
	if modelsPath == "" || !strings.Contains(modelsPath, "provider=") {
		return 0, false
	}

	out, err := c.getModelsResponse(ctx)
	if err != nil {
		return 0, false
	}
	for i := range out.Data {
		if strings.TrimSpace(out.Data[i].ID) != resolvedModel {
			continue
		}
		if window := out.Data[i].ContextWindow(); window > 0 {
			return window, true
		}
		break
	}
	return 0, false
}

func (c *Client) Models(ctx context.Context) ([]string, error) {
	if strings.TrimSpace(c.modelsPath) == "" {
		if c.model == "" {
			return nil, fmt.Errorf("model listing unavailable")
		}
		return []string{c.model}, nil
	}

	out, err := c.getModelsResponse(ctx)
	if err != nil {
		return nil, err
	}

	models := make([]string, 0, len(out.Data))
	for i := range out.Data {
		id := strings.TrimSpace(out.Data[i].ID)
		if id != "" {
			models = append(models, id)
		}
	}
	if len(models) == 0 {
		return nil, fmt.Errorf("openai models response is empty")
	}
	sort.Strings(models)
	return models, nil
}

type modelsResponse struct {
	Data []modelCard `json:"data"`
}

type modelCard struct {
	ID                    string         `json:"id"`
	MaxModelLen           int64          `json:"max_model_len,omitempty"`
	ContextLength         int64          `json:"context_length,omitempty"`
	ReportedContextWindow int64          `json:"context_window,omitempty"`
	Metadata              map[string]any `json:"metadata,omitempty"`
}

func (m modelCard) ContextWindow() int64 {
	if m.MaxModelLen > 0 {
		return m.MaxModelLen
	}
	if m.ContextLength > 0 {
		return m.ContextLength
	}
	if m.ReportedContextWindow > 0 {
		return m.ReportedContextWindow
	}
	if len(m.Metadata) == 0 {
		return 0
	}
	for _, key := range []string{"max_model_len", "context_length", "context_window"} {
		if value, ok := m.Metadata[key]; ok {
			if parsed := parseContextWindowValue(value); parsed > 0 {
				return parsed
			}
		}
	}
	return 0
}

func parseContextWindowValue(value any) int64 {
	switch v := value.(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	case int:
		return int64(v)
	case json.Number:
		parsed, _ := v.Int64()
		return parsed
	case string:
		var parsed int64
		_, _ = fmt.Sscan(strings.TrimSpace(v), &parsed)
		return parsed
	default:
		return 0
	}
}

func (c *Client) getModelsResponse(ctx context.Context) (*modelsResponse, error) {
	if strings.TrimSpace(c.modelsPath) == "" {
		return nil, fmt.Errorf("models endpoint unavailable")
	}
	c.modelsMu.Lock()
	out := c.modelsOut
	if out != nil && time.Since(c.modelsAt) < modelsTTL {
		c.modelsMu.Unlock()
		return out, nil
	}
	call := c.modelsCall
	if call == nil {
		if time.Now().Before(c.modelsRest) {
			err := c.modelsErr
			c.modelsMu.Unlock()
			if out != nil {
				return out, nil
			}
			return nil, err
		}
		call = &modelsFetch{done: make(chan struct{}), timeout: modelsFetchTimeout, failTTL: modelsFailTTL, quickFailTTL: modelsQuickFailTTL}
		c.modelsCall = call
		go c.runModelsFetch(call)
	}
	c.modelsMu.Unlock()

	// An expired catalog is still the best answer there is: serve it now and
	// let the fetch refresh it, rather than hold a run start behind a slow
	// or hanging gateway.
	if out != nil {
		return out, nil
	}
	select {
	case <-call.done:
		return call.out, call.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// runModelsFetch performs one catalog request on behalf of every waiting
// caller. It runs detached from any caller's context, so one caller giving up
// does not fail the others; modelsFetchTimeout bounds it instead.
func (c *Client) runModelsFetch(call *modelsFetch) {
	ctx, cancel := context.WithTimeout(context.Background(), call.timeout)
	defer cancel()
	out, err := c.fetchModels(ctx)

	c.modelsMu.Lock()
	if err != nil {
		rest := call.quickFailTTL
		if ctx.Err() != nil {
			rest = call.failTTL
		}
		slog.Warn("model catalog fetch failed", "provider", c.name, "error", err, "retry_after", rest, "serving_stale", c.modelsOut != nil)
		c.modelsErr, c.modelsRest = err, time.Now().Add(rest)
		call.out, call.err = c.modelsOut, err
		if call.out != nil {
			call.err = nil
		}
	} else {
		c.modelsAt, c.modelsOut, c.modelsErr = time.Now(), out, nil
		call.out = out
	}
	c.modelsCall = nil
	c.modelsMu.Unlock()
	close(call.done)
}

func (c *Client) fetchModels(ctx context.Context) (*modelsResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+c.modelsPath, nil)
	if err != nil {
		return nil, err
	}
	c.applyRequestHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("openai models API error %d: %s", resp.StatusCode, string(b))
	}

	var out modelsResponse
	decoder := json.NewDecoder(resp.Body)
	decoder.UseNumber()
	if err := decoder.Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CountTokens asks the vendor for request usage instead of using a local estimate.
func (c *Client) CountTokens(ctx context.Context, req *provider.Request) (*provider.Usage, error) {
	body, err := c.buildCountRequestBody(req)
	if err != nil {
		return nil, fmt.Errorf("openai: build count request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+c.chatCompletionsPath, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("openai: create count request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	c.applyRequestHeaders(httpReq)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("openai: send count request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("openai: count API error %d: %s", resp.StatusCode, string(errBody))
	}

	var out chatCompletionResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("openai: decode count response: %w", err)
	}
	if out.Usage == nil {
		return nil, fmt.Errorf("openai: count response missing usage")
	}

	u := &provider.Usage{
		InputTokens:  out.Usage.PromptTokens,
		OutputTokens: out.Usage.CompletionTokens,
	}
	if out.Usage.PromptTokensDetails != nil {
		u.InputTokens -= out.Usage.PromptTokensDetails.CachedTokens
		u.InputTokens -= out.Usage.PromptTokensDetails.CacheWriteTokens
		u.CacheCreationInputTokens = out.Usage.PromptTokensDetails.CacheWriteTokens
		u.CacheReadInputTokens = out.Usage.PromptTokensDetails.CachedTokens
	}
	return u, nil
}

// --- OpenAI API request types ---

type apiRequest struct {
	Model                string           `json:"model"`
	Messages             []apiMessage     `json:"messages"`
	Tools                []apiTool        `json:"tools,omitempty"`
	CacheControl         *apiCacheControl `json:"cache_control,omitempty"`
	PromptCacheKey       string           `json:"prompt_cache_key,omitempty"`
	PromptCacheRetention string           `json:"prompt_cache_retention,omitempty"`
	// SessionID is OpenRouter's sticky-routing key; a gateway may strip it
	// for every other route.
	SessionID           string       `json:"session_id,omitempty"`
	Stream              bool         `json:"stream"`
	StreamOptions       *streamOpts  `json:"stream_options,omitempty"`
	MaxTokens           int          `json:"max_tokens,omitempty"`
	MaxCompletionTokens int          `json:"max_completion_tokens,omitempty"`
	Temperature         float64      `json:"temperature,omitempty"`
	ReasoningEffort     string       `json:"reasoning_effort,omitempty"`
	Thinking            *apiThinking `json:"thinking,omitempty"`
	Stop                []string     `json:"stop,omitempty"`
	// Usage asks OpenRouter to report each call's cost (usage.cost).
	Usage *apiUsageOpts `json:"usage,omitempty"`
}

type apiUsageOpts struct {
	Include bool `json:"include"`
}

// apiThinking is the top-level thinking-mode control, distinct from OpenAI's
// reasoning_effort field. Moonshot/Kimi uses it on the k2.x family (and only
// honours reasoning_effort on k3); DeepSeek accepts it alongside
// reasoning_effort. See kimiReasoningForModel and deepseekReasoning.
type apiThinking struct {
	Type string `json:"type,omitempty"` // "enabled" | "disabled"
	Keep string `json:"keep,omitempty"` // "all" to preserve reasoning across turns
}

type apiCacheControl struct {
	Type string `json:"type"`
	TTL  string `json:"ttl,omitempty"`
}

type streamOpts struct {
	IncludeUsage bool `json:"include_usage"`
}

type apiMessage struct {
	Role             string      `json:"role"`
	Content          interface{} `json:"content,omitempty"`
	ReasoningContent string      `json:"reasoning_content,omitempty"`
	// ReasoningDetails is replayed verbatim (OpenRouter contract): the array
	// is exactly what the route returned for this assistant turn, unmodified.
	ReasoningDetails json.RawMessage `json:"reasoning_details,omitempty"`
	ToolCalls        []apiToolCall   `json:"tool_calls,omitempty"`
	ToolCallID       string          `json:"tool_call_id,omitempty"`
}

// contentPart represents a multi-modal content part for OpenAI.
type contentPart struct {
	Type     string       `json:"type"`
	Text     string       `json:"text,omitempty"`
	ImageURL *imageURL    `json:"image_url,omitempty"`
	File     *fileContent `json:"file,omitempty"`
	// CacheControl is the neutral cache marker (see cache_markers.go).
	CacheControl *apiCacheControl `json:"cache_control,omitempty"`
}

type imageURL struct {
	URL string `json:"url"`
}

// fileContent is the OpenAI/OpenRouter standard "file" content part used for
// documents such as PDF, DOCX, and spreadsheets. FileData is a base64 data URL
// of the form "data:<media_type>;base64,<data>".
type fileContent struct {
	Filename string `json:"filename,omitempty"`
	FileData string `json:"file_data,omitempty"`
}

type apiToolCall struct {
	ID       string      `json:"id"`
	Type     string      `json:"type"`
	Function apiFunction `json:"function"`
}

type apiFunction struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type apiTool struct {
	Type     string          `json:"type"`
	Function apiToolFunction `json:"function"`
}

type apiToolFunction struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"`
}

// --- OpenAI SSE response types ---

type chatChunk struct {
	ID      string          `json:"id"`
	Choices []chunkChoice   `json:"choices"`
	Usage   *chunkUsage     `json:"usage,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

type chatCompletionResponse struct {
	Usage *chunkUsage `json:"usage,omitempty"`
}

type chunkChoice struct {
	Index        int        `json:"index"`
	Delta        chunkDelta `json:"delta"`
	FinishReason *string    `json:"finish_reason"`
}

type chunkDelta struct {
	Role             string          `json:"role,omitempty"`
	Content          string          `json:"content,omitempty"`
	Reasoning        json.RawMessage `json:"reasoning,omitempty"`
	ReasoningContent json.RawMessage `json:"reasoning_content,omitempty"`
	ReasoningDetails json.RawMessage `json:"reasoning_details,omitempty"`
	ToolCalls        []deltaToolCall `json:"tool_calls,omitempty"`
}

type deltaToolCall struct {
	Index    int       `json:"index"`
	ID       string    `json:"id,omitempty"`
	Type     string    `json:"type,omitempty"`
	Function deltaFunc `json:"function"`
}

type deltaFunc struct {
	Name      string `json:"name,omitempty"`
	Arguments string `json:"arguments,omitempty"`
}

type chunkUsage struct {
	PromptTokens        int64              `json:"prompt_tokens"`
	CompletionTokens    int64              `json:"completion_tokens"`
	PromptTokensDetails *promptTokenDetail `json:"prompt_tokens_details,omitempty"`
	Billing             *usageBilling      `json:"billing,omitempty"`
	// Cost is OpenRouter's charge for the call in USD (usage accounting).
	Cost float64 `json:"cost,omitempty"`
}

type promptTokenDetail struct {
	CachedTokens     int64 `json:"cached_tokens"`
	CacheWriteTokens int64 `json:"cache_write_tokens,omitempty"`
}

type usageBilling struct {
	RequestID            string  `json:"request_id,omitempty"`
	InputCostUSD         float64 `json:"input_cost_usd"`
	OutputCostUSD        float64 `json:"output_cost_usd"`
	CacheCreationCostUSD float64 `json:"cache_creation_cost_usd"`
	CacheReadCostUSD     float64 `json:"cache_read_cost_usd"`
	// The relay no longer publishes the vendor cost beneath its price — that
	// difference is the platform's margin — so there is no raw total to decode.
	BilledTotalUSD float64 `json:"billed_total_usd"`
}

// toolAcc accumulates streamed tool call arguments.
type toolAcc struct {
	id   string
	name string
	args strings.Builder
}

// Stream sends a request to OpenAI and returns a channel of normalized events.
func (c *Client) Stream(ctx context.Context, req *provider.Request) (<-chan provider.StreamEvent, error) {
	body, err := c.buildRequestBody(req)
	if err != nil {
		return nil, fmt.Errorf("openai: build request: %w", err)
	}

	resp, err := provider.Send(ctx, provider.RetryOptions{
		Provider: "openai",
		Client:   c.httpClient,
		NewRequest: func(reqCtx context.Context) (*http.Request, error) {
			httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, c.baseURL+c.chatCompletionsPath, bytes.NewReader(body))
			if err != nil {
				return nil, fmt.Errorf("openai: create request: %w", err)
			}
			httpReq.Header.Set("Content-Type", "application/json")
			c.applyRequestHeaders(httpReq)
			return httpReq, nil
		},
		OnFailureResponse: func(failed *http.Response, errBody []byte, willRetry bool) {
			detail := string(errBody)
			if len(detail) > 1024 {
				detail = detail[:1024]
			}
			slog.Warn("model request failed", "provider", c.name, "status", failed.StatusCode, "will_retry", willRetry, "body", detail)
		},
		OnRetry: func(attempt, status int, delay time.Duration, cause error) {
			slog.Info("retrying model request", "provider", c.name, "attempt", attempt, "status", status, "error", cause, "delay", delay)
		},
	})
	if err != nil {
		return nil, err
	}

	ch := make(chan provider.StreamEvent, 32)
	go c.parseSSE(ctx, resp, ch)
	return ch, nil
}

func (c *Client) buildRequestBody(req *provider.Request) ([]byte, error) {
	ar := c.buildAPIRequest(req, true, req.MaxTokens)
	return json.Marshal(ar)
}

func (c *Client) buildCountRequestBody(req *provider.Request) ([]byte, error) {
	ar := c.buildAPIRequest(req, false, 1)
	return json.Marshal(ar)
}

func (c *Client) buildAPIRequest(req *provider.Request, stream bool, maxTokens int) apiRequest {
	ar := apiRequest{
		Model:  req.Model,
		Stream: stream,
		Stop:   req.StopSequences,
	}
	if req.Temperature != 0 && !c.forcesDefaultTemperature() {
		ar.Temperature = req.Temperature
	}
	if ar.Model == "" {
		ar.Model = c.model
	}
	// Reasoning control. For Kimi providers the selected mode is mapped to the
	// correct per-model API parameter (k3 → reasoning_effort, k2.x → thinking
	// object); see kimiReasoningForModel. DeepSeek accepts its own effort vocabulary, so the
	// requested level is translated rather than forwarded; see deepseekReasoning.
	// All other providers keep the generic per-request reasoning_effort
	// passthrough.
	switch {
	case c.isKimiProvider():
		ar.ReasoningEffort, ar.Thinking = kimiReasoningForModel(ar.Model, strings.TrimSpace(req.ReasoningEffort))
	case c.isDeepSeekProvider():
		ar.ReasoningEffort, ar.Thinking = deepseekReasoning(req.ReasoningEffort)
	case req.ReasoningEffort != "":
		ar.ReasoningEffort = req.ReasoningEffort
	}
	if stream {
		ar.StreamOptions = &streamOpts{IncludeUsage: true}
	}
	if c.name == "openrouter" {
		ar.Usage = &apiUsageOpts{Include: true}
	}
	cacheCaps, cachePublished := c.cacheCapsFor(ar.Model)
	if c.supportsPromptCacheKey && strings.TrimSpace(req.PromptCacheKey) != "" {
		ar.PromptCacheKey = strings.TrimSpace(req.PromptCacheKey)
		if cachePublished {
			ar.SessionID = ar.PromptCacheKey
		}
	}
	// Legacy fallback for gateways that publish no cache capabilities: the
	// top-level automatic switch for Claude. Block markers replace it otherwise.
	if !cachePublished && c.shouldUseAnthropicOpenRouterPromptCache(ar.Model) {
		ar.CacheControl = &apiCacheControl{Type: "ephemeral"}
	}
	if maxTokens > 0 {
		if usesMaxCompletionTokens(ar.Model) {
			ar.MaxCompletionTokens = maxTokens
		} else {
			ar.MaxTokens = maxTokens
		}
	}

	if req.SystemPrompt != "" {
		ar.Messages = append(ar.Messages, apiMessage{
			Role:    "system",
			Content: req.SystemPrompt,
		})
	}

	var cacheAnchors []int
	for index, m := range req.Messages {
		converted := convertMessage(m)
		if c.reasoningReplayForbidden() {
			for i := range converted {
				converted[i].ReasoningContent = ""
			}
		}
		ar.Messages = append(ar.Messages, converted...)
		if containsInt(req.CacheAnchors, index) && len(converted) > 0 {
			cacheAnchors = append(cacheAnchors, len(ar.Messages)-1)
		}
	}
	if cachePublished {
		applyCacheMarkers(ar.Messages, cacheCaps, cacheAnchors)
	}

	for _, t := range req.Tools {
		params := t.Parameters
		if params == nil {
			params = json.RawMessage(`{"type":"object"}`)
		}
		ar.Tools = append(ar.Tools, apiTool{
			Type: "function",
			Function: apiToolFunction{
				Name:        string(t.Name),
				Description: t.Description,
				Parameters:  params,
			},
		})
	}

	return ar
}

func usesMaxCompletionTokens(model string) bool {
	model = strings.ToLower(strings.TrimSpace(model))
	return strings.HasPrefix(model, "gpt-5")
}

func (c *Client) shouldUseAnthropicOpenRouterPromptCache(model string) bool {
	if c.name != "anthropic" && c.name != "openrouter" {
		return false
	}
	return isAnthropicClaudeModel(model)
}

func isAnthropicClaudeModel(model string) bool {
	trimmed := strings.ToLower(strings.TrimSpace(model))
	if trimmed == "" {
		return false
	}
	if namespace, downstream, ok := strings.Cut(trimmed, "/"); ok {
		if namespace != "anthropic" {
			return false
		}
		trimmed = downstream
	}
	return strings.HasPrefix(trimmed, "claude-")
}

// convertMessage converts an internal Message to one or more OpenAI API messages.
// Tool results may expand to multiple messages since OpenAI requires one per tool_call_id.
func convertMessage(m internal.Message) []apiMessage {
	if len(m.ToolResults) > 0 {
		msgs := make([]apiMessage, 0, len(m.ToolResults))
		for _, tr := range m.ToolResults {
			msgs = append(msgs, apiMessage{
				Role:       "tool",
				Content:    tr.Content,
				ToolCallID: tr.ToolCallID,
			})
		}
		// Keep every outstanding tool result adjacent before sending images in
		// a user content message, the existing supported multimodal transport.
		if len(m.Attachments) > 0 {
			msgs = append(msgs, convertMessage(internal.Message{Role: "user", Content: "Images returned by the tools above.", Attachments: m.Attachments})...)
		}
		return msgs
	}

	if len(m.ToolCalls) > 0 {
		tcs := make([]apiToolCall, len(m.ToolCalls))
		for i, tc := range m.ToolCalls {
			tcs[i] = apiToolCall{
				ID:   tc.ID,
				Type: "function",
				Function: apiFunction{
					Name: string(tc.Name),
					// Guard against replaying a truncated tool-call arguments
					// blob: OpenAI-compatible providers (xAI/Grok) 400 the whole
					// request with "EOF while parsing a string", wedging the
					// conversation. See provider.SanitizeToolArguments.
					Arguments: string(provider.SanitizeToolArguments(tc.Arguments)),
				},
			}
		}
		return []apiMessage{{
			Role:             "assistant",
			Content:          m.Content,
			ReasoningContent: m.ReasoningContent,
			ReasoningDetails: m.ReasoningDetails,
			ToolCalls:        tcs,
		}}
	}

	// If message has attachments, build multi-part content
	if len(m.Attachments) > 0 {
		parts := make([]contentPart, 0, 1+len(m.Attachments))
		if m.Content != "" {
			parts = append(parts, contentPart{Type: "text", Text: m.Content})
		}
		// Attachment payloads are not persisted (see marshalAttachmentsForStorage),
		// so a replayed turn carries descriptors with no bytes. Name them in text
		// rather than dropping them silently — otherwise a follow-up question
		// about "the screenshot" has no referent at all.
		var dropped []string
		var disabled []string
		for _, att := range m.Attachments {
			if provider.IsDisabledAttachment(att) {
				disabled = append(disabled, attachmentLabel(att))
				continue
			}
			if strings.HasPrefix(att.MediaType, "image/") {
				url := att.URL
				if url == "" && att.Data != "" {
					url = "data:" + att.MediaType + ";base64," + att.Data
				}
				if url != "" {
					parts = append(parts, contentPart{
						Type:     "image_url",
						ImageURL: &imageURL{URL: url},
					})
				} else {
					dropped = append(dropped, attachmentLabel(att))
				}
				continue
			}
			// Non-image files (PDF, DOCX, spreadsheets, etc.) use the
			// OpenAI/OpenRouter "file" content part with a base64 data URL.
			fileData := att.URL
			if fileData == "" && att.Data != "" {
				fileData = "data:" + att.MediaType + ";base64," + att.Data
			}
			if fileData == "" {
				dropped = append(dropped, attachmentLabel(att))
				continue
			}
			filename := att.FileName
			if filename == "" {
				filename = "file"
			}
			parts = append(parts, contentPart{
				Type: "file",
				File: &fileContent{Filename: filename, FileData: fileData},
			})
		}
		if len(disabled) > 0 {
			parts = append(parts, contentPart{
				Type: "text",
				Text: "[" + provider.AttachmentDisabledReason + ", so these were not sent: " + strings.Join(disabled, ", ") + "]",
			})
		}
		if len(dropped) > 0 {
			parts = append(parts, contentPart{
				Type: "text",
				Text: "[attachments from an earlier turn, no longer available: " + strings.Join(dropped, ", ") + "]",
			})
		}
		return []apiMessage{{
			Role:             m.Role,
			Content:          parts,
			ReasoningContent: assistantReasoningContent(m),
			ReasoningDetails: assistantReasoningDetails(m),
		}}
	}

	return []apiMessage{{
		Role:             m.Role,
		Content:          m.Content,
		ReasoningContent: assistantReasoningContent(m),
		ReasoningDetails: assistantReasoningDetails(m),
	}}
}

// attachmentLabel names an attachment for prose, preferring the original file
// name and falling back to its media type.
func attachmentLabel(att internal.Attachment) string {
	if att.FileName != "" {
		return att.FileName
	}
	if att.MediaType != "" {
		return att.MediaType
	}
	return "file"
}

func assistantReasoningContent(m internal.Message) string {
	if m.Role != "assistant" {
		return ""
	}
	return m.ReasoningContent
}

func assistantReasoningDetails(m internal.Message) json.RawMessage {
	if m.Role != "assistant" {
		return nil
	}
	return m.ReasoningDetails
}

// reasoningReplayForbidden reports whether this provider's API contract says
// assistant reasoning_content must NOT be echoed back in conversation history.
//
// The default is to replay: reasoning models served over OpenAI-compatible
// APIs either require the replay for correctness or tolerate it —
//   - moonshotai (Kimi): required for interleaved thinking with tool calls
//   - deepseek (V4 thinking mode): 400s without it once a tool call occurred
//   - minimax (M2/M3): thinking must be retained in history verbatim
//   - qwen (Qwen 3.5): required for interleaved thinking with tool calls
//   - x-ai, z-ai, vllm: replay is accepted; providers that never emit
//     reasoning_content leave the field empty, and empty values are omitted
//     from the wire (`omitempty`), so nothing is sent for them either way.
//
// Only providers whose API rejects the field belong here.
func (c *Client) reasoningReplayForbidden() bool {
	switch strings.ToLower(strings.TrimSpace(c.name)) {
	case "openai":
		// OpenAI's chat-completions API rejects unrecognized message fields
		// ("Unknown parameter: messages[N].reasoning_content") and never
		// returns reasoning content itself, so never echo it back.
		return true
	default:
		return false
	}
}

// forcesDefaultTemperature reports whether the provider's models reject any
// explicit temperature. Moonshot's Kimi coding models are always-thinking
// (reasoning-only) and require temperature to be left unset (server default
// of 1), the same restriction OpenAI's o-series reasoning models impose.
func (c *Client) forcesDefaultTemperature() bool {
	return c.isKimiProvider()
}

// isKimiProvider reports whether this client talks to Moonshot's Kimi models
// ("moonshotai" in the gateway catalog), which carry special request
// constraints (reasoning-content replay, fixed temperature), so the two names
// must stay in sync here.
func (c *Client) isKimiProvider() bool {
	switch strings.ToLower(strings.TrimSpace(c.name)) {
	case "moonshotai":
		return true
	default:
		return false
	}
}

// isDeepSeekProvider reports whether this client talks to DeepSeek's models.
// DeepSeek's reasoning contract is uniform across the whole provider — every
// model it serves takes the same efforts — so this is deliberately bound to the
// provider name and never to a model id.
func (c *Client) isDeepSeekProvider() bool {
	return strings.EqualFold(strings.TrimSpace(c.name), "deepseek")
}

// deepseekReasoning maps a requested reasoning level onto DeepSeek's accepted
// range. Per api-docs.deepseek.com/guides/thinking_mode, reasoning_effort takes
// low/high/max with a default of high, and thinking is on unless explicitly
// disabled.
//
// "max" — not "xhigh" — is the top rung. OpenRouter's model pages spell that
// rung `xhigh` in their normalized API, but DeepSeek's own API maps an incoming
// `xhigh` *down* to high, so forwarding it verbatim would silently cap the user
// below the level they picked. We therefore translate xhigh → max. `max` is
// also a documented value in OpenRouter's effort enum, so it stays correct
// whether a gateway serves this provider natively or through OpenRouter, a
// distinction the client cannot see.
//
// Callers can hand us any ladder token: the model-agnostic global default
// ("medium") reaches this path from the project-chat send, and a level stored
// against a previously selected model can be anything. Unknown mid-ladder
// values resolve to high, which is also DeepSeek's own default.
//
// Returns (reasoningEffort, thinking). DeepSeek documents both the flat
// reasoning_effort field and the thinking object, and its own sample code sends
// them together, so we set both: the effort picks the depth and the thinking
// object states the mode explicitly. An empty level returns ("", nil) so the
// model's own default applies.
func deepseekReasoning(level string) (string, *apiThinking) {
	level = strings.ToLower(strings.TrimSpace(level))
	if level == "" || level == "default" {
		return "", nil
	}
	// Thinking is disabled through the thinking object; the OpenAI-format
	// reasoning_effort field has no "none", so it is left off entirely.
	if level == "off" || level == "none" || level == "disabled" {
		return "", &apiThinking{Type: "disabled"}
	}
	effort := "high"
	switch level {
	case "minimal", "low":
		effort = "low"
	case "xhigh", "max":
		effort = "max"
	}
	return effort, &apiThinking{Type: "enabled"}
}

// kimiReasoningForModel maps an operator-selected reasoning mode to the correct
// Kimi API parameter for the given model. Kimi has no graduated levels; the two
// real controls are the k3 family's top-level reasoning_effort (only "max" is
// currently accepted) and the k2.x family's thinking object:
//
//   - k3 family:        mode "on" → reasoning_effort="max"; anything else → default.
//   - kimi-*-coding /   always-thinking; disabling errors, so mode "off" is a
//     k2.7-code:        no-op and "on" simply re-affirms thinking.type="enabled".
//   - k2.6 / k2.5:      mode "on" → thinking.type="enabled",
//     "off" → thinking.type="disabled".
//
// Returns (reasoningEffort, thinking); at most one is non-empty. An empty or
// "default" mode returns ("", nil) so the model's own default applies. The mode
// is normalized so it accepts both the on/off vocabulary AND any OpenAI-style
// ladder token (max/high/…): "off"/"none"/"disabled" mean off, ""/"default" mean
// default, and anything else means thinking on.
func kimiReasoningForModel(model, mode string) (string, *apiThinking) {
	model = strings.ToLower(strings.TrimSpace(model))
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" || mode == "default" {
		return "", nil
	}
	off := mode == "off" || mode == "none" || mode == "disabled"

	// k3 family uses reasoning_effort (currently only "max" is accepted); it has
	// no explicit "off" switch, so an off request just omits it.
	if strings.Contains(model, "k3") {
		if off {
			return "", nil
		}
		return "max", nil
	}

	// k2.x family uses the thinking object. Coding models always think and reject
	// thinking.type="disabled", so never send a disable for them.
	alwaysThinking := strings.Contains(model, "coding") || strings.Contains(model, "k2.7-code")
	if off {
		if alwaysThinking {
			return "", nil
		}
		return "", &apiThinking{Type: "disabled"}
	}
	return "", &apiThinking{Type: "enabled"}
}

func usageFromChunk(usage *chunkUsage) *provider.Usage {
	if usage == nil {
		return nil
	}

	u := &provider.Usage{
		InputTokens:  usage.PromptTokens,
		OutputTokens: usage.CompletionTokens,
	}
	if usage.PromptTokensDetails != nil {
		u.InputTokens -= usage.PromptTokensDetails.CachedTokens
		u.InputTokens -= usage.PromptTokensDetails.CacheWriteTokens
		u.CacheCreationInputTokens = usage.PromptTokensDetails.CacheWriteTokens
		u.CacheReadInputTokens = usage.PromptTokensDetails.CachedTokens
	}
	if usage.Billing != nil {
		u.Cost = &provider.CostBreakdown{
			RequestID:            usage.Billing.RequestID,
			InputCostUSD:         usage.Billing.InputCostUSD,
			OutputCostUSD:        usage.Billing.OutputCostUSD,
			CacheCreationCostUSD: usage.Billing.CacheCreationCostUSD,
			CacheReadCostUSD:     usage.Billing.CacheReadCostUSD,
			// What the relay charges us IS our cost; the vendor price beneath it
			// is the platform's margin and is no longer published. Putting both
			// fields on the billed figure also stops downstream savings maths
			// from mixing pre- and post-markup dollars.
			RawTotalUSD:    usage.Billing.BilledTotalUSD,
			BilledTotalUSD: usage.Billing.BilledTotalUSD,
		}
	} else if usage.Cost > 0 {
		u.Cost = &provider.CostBreakdown{RawTotalUSD: usage.Cost, BilledTotalUSD: usage.Cost}
	}
	return u
}

func extractReasoningText(delta chunkDelta) string {
	// These are incremental tokens: leading/trailing spaces and whitespace-only
	// chunks separate words and paragraphs when consumers concatenate them.
	text := extractReasoningValue(delta.ReasoningContent)
	if text != "" {
		return text
	}
	return extractReasoningValue(delta.Reasoning)
}

func extractReasoningValue(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}

	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return text
	}

	var parts []any
	if err := json.Unmarshal(raw, &parts); err == nil {
		var builder strings.Builder
		for _, part := range parts {
			appendReasoningText(&builder, part)
		}
		return builder.String()
	}

	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err == nil {
		var builder strings.Builder
		appendReasoningText(&builder, obj)
		return builder.String()
	}

	return ""
}

func appendReasoningText(builder *strings.Builder, value any) {
	switch typed := value.(type) {
	case string:
		appendReasoningFragment(builder, typed)
	case []any:
		for _, item := range typed {
			appendReasoningText(builder, item)
		}
	case map[string]any:
		for _, key := range []string{"thinking", "reasoning", "reasoning_content", "content", "text", "summary_text"} {
			if nested, ok := typed[key]; ok {
				appendReasoningText(builder, nested)
			}
		}
		if summary, ok := typed["summary"].([]any); ok {
			for _, item := range summary {
				appendReasoningText(builder, item)
			}
		}
	}
}

func appendReasoningFragment(builder *strings.Builder, fragment string) {
	if fragment == "" {
		return
	}
	if builder.Len() > 0 && needsReasoningSeparator(builder.String(), fragment) {
		builder.WriteByte(' ')
	}
	builder.WriteString(fragment)
}

func needsReasoningSeparator(existing, next string) bool {
	last, _ := utf8.DecodeLastRuneInString(existing)
	first, _ := utf8.DecodeRuneInString(next)
	if last == utf8.RuneError || first == utf8.RuneError {
		return false
	}
	if unicode.IsSpace(last) || unicode.IsSpace(first) {
		return false
	}
	if strings.ContainsRune("([{/'\"`-", last) {
		return false
	}
	if strings.ContainsRune(",.;:!?)]}/'\"`-", first) {
		return false
	}
	return true
}

func (c *Client) applyRequestHeaders(req *http.Request) {
	req.Header.Set(c.authHeaderName, c.authHeaderValuePrefix+c.apiKey)
}

func containsInt(values []int, value int) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
