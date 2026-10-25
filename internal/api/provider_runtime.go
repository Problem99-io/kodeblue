package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/Problem99-io/kodeblue/internal/policy"
	"github.com/Problem99-io/kodeblue/internal/provider"
	openaiProvider "github.com/Problem99-io/kodeblue/internal/provider/openai"
)

// RegisterConfiguredProviders rebuilds the runtime provider registry from config.
//
// Every model is reached through one OpenAI-compatible gateway
// ([providers.gateway]). Providers and models are discovered from its
// /v1/models catalog, or registered on first use when it publishes none.
func RegisterConfiguredProviders(registry *provider.Registry, cfg *policy.Config, logger *slog.Logger) {
	registerConfiguredProviders(registry, cfg, logger, true)
}

// RegisterConfiguredProvidersForStartup builds the registry without waiting on
// catalog discovery, so the HTTP server becomes healthy even when the gateway
// is slow or unreachable. A requested provider is then built on first use.
func RegisterConfiguredProvidersForStartup(registry *provider.Registry, cfg *policy.Config, logger *slog.Logger) {
	registerConfiguredProviders(registry, cfg, logger, false)
}

func registerConfiguredProviders(registry *provider.Registry, cfg *policy.Config, logger *slog.Logger, discoverCatalog bool) {
	if registry == nil || cfg == nil {
		return
	}

	for _, name := range registry.List() {
		registry.Unregister(name)
	}

	if discoverCatalog {
		registerGatewayCatalogProviders(registry, cfg, logger)
	}

	if logger != nil {
		logger.Info("provider registry ready", "available", registry.List())
	}
}

// ResolveConfiguredProvider returns a registered provider, building it from
// the gateway on demand if needed.
func ResolveConfiguredProvider(registry *provider.Registry, cfg *policy.Config, logger *slog.Logger, name, model string) (provider.Provider, bool) {
	if registry == nil {
		return nil, false
	}
	if p, ok := registry.Get(name); ok {
		return p, true
	}
	if p := registerNamedGatewayProvider(registry, cfg, logger, name, model); p != nil {
		return p, true
	}
	if !gatewayConfigured(cfg) {
		return nil, false
	}

	// The gateway already accepts the selected provider/model. Build that
	// client at once instead of holding the first turn behind a catalog lookup;
	// a refresh of the provider list still discovers everything else.
	if fallback := registerGatewayProviderFallback(registry, cfg, logger, name, model); fallback != nil {
		return fallback, true
	}

	registerGatewayCatalogProviders(registry, cfg, logger)
	if p, ok := registry.Get(name); ok {
		return p, true
	}

	return nil, false
}

func registerGatewayProviderFallback(registry *provider.Registry, cfg *policy.Config, logger *slog.Logger, providerName, model string) provider.Provider {
	if registry == nil || cfg == nil {
		return nil
	}

	cleanProvider := strings.ToLower(strings.TrimSpace(providerName))
	if cleanProvider == "" {
		return nil
	}
	if existing, ok := registry.Get(cleanProvider); ok {
		return existing
	}

	gw := cfg.Providers.Gateway
	apiKey := strings.TrimSpace(gw.ResolveAPIKey())
	baseURL := strings.TrimRight(strings.TrimSpace(gw.BaseURL), "/")
	if apiKey == "" || baseURL == "" {
		return nil
	}

	defaultModel := strings.TrimSpace(model)
	if defaultModel == "" {
		defaultModel = cleanProvider
	}

	client := newGatewayProvider(apiKey, baseURL, cleanProvider, defaultModel, nil)
	registry.Register(cleanProvider, client)
	logRegisteredProvider(logger, cleanProvider, defaultModel, baseURL, "gateway_fallback")
	return client
}

// registerNamedGatewayProvider builds the client for a "<id>:<label>"
// provider served by [providers.gateways.<id>]. Named gateways are not
// catalog-discovered: the caller names the provider and model it wants.
func registerNamedGatewayProvider(registry *provider.Registry, cfg *policy.Config, logger *slog.Logger, providerName, model string) provider.Provider {
	if cfg == nil {
		return nil
	}
	gw, apiKey, label, ok := cfg.Providers.NamedGateway(providerName)
	if !ok {
		return nil
	}
	name := strings.ToLower(strings.TrimSpace(providerName))
	if existing, ok := registry.Get(name); ok {
		return existing
	}
	defaultModel := strings.TrimSpace(model)
	if defaultModel == "" {
		defaultModel = label
	}
	baseURL := strings.TrimRight(strings.TrimSpace(gw.BaseURL), "/")
	// The gateway's published cache capabilities turn on explicit cache
	// markers (a gateway may serve Claude in explicit mode). A
	// catalog without them, or one that fails, leaves automatic caching.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	_, cacheCaps, err := discoverGatewayProviders(ctx, baseURL, apiKey)
	cancel()
	if err != nil && logger != nil {
		logger.Warn("named gateway catalog unavailable; no cache markers", "gateway", name, "error", err)
	}
	client := newGatewayProvider(apiKey, baseURL, label, defaultModel, cacheCaps)
	registry.Register(name, client)
	logRegisteredProvider(logger, name, defaultModel, baseURL, "named_gateway")
	return client
}

// RefreshDynamicConfiguredProviders adds any providers the gateway has started
// serving, without rebuilding the existing entries.
func RefreshDynamicConfiguredProviders(registry *provider.Registry, cfg *policy.Config, logger *slog.Logger) {
	if registry == nil || !gatewayConfigured(cfg) {
		return
	}
	registerGatewayCatalogProviders(registry, cfg, logger)
}

func gatewayConfigured(cfg *policy.Config) bool {
	if cfg == nil {
		return false
	}
	gw := cfg.Providers.Gateway
	return gw.Enabled && strings.TrimSpace(gw.BaseURL) != "" && strings.TrimSpace(gw.ResolveAPIKey()) != ""
}

type gatewayModelsResponse struct {
	Data []gatewayModelCard `json:"data"`
}

type gatewayModelCard struct {
	ID       string `json:"id"`
	Provider string `json:"provider"`
	// Cache is the gateway's published prompt-cache capability, if any.
	Cache *struct {
		Supported  bool `json:"supported"`
		MaxMarkers int  `json:"max_markers"`
	} `json:"cache,omitempty"`
}

func registerGatewayCatalogProviders(registry *provider.Registry, cfg *policy.Config, logger *slog.Logger) {
	gw := cfg.Providers.Gateway
	if !gatewayConfigured(cfg) {
		return
	}

	apiKey := gw.ResolveAPIKey()
	baseURL := strings.TrimRight(strings.TrimSpace(gw.BaseURL), "/")
	if apiKey == "" || baseURL == "" {
		return
	}

	discoveryCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	providers, cacheCaps, err := discoverGatewayProviders(discoveryCtx, baseURL, apiKey)
	if err != nil {
		if logger != nil {
			logger.Warn("failed to discover gateway providers", "error", err)
		}
		return
	}

	names := make([]string, 0, len(providers))
	for name := range providers {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		if _, exists := registry.Get(name); exists {
			continue
		}
		models := providers[name]
		if len(models) == 0 {
			continue
		}

		registry.Register(name, newGatewayProvider(apiKey, baseURL, name, models[0], cacheCaps))
		logRegisteredProvider(logger, name, models[0], baseURL, "gateway_catalog")
	}
}

func newGatewayProvider(apiKey, baseURL, providerName, defaultModel string, cacheCaps map[string]openaiProvider.CacheCaps) provider.Provider {
	providerName = strings.ToLower(strings.TrimSpace(providerName))
	return openaiProvider.NewClientWithAdvancedOptions(apiKey, defaultModel, openaiProvider.ClientOptions{
		Name:                   providerName,
		BaseURL:                baseURL,
		SupportsPromptCacheKey: true,
		ChatCompletionsPath:    "/v1/chat/completions",
		ModelsPath:             "/v1/models?provider=" + url.QueryEscape(providerName),
		AuthHeaderName:         "Authorization",
		AuthHeaderValuePrefix:  "Bearer ",
		CacheCaps:              cacheCaps,
	})
}

// discoverGatewayProviders returns provider → model IDs, and the
// per-model cache capabilities (nil when the gateway publishes none).
func discoverGatewayProviders(ctx context.Context, baseURL, apiKey string) (map[string][]string, map[string]openaiProvider.CacheCaps, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/v1/models", nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, decodeDiscoveryError(resp)
	}

	var payload gatewayModelsResponse
	decoder := json.NewDecoder(resp.Body)
	decoder.UseNumber()
	if err := decoder.Decode(&payload); err != nil {
		return nil, nil, err
	}

	providers := map[string][]string{}
	var cacheCaps map[string]openaiProvider.CacheCaps
	for _, model := range payload.Data {
		providerName := strings.ToLower(strings.TrimSpace(model.Provider))
		modelID := strings.TrimSpace(model.ID)
		if providerName == "" || modelID == "" {
			continue
		}
		providers[providerName] = append(providers[providerName], modelID)
		if model.Cache != nil {
			if cacheCaps == nil {
				cacheCaps = map[string]openaiProvider.CacheCaps{}
			}
			cacheCaps[modelID] = openaiProvider.CacheCaps{Supported: model.Cache.Supported, MaxMarkers: model.Cache.MaxMarkers}
		}
	}

	for name, models := range providers {
		providers[name] = uniqueSortedStrings(models)
	}

	return providers, cacheCaps, nil
}

func decodeDiscoveryError(resp *http.Response) error {
	var payload struct {
		Error any `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err == nil && payload.Error != nil {
		return slogValueError(resp.StatusCode, payload.Error)
	}
	return slogValueError(resp.StatusCode, "provider discovery failed")
}

func slogValueError(statusCode int, value any) error {
	return &providerDiscoveryError{statusCode: statusCode, detail: value}
}

type providerDiscoveryError struct {
	statusCode int
	detail     any
}

func (e *providerDiscoveryError) Error() string {
	detail := strings.TrimSpace(strings.ReplaceAll(strings.TrimSpace(toJSONString(e.detail)), "\n", " "))
	if detail == "" {
		detail = http.StatusText(e.statusCode)
	}
	return fmt.Sprintf("gateway models API error %d: %s", e.statusCode, detail)
}

func toJSONString(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return string(encoded)
}

func uniqueSortedStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		key := strings.ToLower(trimmed)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, trimmed)
	}
	sort.Strings(result)
	return result
}

func logRegisteredProvider(logger *slog.Logger, name, model, baseURL, via string) {
	if logger == nil {
		return
	}
	attrs := []any{"name", name, "model", model, "via", via}
	if baseURL != "" {
		attrs = append(attrs, "base_url", baseURL)
	}
	logger.Info("registered provider", attrs...)
}
