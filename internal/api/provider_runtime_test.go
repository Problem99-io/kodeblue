package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	internal "github.com/Problem99-io/kodeblue/internal"
	"github.com/Problem99-io/kodeblue/internal/policy"
	"github.com/Problem99-io/kodeblue/internal/provider"
	openaiProvider "github.com/Problem99-io/kodeblue/internal/provider/openai"
	"github.com/Problem99-io/kodeblue/internal/secrets"
)

func TestGatewayModelRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer relay-key" {
			t.Errorf("unexpected relay request: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	}))
	defer server.Close()
	p := newGatewayProvider("relay-key", server.URL, "openai", "test-model", nil)
	stream, err := p.Stream(context.Background(), &provider.Request{Model: "test-model"})
	if err != nil {
		t.Fatalf("normal model request failed: %v", err)
	}
	for event := range stream {
		if event.Type == provider.EventError {
			t.Fatalf("stream failed: %+v", event)
		}
	}
}

func TestRegisterConfiguredProvidersForStartupDoesNotCallCatalog(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Error(w, "catalog should not be called during startup", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	registry := provider.NewRegistry()
	cfg := &policy.Config{}
	cfg.Providers.Gateway.Enabled = true
	cfg.Providers.Gateway.APIKey = "relay-key"
	cfg.Providers.Gateway.BaseURL = server.URL

	RegisterConfiguredProvidersForStartup(registry, cfg, nil)

	if got := requests.Load(); got != 0 {
		t.Fatalf("expected startup registration to avoid catalog I/O, got %d request(s)", got)
	}
}

func TestResolveConfiguredProviderUsesFallbackWithoutCatalogRoundTrip(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Error(w, "catalog should not be needed for an explicit provider/model", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	registry := provider.NewRegistry()
	cfg := &policy.Config{}
	cfg.Providers.Gateway.Enabled = true
	cfg.Providers.Gateway.APIKey = "relay-key"
	cfg.Providers.Gateway.BaseURL = server.URL

	resolved, ok := ResolveConfiguredProvider(registry, cfg, nil, "anthropic", "claude-sonnet-4.6")
	if !ok || resolved == nil {
		t.Fatal("expected explicit provider/model to resolve through the relay fallback")
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("expected fallback resolution to avoid catalog I/O, got %d request(s)", got)
	}
}

func newGatewayModelsServer(t *testing.T, payloadByPath map[string]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer relay-key" {
			t.Fatalf("expected relay auth header, got %q", got)
		}
		payload, ok := payloadByPath[r.URL.RequestURI()]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(payload))
	}))
}

func TestRegisterConfiguredProvidersUsesOpenAIClientForGatewayProvider(t *testing.T) {
	server := newGatewayModelsServer(t, map[string]string{
		"/v1/models":                  `{"object":"list","data":[{"id":"minimax-m2.7","provider":"minimax"}]}`,
		"/v1/models?provider=minimax": `{"object":"list","data":[{"id":"minimax-m2.7"}]}`,
	})
	defer server.Close()

	registry := provider.NewRegistry()
	cfg := &policy.Config{}
	cfg.Providers.Gateway.Enabled = true
	cfg.Providers.Gateway.APIKey = "relay-key"
	cfg.Providers.Gateway.BaseURL = server.URL

	RegisterConfiguredProviders(registry, cfg, nil)

	registered, ok := registry.Get("minimax")
	if !ok {
		t.Fatal("expected minimax to be registered")
	}
	if _, ok := registered.(*openaiProvider.Client); !ok {
		t.Fatalf("expected gateway provider to use OpenAI-compatible client, got %T", registered)
	}
}

func TestRegisterConfiguredProvidersAddsDynamicGatewayProviders(t *testing.T) {
	server := newGatewayModelsServer(t, map[string]string{
		"/v1/models":               `{"object":"list","data":[{"id":"kimi-k2","provider":"kimi"}]}`,
		"/v1/models?provider=kimi": `{"object":"list","data":[{"id":"kimi-k2"}]}`,
	})
	defer server.Close()

	registry := provider.NewRegistry()
	cfg := &policy.Config{}
	cfg.Providers.Gateway.Enabled = true
	cfg.Providers.Gateway.APIKey = "relay-key"
	cfg.Providers.Gateway.BaseURL = server.URL

	RegisterConfiguredProviders(registry, cfg, nil)

	registered, ok := registry.Get("kimi")
	if !ok {
		t.Fatal("expected kimi to be registered dynamically")
	}
	if _, ok := registered.(*openaiProvider.Client); !ok {
		t.Fatalf("expected kimi provider to use OpenAI-compatible client, got %T", registered)
	}
	if dm, ok := registered.(defaultModeler); !ok || dm.DefaultModel() != "kimi-k2" {
		t.Fatalf("expected dynamic provider default model kimi-k2, got %#v", registered)
	}
	if ml, ok := registered.(modelLister); !ok {
		t.Fatalf("expected dynamic provider to support model listing, got %T", registered)
	} else {
		models, err := ml.Models(context.Background())
		if err != nil {
			t.Fatalf("list dynamic provider models: %v", err)
		}
		if len(models) != 1 || models[0] != "kimi-k2" {
			t.Fatalf("expected kimi-k2 model list, got %#v", models)
		}
	}
}

func TestRegisterConfiguredProvidersUsesGatewayCatalogForBuiltinsWithoutLocalProviderSetup(t *testing.T) {
	server := newGatewayModelsServer(t, map[string]string{
		"/v1/models":                     `{"object":"list","data":[{"id":"claude-sonnet-4.6","provider":"anthropic"},{"id":"gpt-5.4","provider":"openai"},{"id":"kimi-k2.6","provider":"moonshotai"}]}`,
		"/v1/models?provider=anthropic":  `{"object":"list","data":[{"id":"claude-sonnet-4.6"}]}`,
		"/v1/models?provider=openai":     `{"object":"list","data":[{"id":"gpt-5.4"}]}`,
		"/v1/models?provider=moonshotai": `{"object":"list","data":[{"id":"kimi-k2.6"}]}`,
	})
	defer server.Close()

	registry := provider.NewRegistry()
	cfg := &policy.Config{}
	cfg.Providers.Gateway.Enabled = true
	cfg.Providers.Gateway.APIKey = "relay-key"
	cfg.Providers.Gateway.BaseURL = server.URL

	RegisterConfiguredProviders(registry, cfg, nil)

	for _, providerName := range []string{"anthropic", "openai", "moonshotai"} {
		registered, ok := registry.Get(providerName)
		if !ok {
			t.Fatalf("expected %s to be registered from the gateway catalog", providerName)
		}
		if _, ok := registered.(*openaiProvider.Client); !ok {
			t.Fatalf("expected %s provider to use OpenAI-compatible client, got %T", providerName, registered)
		}
	}
}

func TestResolveConfiguredProviderDiscoversDynamicGatewayProviderOnDemand(t *testing.T) {
	server := newGatewayModelsServer(t, map[string]string{
		"/v1/models":                     `{"object":"list","data":[{"id":"kimi-k2.6","provider":"moonshotai"}]}`,
		"/v1/models?provider=moonshotai": `{"object":"list","data":[{"id":"kimi-k2.6"}]}`,
	})
	defer server.Close()

	registry := provider.NewRegistry()
	cfg := &policy.Config{}
	cfg.Providers.Gateway.Enabled = true
	cfg.Providers.Gateway.APIKey = "relay-key"
	cfg.Providers.Gateway.BaseURL = server.URL

	resolved, ok := ResolveConfiguredProvider(registry, cfg, nil, "moonshotai", "")
	if !ok {
		t.Fatal("expected moonshotai to be discovered on demand")
	}
	if _, ok := resolved.(*openaiProvider.Client); !ok {
		t.Fatalf("expected moonshotai provider to use OpenAI-compatible client, got %T", resolved)
	}
}

func TestResolveNamedGatewayProvider(t *testing.T) {
	var auth, body atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			// The catalog publishes explicit caching for the model.
			_, _ = w.Write([]byte(`{"data":[{"id":"vendor/model","provider":"anthropic","cache":{"supported":true,"max_markers":4}}]}`))
			return
		}
		auth.Store(r.Header.Get("Authorization"))
		b, _ := io.ReadAll(r.Body)
		body.Store(string(b))
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	}))
	defer server.Close()

	secrets.Set(secrets.NamedGatewayAPIKey("or"), "named-key")
	defer secrets.Set(secrets.NamedGatewayAPIKey("or"), "")

	registry := provider.NewRegistry()
	cfg := &policy.Config{}
	cfg.Providers.Gateways = map[string]policy.GatewayConfig{
		"or":  {Enabled: true, BaseURL: server.URL + "/"},
		"off": {Enabled: false, BaseURL: server.URL, APIKey: "k"},
	}

	p, ok := ResolveConfiguredProvider(registry, cfg, nil, "or:openrouter", "vendor/model")
	if !ok || p == nil {
		t.Fatal("named gateway provider did not resolve")
	}
	if p.Name() != "openrouter" {
		t.Fatalf("client name = %q, want the label", p.Name())
	}
	if again, _ := registry.Get("or:openrouter"); again != p {
		t.Fatal("named gateway provider not registered under its full name")
	}
	stream, err := p.Stream(context.Background(), &provider.Request{Model: "vendor/model", SystemPrompt: "system", PromptCacheKey: "sess_1",
		Messages: []internal.Message{{ID: "m1", Role: "user", Content: "hello"}}})
	if err != nil {
		t.Fatal(err)
	}
	for range stream {
	}
	if got, _ := auth.Load().(string); got != "Bearer named-key" {
		t.Fatalf("auth = %q, want the named gateway's key", got)
	}
	if sent, _ := body.Load().(string); !strings.Contains(sent, `"cache_control"`) || !strings.Contains(sent, `"session_id":"sess_1"`) {
		t.Fatalf("no cache markers from the named gateway's published caps: %s", sent)
	}

	for _, name := range []string{"off:openai", "missing:openai", "or:", ":openai"} {
		if _, ok := ResolveConfiguredProvider(registry, cfg, nil, name, "m"); ok {
			t.Errorf("%q resolved", name)
		}
	}
}
