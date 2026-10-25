package policy

import (
	"testing"

	"github.com/Problem99-io/kodeblue/internal/secrets"
)

// Provider keys are delivered by the supervisor into the in-memory secret store
// and must win over anything on disk or in the environment — that is the whole
// point of moving them off the config file and out of the env.
func TestGatewayResolveAPIKeyPrefersInjectedSecret(t *testing.T) {
	t.Setenv("TEST_GATEWAY_KEY", "from-env")
	t.Cleanup(func() { secrets.Set(secrets.GatewayAPIKey, "") })

	cfg := GatewayConfig{APIKey: "from-config", APIKeyEnv: "TEST_GATEWAY_KEY"}

	if got := cfg.ResolveAPIKey(); got != "from-config" {
		t.Fatalf("without an injected secret, config should win: got %q", got)
	}

	secrets.Set(secrets.GatewayAPIKey, "from-supervisor")
	if got := cfg.ResolveAPIKey(); got != "from-supervisor" {
		t.Errorf("ResolveAPIKey = %q, want the injected secret", got)
	}
}

// Standalone engine runs have no supervisor, so the config/env fallbacks
// must keep working.
func TestGatewayResolveAPIKeyFallsBackWithoutSecret(t *testing.T) {
	t.Setenv("TEST_GATEWAY_KEY", "from-env")
	secrets.Set(secrets.GatewayAPIKey, "")

	cfg := GatewayConfig{APIKeyEnv: "TEST_GATEWAY_KEY"}
	if got := cfg.ResolveAPIKey(); got != "from-env" {
		t.Errorf("ResolveAPIKey = %q, want %q", got, "from-env")
	}

	empty := GatewayConfig{}
	if got := empty.ResolveAPIKey(); got != "" {
		t.Errorf("unconfigured provider resolved to %q, want empty", got)
	}
}
