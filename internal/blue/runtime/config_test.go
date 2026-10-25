package runtime

import (
	"os"
	"strings"
	"testing"

	"github.com/Problem99-io/kodeblue/internal/blue/config"
	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
	"github.com/Problem99-io/kodeblue/internal/policy"
)

// The engine must accept the config kodeblue writes, with the hub's
// connections as named gateways and no key material in the file.
func TestWriteConfigDeclaresConnections(t *testing.T) {
	cfg := config.Default()
	cfg.Server.StateDir = t.TempDir()
	cfg.Inference.Connections = map[string]hubproto.Connection{
		"or": {ID: "or", Kind: hubproto.ConnOpenRouter, BaseURL: "https://openrouter.ai/api", APIKey: "sk-or-secret"},
		"im": {ID: "im", Kind: hubproto.ConnInferenceManager, BaseURL: "https://im.example", APIKey: "im-secret"},
	}
	k := New(cfg, nil)
	path, err := k.writeConfig(9999)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if strings.Contains(string(b), "secret") {
		t.Fatalf("key material in the engine config:\n%s", b)
	}
	pc, err := policy.LoadConfig(path)
	if err != nil {
		t.Fatalf("engine rejects the config: %v\n%s", err, b)
	}
	if pc.Providers.Gateway.Enabled {
		t.Fatal("default gateway enabled without a local endpoint")
	}
	if g := pc.Providers.Gateways["or"]; !g.Enabled || g.BaseURL != "https://openrouter.ai/api" || len(pc.Providers.Gateways) != 2 {
		t.Fatalf("gateways: %+v", pc.Providers.Gateways)
	}
}
