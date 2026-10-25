package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Problem99-io/kodeblue/internal/blue/config"
)

func TestWriteInference(t *testing.T) {
	p := filepath.Join(t.TempDir(), "kodeblue.toml")
	orig := "[server]\nname = \"web-1\"\n\n[inference]\n# base_url = \"https://api.example.com\"\napi_key_file = \"/etc/kodeblue/inference.key\"\nescalation_model = \"big\"\n\n[response]\nmode = \"recommend\"\n"
	if err := os.WriteFile(p, []byte(orig), 0o640); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.APIKey(); err == nil || !strings.Contains(err.Error(), "base_url") {
		t.Fatalf("an unconfigured endpoint must keep the models off, got %v", err)
	}
	if err := writeInference(cfg, "ftp://x", "", "m"); err == nil {
		t.Fatal("non-http URL accepted")
	}
	if err := writeInference(cfg, "https://api.example.com/", "", "small"); err != nil {
		t.Fatal(err)
	}
	cfg, err = config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	in := cfg.Inference
	if in.BaseURL != "https://api.example.com" || in.TriageModel != "small" || in.AgentModel != "small" || in.Provider != "openai-compatible" {
		t.Fatalf("inference not written: %+v", in)
	}
	if in.EscalationModel != "big" || in.EscalationProvider != "openai-compatible" || in.APIKeyFile != "/etc/kodeblue/inference.key" {
		t.Fatalf("existing settings lost: %+v", in)
	}
	if cfg.Server.Name != "web-1" || cfg.Response.Mode != "recommend" {
		t.Fatalf("other sections changed: %+v", cfg)
	}
	t.Setenv("KODEBLUE_INFERENCE_API_KEY", "k")
	if k, err := cfg.APIKey(); err != nil || k != "k" {
		t.Fatalf("configured endpoint: key %q, err %v", k, err)
	}
}
