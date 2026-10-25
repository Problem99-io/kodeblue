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

// Vendors document their base URL with /v1 (OpenRouter's is
// https://openrouter.ai/api/v1); kodeblue adds /v1/chat/completions itself,
// so a pasted /v1 used to give 404s from …/v1/v1/chat/completions.
func TestWriteInferenceDropsV1(t *testing.T) {
	p := filepath.Join(t.TempDir(), "kodeblue.toml")
	if err := os.WriteFile(p, []byte("[inference]\napi_key_file = \"/etc/kodeblue/inference.key\"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeInference(cfg, "https://openrouter.ai/api/v1/", "", "m"); err != nil {
		t.Fatal(err)
	}
	if cfg, err = config.Load(p); err != nil || cfg.Inference.BaseURL != "https://openrouter.ai/api" {
		t.Fatalf("base_url %q, err %v", cfg.Inference.BaseURL, err)
	}
	// A config written by hand with /v1 is read the same way.
	if err := os.WriteFile(p, []byte("[inference]\nbase_url = \"https://api.example.com/v1\"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if cfg, err = config.Load(p); err != nil || cfg.Inference.BaseURL != "https://api.example.com" {
		t.Fatalf("hand-written base_url %q, err %v", cfg.Inference.BaseURL, err)
	}
}

func TestReadKey(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "k")
	if err := os.WriteFile(f, []byte("  sk-test  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if k, err := readKey(f); err != nil || k != "sk-test" {
		t.Fatalf("key %q, err %v", k, err)
	}
	if err := os.WriteFile(f, []byte("a\nb\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readKey(f); err == nil {
		t.Fatal("two-line key accepted")
	}
	out := filepath.Join(dir, "inference.key")
	if err := writeKey(out, "sk-test"); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(out); err != nil || fi.Mode().Perm() != 0o640 {
		t.Fatalf("key file mode %v, err %v", fi.Mode().Perm(), err)
	}
}
