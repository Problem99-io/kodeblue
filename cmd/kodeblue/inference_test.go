package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Problem99-io/kodeblue/internal/blue/config"
	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
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
	for in, want := range map[string]string{"https://v1": "https://v1", "http://v1/": "http://v1", "https://x/v1?a=1": "https://x/v1?a=1", " https://x/api/v1/ ": "https://x/api"} {
		if got := config.NormalizeBaseURL(in); got != want {
			t.Errorf("NormalizeBaseURL(%q) = %q, want %q", in, got, want)
		}
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
	// A link planted where the old code wrote its temp file must not be
	// followed: the key goes to a new file, and the link's target is untouched.
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, out+".tmp"); err != nil {
		t.Fatal(err)
	}
	if err := writeKey(out, "sk-test"); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(out); err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o640 {
		t.Fatalf("key file %v, err %v", fi.Mode(), err)
	}
	if b, _ := os.ReadFile(out); string(b) != "sk-test\n" {
		t.Fatalf("key file holds %q", b)
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Fatalf("link target overwritten: %q", b)
	}
}

// A server on a hub usually has no model of its own: the installer and the
// operator must see the models the hub sent, not "no model yet".
func TestShowInferenceCountsHubModels(t *testing.T) {
	c := config.Default()
	c.Server.StateDir = t.TempDir()
	c.Hub.URL = "https://hub.example"
	var out strings.Builder
	if showInference(&out, c) || !strings.Contains(out.String(), "models    off") {
		t.Fatalf("no models anywhere:\n%s", out.String())
	}
	s := &hubproto.Settings{Version: "v1",
		Connections: []hubproto.Connection{{ID: "or", Kind: hubproto.ConnOpenRouter, BaseURL: "https://openrouter.ai/api", APIKey: "sk-or-test"}},
		Models:      map[string]hubproto.ModelRef{hubproto.RoleDefault: {Connection: "or", Model: "vendor/small"}},
	}
	if err := c.SaveHubSettings(s); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if !showInference(&out, c) {
		t.Fatalf("hub models not counted:\n%s", out.String())
	}
	for _, want := range []string{"hub       ", "triage=or/vendor/small", "models    on (from the hub's Settings)"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "sk-or-test") {
		t.Fatal("the connection key was printed")
	}
	// A server that refuses hub settings runs without them.
	c.Hub.AcceptSettings = false
	out.Reset()
	if showInference(&out, c) {
		t.Fatalf("hub models counted with accept_settings = false:\n%s", out.String())
	}
}
