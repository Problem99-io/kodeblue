package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Problem99-io/kodeblue/internal/blue/config"
	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
)

func TestDropOwnEndpoint(t *testing.T) {
	p := filepath.Join(t.TempDir(), "kodeblue.toml")
	in := "[server]\nname = \"web-1\"\nbase_url = \"keep-me\"\n\n[inference]\nbase_url = \"https://api.example.com\"\napi_key = \"sk-inline\"\napi_key_file = \"/etc/kodeblue/inference.key\"\ntriage_model = \"m\"\n\n[hub]\nurl = \"https://hub\"\n"
	if err := os.WriteFile(p, []byte(in), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := dropOwnEndpoint(p, "web-1"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	out := string(b)
	for _, want := range []string{"base_url = \"keep-me\"", "# base_url = \"https://api.example.com\"", "connection web-1", "api_key_file = ", "triage_model = \"m\"", "url = \"https://hub\""} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if strings.Contains(out, "sk-inline") {
		t.Fatalf("the inline key is still there:\n%s", out)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
}

func TestOwnKeysAndModels(t *testing.T) {
	dir := t.TempDir()
	kf := filepath.Join(dir, "inference.key")
	_ = os.WriteFile(kf, []byte("sk-file\n"), 0o640)
	cfg := config.Default()
	cfg.Inference.BaseURL, cfg.Inference.APIKeyFile, cfg.Inference.Provider = "https://api.example.com", kf, "openai"
	cfg.Inference.TriageModel, cfg.Inference.AgentModel = "small", "big"
	if inline, file, env := ownKeys(cfg); inline != "" || file != "sk-file" || env != "" {
		t.Fatalf("own keys %q %q %q", inline, file, env)
	}
	cfg.Inference.APIKey = "sk-inline"
	if inline, file, _ := ownKeys(cfg); inline != "sk-inline" || file != "sk-file" {
		t.Fatalf("inline and file %q %q", inline, file)
	}
	// The default and the roles that differ from it; the rest follow the
	// default on the hub.
	m := ownModels(cfg)
	if len(m) != 2 || m[hubproto.RoleDefault].Model != "big" || m[hubproto.RoleTriage].Model != "small" || m[hubproto.RoleTriage].Provider != "openai" {
		t.Fatalf("own models %+v", m)
	}
	cfg.Inference.AgentModels = map[string]string{hubproto.RoleReviewer: "huge"}
	cfg.Inference.EscalationModel = "big"
	m = ownModels(cfg)
	if m[hubproto.RoleReviewer].Model != "huge" || m[hubproto.RoleCritical].Model != "big" || len(m) != 4 {
		t.Fatalf("own models with overrides %+v", m)
	}
	// Roles the hub already picks on its connections are not moved.
	cfg.Inference.Refs = map[string]hubproto.ModelRef{hubproto.RoleTriage: {Connection: "main", Model: "hub-small"}}
	if _, ok := ownModels(cfg)[hubproto.RoleTriage]; ok {
		t.Fatal("a role the hub picks was moved")
	}
	// A key file with no endpoint still counts; it has no models.
	cfg.Inference.BaseURL, cfg.Inference.APIKey = "", ""
	if _, file, _ := ownKeys(cfg); file != "sk-file" || ownModels(cfg) != nil {
		t.Fatal("key file without an endpoint")
	}
}

func TestHubBehind(t *testing.T) {
	old := hubproto.Version
	t.Cleanup(func() { hubproto.Version = old })
	hubproto.Version = "v0.3.0"
	for v, behind := range map[string]bool{"": true, "v0.2.9": true, "v0.3.0": false, "v0.4.0": false, "dev": false} {
		if hubBehind(v) != behind {
			t.Errorf("hubBehind(%q) = %t", v, !behind)
		}
	}
}
