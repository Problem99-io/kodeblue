package main

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/Problem99-io/kodeblue/internal/blue/config"
)

// inferenceCmd shows or sets the model endpoint ([inference] in the config).
// Without flags it prints the current endpoint and exits 1 when the model
// layers are off, so the installer can tell whether to ask for one.
func inferenceCmd(cfg config.Config, baseURL, provider, model string) {
	if baseURL == "" && provider == "" && model == "" {
		in := cfg.Inference
		fmt.Printf("endpoint  %s\nprovider  %s\ntriage    %s\nagents    %s\n", orNone(in.BaseURL), orNone(in.Provider), orNone(in.TriageModel), orNone(in.AgentModel))
		if in.EscalationModel != "" {
			fmt.Printf("critical  %s\n", in.EscalationModel)
		}
		if err := cfg.ModelsReady(); err != nil {
			fmt.Printf("models    off (%v)\n", err)
			os.Exit(1)
		}
		fmt.Println("models    on")
		return
	}
	if os.Geteuid() != 0 {
		fatal(errors.New("setting the model endpoint must run as root (it writes the config)"))
	}
	if err := writeInference(cfg, baseURL, provider, model); err != nil {
		fatal(err)
	}
	fmt.Println("model endpoint saved; restart kodeblue to use it (systemctl restart kodeblue)")
}

// writeInference rewrites the [inference] table with the given endpoint,
// provider label and model (used for triage and agents), keeping the key
// settings and any escalation model already configured.
func writeInference(cfg config.Config, baseURL, provider, model string) error {
	in := cfg.Inference
	if baseURL != "" {
		u, err := url.Parse(baseURL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return fmt.Errorf("--url must be an http(s) URL, e.g. https://api.example.com (got %q)", baseURL)
		}
		in.BaseURL = strings.TrimRight(baseURL, "/")
	}
	if provider != "" {
		in.Provider = provider
	}
	if model != "" {
		in.TriageModel, in.AgentModel = model, model
	}
	if in.BaseURL == "" || in.AgentModel == "" {
		return errors.New("set both --url and --model")
	}
	q := strconv.Quote
	var b strings.Builder
	b.WriteString("[inference]\n# Any OpenAI-compatible endpoint: kodeblue calls {base_url}/v1/chat/completions.\n")
	fmt.Fprintf(&b, "base_url = %s\n", q(in.BaseURL))
	if in.APIKey != "" {
		fmt.Fprintf(&b, "api_key = %s\n", q(in.APIKey))
	}
	fmt.Fprintf(&b, "api_key_file = %s   # root:kodeblue 0640, one line\n", q(in.APIKeyFile))
	fmt.Fprintf(&b, "provider = %s\ntriage_model = %s\nagent_model = %s\n", q(in.Provider), q(in.TriageModel), q(in.AgentModel))
	if in.EscalationModel != "" {
		fmt.Fprintf(&b, "escalation_provider = %s\nescalation_model = %s\n", q(in.EscalationProvider), q(in.EscalationModel))
	}
	return replaceSection(cfg.Path(), "inference", b.String())
}

func orNone(s string) string {
	if s == "" {
		return "(not set)"
	}
	return s
}
