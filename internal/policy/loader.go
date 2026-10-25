package policy

import (
	"errors"
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

// LoadConfig reads and decodes a single TOML configuration file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}
	cfg := DefaultConfig()
	if err := toml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return cfg, nil
}

// DefaultConfig returns a Config populated with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Host: "127.0.0.1",
			Port: 9090,
		},
		Providers: ProvidersConfig{
			Gateway: GatewayConfig{
				Enabled:   true,
				APIKeyEnv: "KODEBLUE_GATEWAY_API_KEY",
			},
		},
		Agent: AgentConfig{
			MaxIterations:            200,
			CompactionThresholdRatio: 0.8,
			CompactionModel:          "",
		},
		Paths: PathsConfig{
			ProjectRoot:     ".",
			AllowWritePaths: []string{"."},
			DenyPaths:       []string{".git", "node_modules"},
		},
		Skills: SkillsConfig{
			Enabled:     true,
			Permissions: map[string]string{"*": "allow"},
		},
		Instructions: InstructionsConfig{
			ProjectFiles: []string{"AGENTS.md"},
		},
	}
}

// Validate checks the config for required fields and valid value ranges.
func (c *Config) Validate() error {
	var errs []error

	if c.Server.Port < 1 || c.Server.Port > 65535 {
		errs = append(errs, fmt.Errorf("server.port must be 1-65535, got %d", c.Server.Port))
	}

	if c.Agent.MaxIterations < 0 {
		errs = append(errs, fmt.Errorf("agent.max_iterations must be >= 0 (0 disables the continue prompt), got %d", c.Agent.MaxIterations))
	}
	if c.Agent.CompactionThresholdRatio <= 0 || c.Agent.CompactionThresholdRatio > 1 {
		errs = append(errs, fmt.Errorf("agent.compaction_threshold_ratio must be (0, 1], got %f", c.Agent.CompactionThresholdRatio))
	}

	if c.Providers.Gateway.Enabled && c.Providers.Gateway.BaseURL == "" {
		errs = append(errs, errors.New("providers.gateway.base_url is required when enabled"))
	}

	return errors.Join(errs...)
}
