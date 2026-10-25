package policy

import (
	"os"
	"strings"

	"github.com/Problem99-io/kodeblue/internal/secrets"
)

// Config is the engine configuration, read from the TOML file passed with
// -config. kodeblue writes that file on every start.
type Config struct {
	Server       ServerConfig       `toml:"server"`
	Providers    ProvidersConfig    `toml:"providers"`
	Agent        AgentConfig        `toml:"agent"`
	Skills       SkillsConfig       `toml:"skills"`
	Paths        PathsConfig        `toml:"paths"`
	Instructions InstructionsConfig `toml:"instructions"`
	MCP          MCPConfig          `toml:"mcp"`
}

// MCPConfig lists the external Model Context Protocol servers the engine should
// connect to. Each server's tools are exposed to the agent as mcp__<server>__<tool>.
type MCPConfig struct {
	Servers []MCPServerConfig `toml:"servers"`
}

// MCPServerConfig describes a single external MCP server connection. The shape
// mirrors mcp.ServerConfig (the two are converted in cmd/kodeblue-engine).
type MCPServerConfig struct {
	Name      string            `toml:"name"`
	Transport string            `toml:"transport"` // "stdio" | "http" | "sse"
	Command   string            `toml:"command"`   // stdio: executable
	Args      []string          `toml:"args"`      // stdio: arguments
	URL       string            `toml:"url"`       // http/sse: endpoint
	Env       map[string]string `toml:"env"`       // stdio: extra env
	Headers   map[string]string `toml:"headers"`   // http/sse: request headers
	Enabled   bool              `toml:"enabled"`
}

type ServerConfig struct {
	Host string `toml:"host"`
	Port int    `toml:"port"`
}

type ProvidersConfig struct {
	Gateway GatewayConfig `toml:"gateway"`
	// Gateways are further named OpenAI-compatible endpoints used side by
	// side with Gateway. A provider named "<id>:<label>" is served by
	// Gateways[id]; label is the vendor the client tunes requests for
	// ("anthropic", "moonshotai", ...). Their keys come from the secrets
	// slot "gateway:<id>" (see secrets.NamedGatewayAPIKey).
	Gateways map[string]GatewayConfig `toml:"gateways"`
}

// NamedGateway splits a "<id>:<label>" provider name and returns the named
// gateway, its resolved key and the label. ok is false when name is not of
// that form or no such gateway is enabled with a URL and key.
func (p ProvidersConfig) NamedGateway(name string) (gw GatewayConfig, apiKey, label string, ok bool) {
	id, label, found := strings.Cut(strings.ToLower(strings.TrimSpace(name)), ":")
	if !found || id == "" || label == "" {
		return GatewayConfig{}, "", "", false
	}
	gw, ok = p.Gateways[id]
	if !ok || !gw.Enabled || strings.TrimSpace(gw.BaseURL) == "" {
		return GatewayConfig{}, "", "", false
	}
	apiKey = gw.resolveAPIKey(secrets.NamedGatewayAPIKey(id))
	if apiKey == "" {
		return GatewayConfig{}, "", "", false
	}
	return gw, apiKey, label, true
}

// GatewayConfig is the OpenAI-compatible endpoint every model is reached
// through. Providers and models are discovered from its /v1/models catalog.
type GatewayConfig struct {
	Enabled   bool   `toml:"enabled"`
	BaseURL   string `toml:"base_url"`
	APIKey    string `toml:"api_key"`
	APIKeyEnv string `toml:"api_key_env"`
}

// ResolveAPIKey returns the gateway key.
//
// Precedence: the in-memory secret the supervisor injects at startup, then an
// inline config value, then the named environment variable. The supervisor
// path wins because it is the only one that keeps the key off disk and out of
// the environment that agent tool processes inherit; the other two are for
// standalone runs. See internal/secrets.
func (c GatewayConfig) ResolveAPIKey() string {
	return c.resolveAPIKey(secrets.GatewayAPIKey)
}

func (c GatewayConfig) resolveAPIKey(slot string) string {
	if key := secrets.Get(slot); key != "" {
		return key
	}
	if c.APIKey != "" {
		return c.APIKey
	}
	if c.APIKeyEnv != "" {
		return os.Getenv(c.APIKeyEnv)
	}
	return ""
}

type AgentConfig struct {
	// MaxIterations is how many tool-calling turns a run takes before it pauses
	// and asks whether to keep going. It does not end the run: saying yes buys
	// another MaxIterations turns. 0 disables the checkpoint.
	MaxIterations            int     `toml:"max_iterations"`
	CompactionThresholdRatio float64 `toml:"compaction_threshold_ratio"`
	CompactionModel          string  `toml:"compaction_model"`
}

type PathsConfig struct {
	ProjectRoot     string   `toml:"project_root"`
	AllowWritePaths []string `toml:"allow_write_paths"`
	DenyPaths       []string `toml:"deny_paths"`
}

type InstructionsConfig struct {
	GlobalFiles  []string `toml:"global_files"`
	ProjectFiles []string `toml:"project_files"`
}

type SkillsConfig struct {
	Enabled     bool              `toml:"enabled"`
	Permissions map[string]string `toml:"permissions"` // pattern → "allow"|"deny"|"ask"
}
