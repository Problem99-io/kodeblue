// Package config loads kodeblue's configuration from a single root-owned TOML
// file (default /etc/kodeblue/kodeblue.toml).
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
	"github.com/Problem99-io/kodeblue/internal/blue/respond"
	"github.com/Problem99-io/kodeblue/internal/blue/upgrade"
)

const DefaultPath = "/etc/kodeblue/kodeblue.toml"

type Config struct {
	Server     Server         `toml:"server"`
	Inference  Inference      `toml:"inference"`
	Schedule   Schedule       `toml:"schedule"`
	Detect     Detect         `toml:"detect"`
	Budget     Budget         `toml:"budget"`
	Response   respond.Policy `toml:"response"`
	Notify     Notify         `toml:"notify"`
	Engine     Engine         `toml:"engine"`
	Hub        Hub            `toml:"hub"`
	Agents     Agents         `toml:"agents"`
	Requests   Requests       `toml:"requests"`
	CVEFeed    CVEFeed        `toml:"cve_feed"`
	Upgrade    Upgrade        `toml:"upgrade"`
	Cloudflare Cloudflare     `toml:"cloudflare"`
	// ActionRules are the hub's per-action approval rules (see
	// ActionRule). They come only from hub settings, never from this file.
	ActionRules map[string]string `toml:"-"`
	// HubSettingsVersion is the version of the hub settings applied.
	HubSettingsVersion string `toml:"-"`
	// RootResponseMode is [response] mode as the root-owned config sets it,
	// before a stricter mode from the hub is applied.
	RootResponseMode string `toml:"-"`
	// RootCVEFeed is [cve_feed] as the root-owned config sets it: the most
	// the hub may turn on.
	RootCVEFeed CVEFeed `toml:"-"`
	path        string
}

// Requests controls the request tap: kodeblue records the plaintext HTTP
// requests reaching the listening ports of its network namespace in
// <state>/requests/access.log (request line, client, status, user agent),
// so request monitors do not depend on what the application logs. It needs
// CAP_NET_RAW.
type Requests struct {
	Disabled bool `toml:"disabled"`
}

// CVEFeed is the daily pull of new CVEs, matched against the software on
// this server for the reviewer to check. It only downloads public feeds;
// nothing about the server is sent. Each switch here is the most the hub
// may turn on: off in this file (a server whose egress must stay closed),
// the hub cannot turn it on; on, hub operators may switch it.
type CVEFeed struct {
	Enabled bool `toml:"enabled"`
	// Sources: NIST's National Vulnerability Database (every new CVE) and
	// CISA's Known Exploited Vulnerabilities list (exploited now).
	NVD bool `toml:"nvd"`
	KEV bool `toml:"cisa_kev"`
	// NVDAPIKey is optional: NVD allows more requests with one.
	NVDAPIKey string `toml:"nvd_api_key"`
}

// Sources lists the feed's sources in effect (none when it is off).
func (f CVEFeed) Sources() []string {
	var l []string
	if f.Enabled && f.NVD {
		l = append(l, "nvd")
	}
	if f.Enabled && f.KEV {
		l = append(l, "cisa_kev")
	}
	return l
}

// Agents holds extra instructions per agent role (learner, responder,
// reviewer, operator, or "all"), added after each agent's own prompt.
type Agents struct {
	Instructions map[string]string `toml:"instructions"`
}

type Server struct {
	Name     string `toml:"name"`
	StateDir string `toml:"state_dir"`
	// Root lets kodeblue inspect a host filesystem mounted elsewhere (e.g.
	// /host when kodeblue itself runs in a container). Normally "/".
	Root string `toml:"root"`
}

// Inference is the OpenAI-compatible endpoint (POST {base_url}/v1/chat/completions)
// that triage and the agents use. Nothing is set by default: until base_url,
// a key and the models are configured, the model layers stay off and kodeblue
// runs sensors, detection and monitors only.
type Inference struct {
	BaseURL    string `toml:"base_url"`
	APIKey     string `toml:"api_key"`
	APIKeyFile string `toml:"api_key_file"`
	APIKeyEnv  string `toml:"api_key_env"`
	// Provider/model used by triage and by every agent session. A small model
	// is the point: the deterministic layers make its job narrow. Provider is
	// a routing label for gateways that serve several vendors; a plain
	// OpenAI-compatible endpoint can leave the default.
	Provider    string `toml:"provider"`
	TriageModel string `toml:"triage_model"`
	AgentModel  string `toml:"agent_model"`
	// Critical incidents may use a stronger model.
	EscalationProvider string `toml:"escalation_provider"`
	EscalationModel    string `toml:"escalation_model"`
	// AgentModels overrides agent_model per role: learner, responder,
	// reviewer, operator.
	AgentModels map[string]string `toml:"agent_models"`

	// Set from hub settings, never from the file: the hub's connections
	// (by ID) and its per-role model choices.
	Connections map[string]hubproto.Connection `toml:"-"`
	Refs        map[string]hubproto.ModelRef   `toml:"-"`
}

type Schedule struct {
	SweepSeconds     int `toml:"sweep_seconds"`
	FastWatchSeconds int `toml:"fast_watch_seconds"`
	TriageSeconds    int `toml:"triage_seconds"`
	ReviewHours      int `toml:"review_hours"`
	LearningMinutes  int `toml:"learning_minutes"`
	LearningSweeps   int `toml:"learning_sweeps"`
	// RetentionDays is how long settled findings, the journal and the cost
	// ledger are kept (0: 90 days; negative: forever). Open incidents'
	// findings and anything still unsettled are never pruned.
	RetentionDays int `toml:"retention_days"`
}

type Detect struct {
	Collectors           []string `toml:"collectors"`
	ExtraIntegrityPaths  []string `toml:"extra_integrity_paths"`
	DebounceSweeps       int      `toml:"debounce_sweeps"`
	RealertHours         int      `toml:"realert_hours"`
	BruteForceThreshold  int      `toml:"bruteforce_threshold"`
	AutoAcceptConfidence float64  `toml:"auto_accept_confidence"`
}

type Budget struct {
	// DailyUSD caps model spend per UTC day. Past it, only critical findings
	// reach a model; everything else waits for the next day's digest.
	DailyUSD float64 `toml:"daily_usd"`
	// Token prices (USD per million) for endpoints that report no cost per
	// call. Without them such calls count as $0 and daily_usd is not enforced.
	// HubMaxDailyUSD caps the daily budget the hub may set (it cannot raise
	// spend past this; the root-owned file decides).
	HubMaxDailyUSD         float64 `toml:"hub_max_daily_usd"`
	InputUSDPerMTok        float64 `toml:"input_usd_per_mtok"`
	OutputUSDPerMTok       float64 `toml:"output_usd_per_mtok"`
	MaxConcurrentIncidents int     `toml:"max_concurrent_incidents"`
	IncidentMaxIterations  int     `toml:"incident_max_iterations"`
	MaxIncidentsPerHour    int     `toml:"max_incidents_per_hour"`
}

type Notify struct {
	// Telegram bot token is a credential; prefer a root-owned file.
	TelegramBotToken     string `toml:"telegram_bot_token"`
	TelegramBotTokenFile string `toml:"telegram_bot_token_file"`
	TelegramChatID       string `toml:"telegram_chat_id"`
	TelegramChatIDFile   string `toml:"telegram_chat_id_file"`
	// Slack incoming webhook (one-way updates to a channel). Prefer the file:
	// the URL is a credential.
	SlackWebhookURL  string `toml:"slack_webhook_url"`
	SlackWebhookFile string `toml:"slack_webhook_file"`
	// MinSeverity gates automatic incident notifications. Containment actions
	// and agent-sent messages are always delivered.
	MinSeverity string `toml:"min_severity"`
	// AgentMessagesPerHour caps the send_alert tool.
	AgentMessagesPerHour int `toml:"agent_messages_per_hour"`
	// With a hub, notification delivery belongs to the hub: notifications are queued for it
	// and local destinations are ignored. Direct = true also posts straight
	// from this server — an independent channel a compromised hub cannot
	// suppress.
	Direct bool `toml:"direct"`
}

// Hub is the optional central console. kodeblue dials out to it; the hub
// never connects to the server.
type Hub struct {
	URL     string `toml:"url"`
	KeyFile string `toml:"key_file"`
	// Pin ("sha256//<base64 SPKI hash>") accepts a self-signed hub
	// certificate with exactly this public key. CAFile trusts a private CA.
	Pin         string `toml:"pin"`
	CAFile      string `toml:"ca_file"`
	SyncSeconds int    `toml:"sync_seconds"`
	// AcceptMessages lets signed-in hub operators message this server's
	// agents. Messages can ask for containment, which the response policy
	// above still governs.
	AcceptMessages   bool `toml:"accept_messages"`
	ShareTranscripts bool `toml:"share_transcripts"`
	MessagesPerHour  int  `toml:"messages_per_hour"`
	// AcceptApprovals lets signed-in hub operators approve or deny
	// containment an agent requested under recommend mode. The action still
	// runs through the root helper under the policy above; set it false to
	// keep approval on this server's CLI only.
	AcceptApprovals bool `toml:"accept_approvals"`
	// AcceptSettings applies the settings hub operators choose in the
	// console: the model endpoint, a model and extra instructions per agent,
	// and which containment actions need approval. Those rules can only
	// tighten [response]; the root helper never reads them.
	AcceptSettings bool `toml:"accept_settings"`
	// AcceptLearning lets hub operators run the learner again or relearn the
	// whole baseline. Relearning absorbs what the server runs at that moment
	// as normal, so every run is announced in Slack.
	AcceptLearning bool `toml:"accept_learning"`
	// AcceptUpgrades lets hub operators start an upgrade of kodeblue to the
	// hub's version (Update in the console). The release still comes from
	// [upgrade] release_url and must match its SHA256SUMS; downgrades are
	// refused. Nothing upgrades without an operator asking.
	AcceptUpgrades bool `toml:"accept_upgrades"`
}

// Upgrade is where releases come from, for an upgrade a hub operator
// started or `kodeblue upgrade`. Only the root-owned config sets it.
type Upgrade struct {
	// ReleaseURL holds one directory per release tag, each with the agent
	// tarballs and SHA256SUMS (default: the GitHub releases).
	ReleaseURL string `toml:"release_url"`
}

func (h Hub) Enabled() bool { return strings.TrimSpace(h.URL) != "" }

// APIKey reads the server's hub key.
func (h Hub) APIKey() (string, error) {
	b, err := os.ReadFile(h.KeyFile)
	if err != nil {
		return "", err
	}
	k := strings.TrimSpace(string(b))
	if k == "" {
		return "", fmt.Errorf("%s is empty: enroll with `kodeblue enroll`", h.KeyFile)
	}
	return k, nil
}

type Engine struct {
	Binary string `toml:"binary"`
}

func Default() Config {
	return Config{
		Server: Server{StateDir: "/var/lib/kodeblue", Root: "/"},
		Inference: Inference{
			APIKeyFile: "/etc/kodeblue/inference.key", APIKeyEnv: "KODEBLUE_INFERENCE_API_KEY",
			Provider: "openai-compatible",
		},
		Schedule: Schedule{SweepSeconds: 60, FastWatchSeconds: 5, TriageSeconds: 120, ReviewHours: 24, LearningMinutes: 30, LearningSweeps: 10},
		Detect:   Detect{DebounceSweeps: 2, RealertHours: 24, BruteForceThreshold: 20, AutoAcceptConfidence: 0.85},
		Budget:   Budget{DailyUSD: 1.0, HubMaxDailyUSD: 20, MaxConcurrentIncidents: 2, IncidentMaxIterations: 30, MaxIncidentsPerHour: 6},
		Response: respond.DefaultPolicy(),
		Notify:   Notify{TelegramBotTokenFile: "/etc/kodeblue/telegram.token", TelegramChatIDFile: "/etc/kodeblue/telegram.chat", SlackWebhookFile: "/etc/kodeblue/slack.webhook", MinSeverity: "high", AgentMessagesPerHour: 20},
		Engine:   Engine{},
		CVEFeed:  CVEFeed{Enabled: true, NVD: true, KEV: true},
		Hub:      Hub{KeyFile: "/etc/kodeblue/hub.key", SyncSeconds: 15, AcceptMessages: true, ShareTranscripts: true, MessagesPerHour: 20, AcceptApprovals: true, AcceptSettings: true, AcceptLearning: true, AcceptUpgrades: true},
		Upgrade:  Upgrade{ReleaseURL: upgrade.DefaultReleaseURL},
	}
}

// Load reads path over the defaults. A missing file yields defaults.
func Load(path string) (Config, error) {
	c := Default()
	c.path = path
	if path != "" {
		if _, err := os.Stat(path); err == nil {
			if _, err := toml.DecodeFile(path, &c); err != nil {
				return c, fmt.Errorf("parse %s: %w", path, err)
			}
		}
	}
	if c.Server.Name == "" {
		c.Server.Name, _ = os.Hostname()
	}
	if c.Server.Root == "" {
		c.Server.Root = "/"
	}
	if c.Inference.EscalationProvider == "" {
		c.Inference.EscalationProvider = c.Inference.Provider
	}
	// The root response helper's state (action journal, quarantined files, SSH
	// key backups) lives beside the kodeblue state dir, not inside it: the
	// kodeblue user owns <state_dir> and could rename a directory within it to
	// plant a forged journal, but not one whose parent only root can change.
	// For the default /var/lib/kodeblue this is /var/lib/kodeblue-respond.
	c.Response.StateDir = c.Server.StateDir + "-respond"
	// The hub and the model endpoints are infrastructure block_ip must never
	// cut off. They come from the root-owned config (the root helper reads
	// only that), never from a request.
	c.Inference.BaseURL = NormalizeBaseURL(c.Inference.BaseURL)
	c.Response.InfraHosts = nil
	for _, h := range []string{c.Hub.URL, c.Inference.BaseURL} {
		if strings.TrimSpace(h) != "" {
			c.Response.InfraHosts = append(c.Response.InfraHosts, h)
		}
	}
	if c.Engine.Binary == "" {
		if exe, err := os.Executable(); err == nil {
			for _, cand := range []string{filepath.Join(filepath.Dir(exe), "kodeblue-engine"), "/usr/local/lib/kodeblue/engine"} {
				if _, err := os.Stat(cand); err == nil {
					c.Engine.Binary = cand
					break
				}
			}
		}
	}
	return c, nil
}

func (c Config) Path() string { return c.path }

// NormalizeBaseURL turns an endpoint as vendors document it ("…/v1",
// trailing slash) into the base kodeblue appends /v1/chat/completions to.
func NormalizeBaseURL(raw string) string {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	if u, err := url.Parse(raw); err == nil && u.Host != "" && strings.HasSuffix(u.Path, "/v1") && u.RawQuery == "" && u.Fragment == "" {
		return strings.TrimSuffix(raw, "/v1")
	}
	return raw
}

// IntegrityPaths is the full list of extra files the integrity collector
// hashes: configured paths, paths the agents added (learned), and kodeblue's
// own binaries and config — an attacker's first move against a monitor is to
// tamper with it. The daemon, the agents' snapshot tool and the CLI must all
// use this so they see the same watch list.
func (c Config) IntegrityPaths(learned []string) []string {
	paths := append(append([]string{}, c.Detect.ExtraIntegrityPaths...), learned...)
	if exe, err := os.Executable(); err == nil {
		if real, err := filepath.EvalSymlinks(exe); err == nil {
			exe = real
		}
		paths = append(paths, exe)
	}
	if c.Engine.Binary != "" {
		paths = append(paths, c.Engine.Binary)
	}
	if c.path != "" {
		paths = append(paths, c.path)
	}
	return paths
}

// APIKey resolves the key of the server's own [inference] endpoint:
// inline > file > env.
func (c Config) APIKey() (string, error) {
	in := c.Inference
	if strings.TrimSpace(in.BaseURL) == "" {
		return "", errors.New("no model endpoint: set [inference] base_url")
	}
	if k := strings.TrimSpace(c.Inference.APIKey); k != "" {
		return k, nil
	}
	if c.Inference.APIKeyFile != "" {
		if b, err := os.ReadFile(c.Inference.APIKeyFile); err == nil {
			if k := strings.TrimSpace(string(b)); k != "" {
				return k, nil
			}
		}
	}
	if c.Inference.APIKeyEnv != "" {
		if k := strings.TrimSpace(os.Getenv(c.Inference.APIKeyEnv)); k != "" {
			return k, nil
		}
	}
	return "", fmt.Errorf("no inference API key: set inference.api_key_file (%s) or $%s", c.Inference.APIKeyFile, c.Inference.APIKeyEnv)
}

func (c Config) DBPath() string       { return filepath.Join(c.Server.StateDir, "kodeblue.db") }
func (c Config) WorkspaceDir() string { return filepath.Join(c.Server.StateDir, "workspace") }
func (c Config) EngineDir() string    { return filepath.Join(c.Server.StateDir, "engine") }

// MigrateEngineDir moves engine state from where early releases kept it
// (<state>/kodecode with kodecode.db and kodecode.log) to EngineDir.
func (c Config) MigrateEngineDir() error {
	old := filepath.Join(c.Server.StateDir, "kodecode")
	if _, err := os.Stat(old); err != nil {
		return nil
	}
	if _, err := os.Stat(c.EngineDir()); err == nil {
		return nil
	}
	if err := os.Rename(old, c.EngineDir()); err != nil {
		return err
	}
	for _, ext := range []string{".db", ".db-wal", ".db-shm", ".db.run-locks", ".log"} {
		_ = os.Rename(filepath.Join(c.EngineDir(), "kodecode"+ext), filepath.Join(c.EngineDir(), "engine"+ext))
	}
	return nil
}

func (c Config) CursorPath() string  { return filepath.Join(c.Server.StateDir, "cursors.json") }
func (c Config) RequestsDir() string { return filepath.Join(c.Server.StateDir, "requests") }
func (c Config) ResponseDir() string { return c.Server.StateDir + "-respond" }
func (c Config) MaintenanceFile() string {
	return filepath.Join(c.Server.StateDir, "maintenance-until")
}
