// Package hubproto is the wire contract between a kodeblue agent and the
// kodeblue hub. The agent always dials out: it enrolls once with a one-time
// token, then authenticates every request with its own API key. The hub never
// connects to servers.
package hubproto

import (
	"encoding/json"
	"regexp"
	"time"
)

const (
	PathPrefix   = "/api/agent/v1/"
	PathEnroll   = "/api/agent/v1/enroll"
	PathSync     = "/api/agent/v1/sync"
	PathMessages = "/api/agent/v1/messages" // GET long-poll; POST /{id}/reply
	// MaxSyncBytes bounds one sync request body on both sides.
	MaxSyncBytes = 16 << 20
)

type EnrollRequest struct {
	Token    string `json:"token"`
	Name     string `json:"name"`
	Hostname string `json:"hostname"`
	Version  string `json:"version"`
}

type EnrollResponse struct {
	ServerID string `json:"server_id"`
	Name     string `json:"name"`
	APIKey   string `json:"api_key"`
	// Optional fleet defaults the hub operator configured. Enrollment writes
	// them only where the server has none of its own. (Slack is not handed
	// out: the hub posts notifications itself.)
	InferenceKey string             `json:"inference_key,omitempty"`
	Inference    *InferenceDefaults `json:"inference,omitempty"`
}

// InferenceDefaults is the fleet's model endpoint: any OpenAI-compatible API.
type InferenceDefaults struct {
	BaseURL  string `json:"base_url"`
	Provider string `json:"provider,omitempty"`
	Model    string `json:"model"`
}

// Status is the agent's current state, sent on every sync.
type Status struct {
	Name         string `json:"name"`
	Hostname     string `json:"hostname"`
	Version      string `json:"version"`
	OS           string `json:"os,omitempty"`
	Kernel       string `json:"kernel,omitempty"`
	Uptime       string `json:"uptime,omitempty"`
	Phase        string `json:"phase"`                        // learning | watching | maintenance
	ResponseMode string `json:"response_mode"`                // what the server applies now
	RootMode     string `json:"root_response_mode,omitempty"` // [response] mode in its root-owned config
	// ModeCeiling is the highest mode the hub may switch it to: RootMode,
	// or the root-owned [response] hub_max_mode when that is higher.
	ModeCeiling    string             `json:"response_mode_ceiling,omitempty"`
	ModelsEnabled  bool               `json:"models_enabled"`
	TriageModel    string             `json:"triage_model"`
	AgentModel     string             `json:"agent_model"`
	Heartbeat      string             `json:"heartbeat"`
	LearnedAt      string             `json:"learned_at,omitempty"`
	LearnerPending bool               `json:"learner_pending,omitempty"` // learned without a model: the learner and assessment wait for one
	LastReviewAt   string             `json:"last_review_at,omitempty"`
	Maintenance    string             `json:"maintenance_until,omitempty"`
	SpendToday     float64            `json:"spend_today_usd"`
	SpendByPurpose map[string]float64 `json:"spend_by_purpose,omitempty"`
	Spend7d        float64            `json:"spend_7d_usd"`
	DailyBudget    float64            `json:"daily_budget_usd"`
	TokensToday    int                `json:"tokens_today"`
	Baseline       map[string]int     `json:"baseline,omitempty"`
	CollectorRuns  map[string]int     `json:"collector_runs,omitempty"`
	Profile        string             `json:"profile,omitempty"`
	// FindingStats7d is rule -> status -> count: the raw false-positive picture.
	FindingStats7d       map[string]map[string]int `json:"finding_stats_7d,omitempty"`
	SupportsInvestigator bool                      `json:"supports_investigator,omitempty"`
	AcceptsMessages      bool                      `json:"accepts_messages"`
	// AcceptsApprovals: hub operators may approve or deny containment the
	// agent asked for (hub.accept_approvals).
	AcceptsApprovals bool `json:"accepts_approvals"`
	// AcceptsRuleApprovals: hub operators may also approve containment
	// rules, which act without asking (accept_approvals, and root set
	// [response] mode or hub_max_mode to contain).
	AcceptsRuleApprovals bool `json:"accepts_rule_approvals,omitempty"`
	// AcceptsSettings: the server applies settings from the hub
	// (hub.accept_settings). SettingsVersion is the version it has applied.
	AcceptsSettings bool   `json:"accepts_settings"`
	SettingsVersion string `json:"settings_version,omitempty"`
	// AcceptsLearning: hub operators may start a learning run
	// (hub.accept_learning). Learning is true while one runs.
	AcceptsLearning bool `json:"accepts_learning"`
	Learning        bool `json:"learning,omitempty"`
	// AcceptsUpgrades: hub operators may start an upgrade to the hub's
	// version (hub.accept_upgrades). Upgrade is the last one asked for.
	AcceptsUpgrades bool           `json:"accepts_upgrades"`
	Upgrade         *UpgradeStatus `json:"upgrade,omitempty"`
	// Models is the model each role uses now; Actions is each enabled
	// containment action's effective rule (auto | approve | off) after the
	// root policy and the hub's rules.
	Models  map[string]string `json:"models,omitempty"`
	Actions map[string]string `json:"actions,omitempty"`

	// BaselineSweep of BaselineSweeps baseline snapshots are taken while the
	// learning phase collects them; BaselineETA is when the last is due.
	BaselineSweep  int    `json:"baseline_sweep,omitempty"`
	BaselineSweeps int    `json:"baseline_sweeps,omitempty"`
	BaselineETA    string `json:"baseline_eta,omitempty"`
	// BaselineAt is when the last baseline was completed: while the phase is
	// still learning after it, the learning session or assessment runs.
	BaselineAt string `json:"baseline_at,omitempty"`
	// SettingsSaved is a settings version received from the hub and saved,
	// which the server applies at its next restart (as soon as no agent
	// session runs). Empty once applied.
	SettingsSaved string `json:"settings_saved,omitempty"`
	// Tuning is the value of each hub-settable setting (Tunings) in effect.
	Tuning map[string]string `json:"tuning,omitempty"`
	// Software is the daily software check: versions and the CVE feed.
	Software *Software `json:"software,omitempty"`
}

// UpgradeStatus is an upgrade of kodeblue an operator asked for: waiting
// (until no learning or agent session runs), installing, done or failed.
type UpgradeStatus struct {
	To     string    `json:"to"`
	From   string    `json:"from,omitempty"`
	State  string    `json:"state"`
	Detail string    `json:"detail,omitempty"`
	By     string    `json:"by,omitempty"`
	At     time.Time `json:"at"`
}

// Software is how up to date a server is and what the CVE feed found.
type Software struct {
	CheckedAt       string   `json:"checked_at,omitempty"`
	OS              string   `json:"os,omitempty"`
	SupportEnds     string   `json:"support_ends,omitempty"` // end of standard support (YYYY-MM-DD)
	ExtendedEnds    string   `json:"extended_ends,omitempty"`
	RebootRequired  bool     `json:"reboot_required,omitempty"`
	Updates         int      `json:"updates"`
	SecurityUpdates int      `json:"security_updates"`
	ListsUpdated    string   `json:"lists_updated,omitempty"`
	Images          []string `json:"images,omitempty"`

	Feed CVEFeedStatus `json:"feed"`
}

// CVEFeedStatus is the CVE feed's state on a server.
type CVEFeedStatus struct {
	// Sources in effect; Allowed are those the server's own config allows
	// the hub to turn on.
	Sources  []string `json:"sources"`
	Allowed  []string `json:"allowed"`
	LastPull string   `json:"last_pull,omitempty"`
	Through  string   `json:"through,omitempty"` // CVEs are covered up to here
	Failures int      `json:"failures,omitempty"`
	// Matches are the CVEs of the last 30 days naming software here, most
	// urgent first (at most 25).
	Matches []CVEMatch `json:"matches,omitempty"`
	Total   int        `json:"total"`
}

// CVEMatch is a CVE that names software on the server.
type CVEMatch struct {
	ID       string  `json:"id"`
	Severity string  `json:"severity,omitempty"`
	Score    float64 `json:"score,omitempty"`
	KEV      bool    `json:"kev,omitempty"`
	Term     string  `json:"term"`
	From     string  `json:"from"`
	How      string  `json:"how"`
	FoundAt  string  `json:"found_at"`
	Summary  string  `json:"summary,omitempty"`
}

// Record is one object the hub stores per server, keyed by (Kind, ID).
// Kinds: incident, finding, monitor, allow_rule, journal, action, pending_action,
// session, report, skill, definition, service, vulnerability — and
// notification: an update for the team's Slack channel, which the hub stores
// once and posts itself.
type Record struct {
	Kind      string          `json:"kind"`
	ID        string          `json:"id"`
	UpdatedAt time.Time       `json:"updated_at"`
	Data      json.RawMessage `json:"data"`
}

type SyncRequest struct {
	Status  Status   `json:"status"`
	Records []Record `json:"records"`
	// Replace lists kinds whose full set is in Records; the hub deletes rows
	// of those kinds that are not present (monitors, allow rules, pending).
	Replace []string `json:"replace,omitempty"`
}

type SyncResponse struct {
	OK         bool      `json:"ok"`
	ServerTime time.Time `json:"server_time"`
	// Pending tells the agent operator messages are waiting.
	Pending int `json:"pending_messages"`
	// Settings is sent when the server accepts hub settings and the version
	// it reported differs from the hub's. A Settings with an empty Version
	// clears what the server applied before.
	Settings *Settings `json:"settings,omitempty"`
}

// Model roles: Default covers every role without its own model. Critical is
// the responder on critical incidents.
const (
	RoleDefault      = "default"
	RoleTriage       = "triage"
	RoleLearner      = "learner"
	RoleResponder    = "responder"
	RoleReviewer     = "reviewer"
	RoleInvestigator = "investigator"
	RoleOperator     = "operator"
	RoleCritical     = "critical"
	// RoleAll in Instructions applies to every agent.
	RoleAll = "all"
)

// ModelRoles are the keys Settings.Models accepts.
var ModelRoles = []string{RoleDefault, RoleTriage, RoleLearner, RoleResponder, RoleReviewer, RoleInvestigator, RoleOperator, RoleCritical}

// InstructionRoles are the keys Settings.Instructions accepts. Triage has
// none: its answer must stay strict JSON.
var InstructionRoles = []string{RoleAll, RoleLearner, RoleResponder, RoleReviewer, RoleInvestigator, RoleOperator}

// MaxInstructions bounds one role's extra instructions.
const MaxInstructions = 8000

// Approval rules per containment action.
const (
	ActionAuto    = "auto"    // run without asking, if the server's root policy is contain
	ActionApprove = "approve" // always wait for a human
	ActionOff     = "off"     // never run; the agent may only recommend it
)

// Settings is what hub operators chose for one server: the fleet defaults
// with that server's overrides applied. The server applies them only with
// [hub] accept_settings. Approval rules can only tighten the server's
// root-owned response policy, never loosen it.
type Settings struct {
	Version string `json:"version"`
	// Connections are model endpoints the hub configured; Models picks a
	// model on one of them (or on the server's own [inference] endpoint,
	// connection "") per role.
	Connections  []Connection        `json:"connections,omitempty"`
	Models       map[string]ModelRef `json:"model_refs,omitempty"`   // role -> model
	Instructions map[string]string   `json:"instructions,omitempty"` // role -> extra instructions
	Approvals    map[string]string   `json:"approvals,omitempty"`    // action -> auto | approve | off
	// ResponseMode is off | recommend | contain, or empty for the server's
	// own. The server applies it only up to the mode its root-owned config
	// allows: the hub can switch a server between modes but never above
	// that ceiling.
	ResponseMode string `json:"response_mode,omitempty"`
	// Tuning sets server settings by key (see Tunings): cost, cadence and
	// noise. The server checks each value again and caps the budget.
	Tuning map[string]string `json:"tuning,omitempty"`
	// ProtectedUsers, ProtectedIPs and ProtectedUnits are added to the
	// server's own protected lists (never replace them), and
	// MaxActionsPerHour can only lower its containment rate limit.
	ProtectedUsers    []string `json:"protected_users,omitempty"`
	ProtectedIPs      []string `json:"protected_ips,omitempty"`
	ProtectedUnits    []string `json:"protected_units,omitempty"`
	MaxActionsPerHour int      `json:"max_actions_per_hour,omitempty"`
}

// ResponseModes in order of what they allow.
var ResponseModes = []string{"off", "recommend", "contain"}

// ModeRank orders response modes (-1 for an unknown one).
func ModeRank(m string) int {
	for i, x := range ResponseModes {
		if x == m {
			return i
		}
	}
	return -1
}

// Connection kinds. All are OpenAI-compatible: {BaseURL}/v1/chat/completions
// and {BaseURL}/v1/models. They differ in how the hub reads their catalog.
const (
	// ConnInferenceManager is a gateway whose /v1/models entries carry the
	// vendor ("provider") each model is routed to.
	ConnInferenceManager = "inference-manager"
	ConnOpenRouter       = "openrouter"
	ConnOpenAI           = "openai-compatible"
)

// ConnectionKinds are the kinds a Connection may have.
var ConnectionKinds = []string{ConnInferenceManager, ConnOpenRouter, ConnOpenAI}

// Connection is one model endpoint. ID is short and stable: it names the
// endpoint inside the agent runtime ("<id>:<provider>").
type Connection struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Name    string `json:"name,omitempty"`
	BaseURL string `json:"base_url"`
	APIKey  string `json:"api_key,omitempty"`
}

// ModelRef is a model on a connection. Provider is the vendor label the
// connection routes it to (inference manager), or empty for the kind's
// default.
type ModelRef struct {
	Connection string `json:"connection,omitempty"`
	Provider   string `json:"provider,omitempty"`
	Model      string `json:"model"`
}

// UnmarshalJSON also takes a bare model ID, the shape older hubs stored.
func (r *ModelRef) UnmarshalJSON(b []byte) error {
	var id string
	if json.Unmarshal(b, &id) == nil {
		*r = ModelRef{Model: id}
		return nil
	}
	type plain ModelRef
	return json.Unmarshal(b, (*plain)(r))
}

// DefaultProvider is the provider label used for a connection kind when a
// ModelRef names none.
func DefaultProvider(kind string) string {
	if kind == ConnOpenRouter {
		return ConnOpenRouter
	}
	return ConnOpenAI
}

var (
	connIDRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	providerRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
)

// ValidConnectionID reports whether id may name a connection.
func ValidConnectionID(id string) bool { return connIDRe.MatchString(id) }

// ValidProvider reports whether p may be a provider label.
func ValidProvider(p string) bool { return p == "" || providerRe.MatchString(p) }

// OperatorMessage is a message an authenticated hub operator sent to this
// server's kodeblue.
type OperatorMessage struct {
	// CouncilPhase controls report presentation only; it grants no additional tools.
	CouncilPhase   string    `json:"council_phase,omitempty"`
	ID             int64     `json:"id"`
	Author         string    `json:"author"`
	Body           string    `json:"body"`
	IncidentID     int64     `json:"incident_id,omitempty"`
	ConversationID string    `json:"conversation_id"`
	CreatedAt      time.Time `json:"created_at"`
	// Decision ("approve" | "deny") makes this a ruling on the pending
	// containment request RequestID instead of a message for the agent. The
	// server handles it without a model, under its own response policy. A
	// vulnerability command names its vulnerability in RequestID.
	Decision  string `json:"decision,omitempty"`
	RequestID string `json:"request_id,omitempty"`
	// Command (CommandLearn | CommandRelearn | CommandStop, or a
	// vulnerability or containment rule command) makes this a request to
	// run learning, stop a session or change a vulnerability or rule, not a
	// message for the agent.
	Command string `json:"command,omitempty"`
	// SessionID names the running session CommandStop aborts (optional for
	// other commands).
	SessionID string `json:"session_id,omitempty"`
	// RuleHash is the content of the containment rule RequestID the
	// operator saw when approving it; the server refuses an approval of
	// anything else.
	RuleHash string `json:"rule_hash,omitempty"`
}

// Learning commands an operator can send from the hub.
const (
	// CommandLearn runs the learner agent now on the baseline the server
	// already has; detection keeps running.
	CommandLearn       = "learn"
	CommandInvestigate = "investigate"
	// CommandRelearn runs the whole learning phase again: baseline sweeps
	// (changes seen meanwhile are absorbed as normal), then the learner.
	CommandRelearn = "relearn"
	// CommandStop aborts a running agent session (by SessionID, or the
	// session of IncidentID). Detection and other sessions keep running.
	CommandStop = "stop"
	// CommandUpgrade upgrades kodeblue to the release named in Body (the
	// hub's own version), once no learning or agent session runs. Only an
	// operator starts it; nothing upgrades on its own.
	CommandUpgrade = "upgrade"
)

// Vulnerability commands an operator can send from the hub. The server
// applies them without a model; Body is the operator's note.
const (
	// CommandVulnAccept records a vulnerability as a risk the team keeps.
	CommandVulnAccept = "vuln_accept"
	// CommandVulnReopen opens an accepted or resolved vulnerability again.
	CommandVulnReopen = "vuln_reopen"
	// CommandVulnRecheck runs the vulnerability's check now.
	CommandVulnRecheck = "vuln_recheck"
)

// VulnCommands are the vulnerability commands.
var VulnCommands = []string{CommandVulnAccept, CommandVulnReopen, CommandVulnRecheck}

// Containment rule commands an operator can send from the hub. RequestID
// names the rule and Body is the operator's note. Approving and deleting
// need hub.accept_approvals on the server; the root helper checks them.
const (
	// CommandRuleApprove makes a proposed rule active (or renews one).
	CommandRuleApprove = "rule_approve"
	// CommandRuleReject turns a proposal down.
	CommandRuleReject = "rule_reject"
	// CommandRulePause stops an active rule; approving resumes it.
	CommandRulePause = "rule_pause"
	// CommandRuleDelete removes a rule for good.
	CommandRuleDelete = "rule_delete"
)

// RuleCommands are the containment rule commands.
var RuleCommands = []string{CommandRuleApprove, CommandRuleReject, CommandRulePause, CommandRuleDelete}

type MessagesResponse struct {
	Messages []OperatorMessage `json:"messages"`
}

type MessageReply struct {
	Status    string  `json:"status"` // done | failed | refused
	Text      string  `json:"text"`
	SessionID string  `json:"session_id,omitempty"`
	CostUSD   float64 `json:"cost_usd,omitempty"`
}

// Transcript is an agent session as the hub shows it: what the model said,
// its reasoning, and every tool call with a bounded result.
type Transcript struct {
	SessionID  string    `json:"session_id"`
	IncidentID int64     `json:"incident_id,omitempty"`
	Kind       string    `json:"kind,omitempty"`
	Title      string    `json:"title,omitempty"`
	Running    bool      `json:"running"`
	Turns      []Turn    `json:"turns"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type Turn struct {
	Role      string     `json:"role"`
	Text      string     `json:"text,omitempty"`
	Reasoning string     `json:"reasoning,omitempty"`
	Tools     []ToolStep `json:"tools,omitempty"`
	At        time.Time  `json:"at"`
	CostUSD   float64    `json:"cost_usd,omitempty"`
}

type ToolStep struct {
	ID      string `json:"id,omitempty"`
	Name    string `json:"name"`
	Args    string `json:"args,omitempty"`
	Result  string `json:"result,omitempty"`
	IsError bool   `json:"is_error,omitempty"`
}
