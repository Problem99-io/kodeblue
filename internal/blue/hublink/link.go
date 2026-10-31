// Package hublink connects one kodeblue to the kodeblue hub. Everything is
// outbound from the server: a periodic sync pushes state (status, incidents,
// findings, monitors, journal, agent transcripts, reports), and a long-poll
// picks up messages operators send from the hub. The server never listens.
package hublink

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/config"
	"github.com/Problem99-io/kodeblue/internal/blue/containment"
	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
	"github.com/Problem99-io/kodeblue/internal/blue/mcpserver"
	"github.com/Problem99-io/kodeblue/internal/blue/notify"
	"github.com/Problem99-io/kodeblue/internal/blue/respond"
	"github.com/Problem99-io/kodeblue/internal/blue/sensors"
	"github.com/Problem99-io/kodeblue/internal/blue/services"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

// Agent is what the daemon provides to the link.
type Agent interface {
	Phase() string
	ModelsEnabled() bool
	// Transcript returns the session's turns (live progress included while
	// running), or an error when the model runtime is not available.
	Transcript(ctx context.Context, sessionID string, running bool) ([]hubproto.Turn, error)
	// LiveSessions lists sessions with a run in progress (session -> incident).
	LiveSessions() map[string]int64
	HandleOperatorMessage(ctx context.Context, m hubproto.OperatorMessage) hubproto.MessageReply
	// ApplySettings is called after new hub settings were saved.
	ApplySettings()
	// Learn starts the learning command m.Command and returns once it has
	// started (or was refused); Learning reports whether learning runs now.
	Learn(ctx context.Context, m hubproto.OperatorMessage) hubproto.MessageReply
	Learning() bool
	// Maintenance returns the end of the maintenance window being enforced
	// (RFC 3339), or "" when none is open.
	Maintenance() string
	// StopSession aborts a running agent session named by the operator
	// message (SessionID, or the session of IncidentID).
	StopSession(ctx context.Context, m hubproto.OperatorMessage) hubproto.MessageReply
	// DecisionMade is called after an operator decision on a containment
	// request was carried out, so the incident's agent can continue.
	DecisionMade()
	// Software is the daily software check: versions and the CVE feed.
	Software() *hubproto.Software
	// Upgrade records an operator's upgrade to the release m.Body, which
	// starts once no learning or agent session runs; UpgradeStatus is the
	// last one asked for.
	Upgrade(m hubproto.OperatorMessage) hubproto.MessageReply
	UpgradeStatus() *hubproto.UpgradeStatus
}

type Link struct {
	cfg    config.Config
	st     *store.Store
	log    *slog.Logger
	agent  Agent
	base   string
	key    string
	client *http.Client
	poll   *http.Client

	mu     sync.Mutex
	hashes map[string]string // record kind/id -> content hash last accepted by the hub
	nudge  chan struct{}
	recent []time.Time // operator messages handled in the last hour
	// deciding holds containment requests a ruling is being carried out on.
	deciding map[string]bool
	// savedSettings is the settings version saved and waiting for the
	// restart that applies it.
	savedSettings *string
}

func New(cfg config.Config, st *store.Store, logger *slog.Logger, agent Agent) (*Link, error) {
	u, err := hubproto.CheckURL(cfg.Hub.URL)
	if err != nil {
		return nil, err
	}
	key, err := cfg.Hub.APIKey()
	if err != nil {
		return nil, err
	}
	c, err := hubproto.HTTPClient(cfg.Hub.Pin, cfg.Hub.CAFile, 60*time.Second)
	if err != nil {
		return nil, err
	}
	p, _ := hubproto.HTTPClient(cfg.Hub.Pin, cfg.Hub.CAFile, 70*time.Second)
	return &Link{cfg: cfg, st: st, log: logger, agent: agent, base: u.String(), key: key, client: c, poll: p,
		hashes: map[string]string{}, nudge: make(chan struct{}, 1)}, nil
}

// Nudge asks for a sync soon (an incident changed, a reply is ready).
func (l *Link) Nudge() {
	select {
	case l.nudge <- struct{}{}:
	default:
	}
}

// Run blocks until ctx ends.
func (l *Link) Run(ctx context.Context) {
	l.log.Info("hub link starting", "hub", l.base, "messages", l.cfg.Hub.AcceptMessages)
	go l.messageLoop(ctx)
	every := time.Duration(max(l.cfg.Hub.SyncSeconds, 5)) * time.Second
	const firstRetry = 5 * time.Second
	backoff := firstRetry
	for {
		err := l.syncOnce(ctx)
		wait := every
		if len(l.agent.LiveSessions()) > 0 {
			wait = min(every, 5*time.Second) // an agent is working: stream it
		}
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			// 5s, 10s, 20s … 5m: a hub restart is caught up quickly, an
			// outage is not hammered.
			wait = backoff
			backoff = min(backoff*2, 5*time.Minute)
			l.log.Warn("hub sync failed", "error", err, "retry_in", wait)
		} else {
			backoff = firstRetry
		}
		if !l.pause(ctx, wait, err == nil) {
			return
		}
	}
}

// pause waits d before the next sync. When the hub is reachable it ends
// early for a nudge (coalescing bursts) or for a queued notification, so
// updates reach Slack within seconds instead of at the next full sync.
func (l *Link) pause(ctx context.Context, d time.Duration, healthy bool) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	tick := time.NewTicker(3 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-timer.C:
			return true
		case <-tick.C:
			if healthy && len(l.st.UnsyncedNotifications(1)) > 0 {
				return true
			}
		case <-l.nudge:
			if healthy {
				select {
				case <-ctx.Done():
					return false
				case <-time.After(2 * time.Second):
				}
				return true
			}
		}
	}
}

type cursor struct {
	Incidents int64 `json:"incidents"`
	Findings  int64 `json:"findings"`
	Journal   int64 `json:"journal"`
}

func (l *Link) syncOnce(ctx context.Context) error {
	var cur cursor
	_ = json.Unmarshal([]byte(l.st.Get("hub_cursor")), &cur)
	now := time.Now()
	// Re-send a small overlap: rows updated in the same second as the cursor.
	incSince := time.Unix(max(cur.Incidents-1, 0), 0)
	findSince := time.Unix(max(cur.Findings-1, 0), 0)

	req := hubproto.SyncRequest{Status: l.status()}
	next := cur
	pending := map[string]string{} // hashes to commit after a successful sync

	add := func(kind, id string, at time.Time, v any) {
		data, err := json.Marshal(v)
		if err != nil {
			return
		}
		h := sha(data)
		k := kind + "/" + id
		l.mu.Lock()
		same := l.hashes[k] == h
		l.mu.Unlock()
		if same {
			return
		}
		pending[k] = h
		req.Records = append(req.Records, hubproto.Record{Kind: kind, ID: id, UpdatedAt: at, Data: data})
	}
	// addSet sends a whole collection when any member changed, so the hub can
	// drop members that disappeared.
	addSet := func(kind string, items map[string]any, at time.Time) {
		data, _ := json.Marshal(items)
		h := sha(data)
		l.mu.Lock()
		same := l.hashes["set/"+kind] == h
		l.mu.Unlock()
		if same {
			return
		}
		pending["set/"+kind] = h
		req.Replace = append(req.Replace, kind)
		for id, v := range items {
			b, _ := json.Marshal(v)
			req.Records = append(req.Records, hubproto.Record{Kind: kind, ID: id, UpdatedAt: at, Data: b})
		}
	}

	sessions := map[string]int64{}
	for _, in := range l.st.Incidents(`WHERE updated_at>=? ORDER BY updated_at LIMIT 200`, incSince.Unix()) {
		add("incident", fmt.Sprint(in.ID), in.UpdatedAt, in)
		next.Incidents = max(next.Incidents, in.UpdatedAt.Unix())
		if in.SessionID != "" {
			sessions[in.SessionID] = in.ID
		}
	}
	for _, f := range l.st.FindingsUpdatedSince(findSince, 500) {
		add("finding", fmt.Sprint(f.ID), f.UpdatedAt, f)
		next.Findings = max(next.Findings, f.UpdatedAt.Unix())
	}
	for _, j := range l.st.JournalAfter(cur.Journal, 1000) {
		add("journal", fmt.Sprint(j.ID), j.At, j)
		next.Journal = max(next.Journal, j.ID)
	}

	mons := map[string]any{}
	for _, m := range l.st.Monitors(true) {
		mons[m.ID] = m
	}
	addSet("monitor", mons, now)
	rules := map[string]any{}
	for _, r := range l.st.AllowRules() {
		rules[fmt.Sprint(r.ID)] = r
	}
	addSet("allow_rule", rules, now)
	actions := map[string]any{}
	journal := respond.Load(l.cfg.Response.StateDir)
	for _, r := range journal {
		actions[r.ID] = r // later records (undo) replace earlier ones
	}
	addSet("action", actions, now)
	pendingActs := map[string]any{}
	for _, r := range mcpserver.LoadRequests(l.cfg) {
		pendingActs[r.ID] = r
	}
	addSet("pending_action", pendingActs, now)
	addSet("report", l.files(filepath.Join(l.cfg.WorkspaceDir(), "reports"), "*.md"), now)
	addSet("skill", l.files(filepath.Join(l.cfg.WorkspaceDir(), ".kodeblue", "skills"), "*/SKILL.md"), now)
	addSet("definition", l.files(filepath.Join(l.cfg.WorkspaceDir(), ".kodeblue", "definitions"), "*"), now)
	svcs := map[string]any{}
	var inv services.Inventory
	if json.Unmarshal([]byte(l.st.Get(services.InventoryKey)), &inv) == nil {
		for _, r := range inv.Services {
			svcs[r.Name] = r
		}
	}
	addSet("service", svcs, now)
	vulns := map[string]any{}
	for _, v := range l.st.Vulnerabilities(`ORDER BY id`) {
		vulns[v.ID] = v
	}
	addSet("vulnerability", vulns, now)
	crules := map[string]any{}
	for _, v := range containment.ListWith(l.cfg, l.st, journal) {
		crules[v.ID] = v
	}
	addSet("containment_rule", crules, now)

	if l.cfg.Hub.ShareTranscripts {
		for sid, inc := range l.agent.LiveSessions() {
			sessions[sid] = inc
		}
		live := l.agent.LiveSessions()
		for sid, inc := range sessions {
			_, running := live[sid]
			turns, err := l.agent.Transcript(ctx, sid, running)
			if err != nil || len(turns) == 0 {
				continue
			}
			t := hubproto.Transcript{SessionID: sid, IncidentID: inc, Running: running, Turns: turns, UpdatedAt: turns[len(turns)-1].At}
			if in := l.st.GetIncident(inc); in != nil {
				t.Kind, t.Title = in.Kind, in.Title
			}
			add("session", sid, t.UpdatedAt, t)
		}
	}

	// Notifications: the hub owns Slack. They are sent until the hub accepts
	// them (it de-duplicates by id), so none is lost while it is unreachable.
	var queued []int64
	for _, n := range l.st.UnsyncedNotifications(200) {
		b, _ := json.Marshal(n)
		req.Records = append(req.Records, hubproto.Record{Kind: "notification", ID: fmt.Sprint(n.ID), UpdatedAt: n.At, Data: b})
		queued = append(queued, n.ID)
	}

	var resp hubproto.SyncResponse
	if err := l.call(ctx, l.client, http.MethodPost, hubproto.PathSync, req, &resp); err != nil {
		return err
	}
	l.st.MarkNotificationsSynced(queued)
	if resp.Settings != nil {
		l.saveSettings(resp.Settings)
	}
	l.mu.Lock()
	for k, h := range pending {
		l.hashes[k] = h
	}
	l.mu.Unlock()
	b, _ := json.Marshal(next)
	_ = l.st.Set("hub_cursor", string(b))
	_ = l.st.Set("hub_last_sync", now.UTC().Format(time.RFC3339))
	return nil
}

// files reads small text files matching pattern under dir.
func (l *Link) files(dir, pattern string) map[string]any {
	out := map[string]any{}
	matches, _ := filepath.Glob(filepath.Join(dir, pattern))
	for _, p := range matches {
		st, err := os.Stat(p)
		if err != nil || st.IsDir() || st.Size() > 256<<10 {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		rel, _ := filepath.Rel(dir, p)
		out[rel] = map[string]any{"name": rel, "content": string(b), "modified": st.ModTime().UTC()}
	}
	return out
}

func (l *Link) status() hubproto.Status {
	host, _ := os.Hostname()
	day := time.Now().UTC().Truncate(24 * time.Hour)
	usd, per, tokens := l.st.SpentSince(day)
	week, _, _ := l.st.SpentSince(time.Now().Add(-7 * 24 * time.Hour))
	s := hubproto.Status{
		Name: l.cfg.Server.Name, Hostname: host, Version: hubproto.Version, OS: osRelease(l.cfg.Server.Root) + " " + runtime.GOARCH,
		Kernel: firstLine(filepath.Join(l.cfg.Server.Root, "proc/sys/kernel/osrelease")), Uptime: uptime(l.cfg.Server.Root),
		Phase: l.agent.Phase(), ResponseMode: l.cfg.Response.Mode, RootMode: l.cfg.RootResponseMode, ModeCeiling: l.cfg.ModeCeiling(), ModelsEnabled: l.agent.ModelsEnabled(),
		TriageModel: l.cfg.ModelFor(hubproto.RoleTriage), AgentModel: l.cfg.ModelFor(hubproto.RoleResponder),
		Heartbeat: l.st.Get("heartbeat"), LearnedAt: l.st.Get("learned_at"), LearnerPending: l.st.Get(store.LearnerPendingKey) != "", LastReviewAt: l.st.Get("last_review_at"),
		SpendToday: usd, SpendByPurpose: per, Spend7d: week, DailyBudget: l.cfg.Budget.DailyUSD, TokensToday: tokens,
		Baseline: l.st.BaselineCounts(), CollectorRuns: l.st.CollectorRuns(), Profile: l.st.Get("profile_summary"),
		FindingStats7d: l.st.FindingStats(time.Now().Add(-7 * 24 * time.Hour)), AcceptsMessages: l.cfg.Hub.AcceptMessages,
		AcceptsApprovals: l.cfg.Hub.AcceptApprovals, AcceptsRuleApprovals: l.cfg.Hub.AcceptApprovals && l.cfg.Response.HubMayAutomate(),
		AcceptsSettings: l.cfg.Hub.AcceptSettings, SettingsVersion: l.cfg.HubSettingsVersion,
		AcceptsLearning: l.cfg.Hub.AcceptLearning, Learning: l.agent.Learning(),
		AcceptsUpgrades: l.cfg.Hub.AcceptUpgrades, Upgrade: l.agent.UpgradeStatus(),
		Models: l.cfg.EffectiveModels(), Actions: map[string]string{}, Tuning: l.cfg.TuningValues(),
	}
	for _, a := range respond.ActionNames() {
		s.Actions[a] = l.cfg.ActionRule(a)
	}
	// The window the daemon enforces, not the file's raw (kodeblue-writable,
	// possibly far-future) content.
	s.Maintenance = l.agent.Maintenance()
	s.Software = l.agent.Software()
	if s.Phase == "learning" {
		s.BaselineSweep, s.BaselineSweeps, s.BaselineETA = l.st.BaselineProgress()
		s.BaselineAt = l.st.Get("baseline_at")
	}
	if l.savedSettings != nil && *l.savedSettings != l.cfg.HubSettingsVersion {
		s.SettingsSaved = *l.savedSettings
	}
	return s
}

// saveSettings stores settings the hub sent and asks the daemon to restart
// with them. Approval rules in them can only tighten the root policy
// (config.ActionRule); the root helper never reads them.
func (l *Link) saveSettings(s *hubproto.Settings) {
	if !l.cfg.Hub.AcceptSettings || s.Version == l.cfg.HubSettingsVersion {
		return
	}
	if l.savedSettings != nil && *l.savedSettings == s.Version {
		return
	}
	if err := checkSettings(s); err != nil {
		l.log.Warn("ignoring hub settings", "version", s.Version, "error", err)
		return
	}
	if err := l.cfg.SaveHubSettings(s); err != nil {
		l.log.Error("save hub settings", "error", err)
		return
	}
	v := s.Version
	l.savedSettings = &v
	l.st.Journal("hub", "hub.settings", fmt.Sprintf("saved settings %q from the hub", v))
	l.log.Info("hub settings saved; applying them when no agent session runs", "version", v)
	l.agent.ApplySettings()
}

// checkSettings bounds what the hub can hand over.
func checkSettings(s *hubproto.Settings) error {
	ids := map[string]bool{}
	for _, c := range s.Connections {
		u, err := url.Parse(c.BaseURL)
		if !hubproto.ValidConnectionID(c.ID) || ids[c.ID] || !slices.Contains(hubproto.ConnectionKinds, c.Kind) ||
			err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return fmt.Errorf("bad model connection %q", c.ID)
		}
		ids[c.ID] = true
	}
	for role, m := range s.Models {
		if !slices.Contains(hubproto.ModelRoles, role) || m.Model == "" || len(m.Model) > 200 || strings.ContainsAny(m.Model, "\n\r") ||
			!hubproto.ValidProvider(m.Provider) || (m.Connection != "" && !ids[m.Connection]) {
			return fmt.Errorf("bad model for %q", role)
		}
	}
	for role, t := range s.Instructions {
		if !slices.Contains(hubproto.InstructionRoles, role) || len(t) > hubproto.MaxInstructions {
			return fmt.Errorf("bad instructions for %q", role)
		}
	}
	for _, r := range s.Approvals {
		if r != hubproto.ActionAuto && r != hubproto.ActionApprove && r != hubproto.ActionOff {
			return fmt.Errorf("bad approval rule %q", r)
		}
	}
	if err := hubproto.CheckTuning(s.Tuning); err != nil {
		return err
	}
	if err := hubproto.CheckProtected(s.ProtectedUsers, s.ProtectedIPs, s.ProtectedUnits); err != nil {
		return err
	}
	if s.MaxActionsPerHour < 0 {
		return errors.New("bad max_actions_per_hour")
	}
	return nil
}

// ---- operator messages ----

// messageLoop polls the hub for operator messages. Chat admission is ordered,
// but its answer waits independently so more input can steer a live session.
// Legacy agents and learning commands retain the serial queue. Stop and
// approve/deny run as soon as they arrive, since they often concern that session.
// Containment rule rulings take no model either, and pausing a rule that
// misfires must not wait.
func (l *Link) messageLoop(ctx context.Context) {
	queue := make(chan hubproto.OperatorMessage, 64)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case m := <-queue:
				if _, ok := l.agent.(operatorMessageStarter); ok && m.Decision == "" && m.Command == "" {
					wait := l.beginChat(ctx, m)
					go func(m hubproto.OperatorMessage, wait func() hubproto.MessageReply) {
						l.sendReply(ctx, m.ID, wait())
						l.Nudge()
					}(m, wait)
				} else {
					l.answer(ctx, m)
				}
			}
		}
	}()
	backoff := 5 * time.Second
	for ctx.Err() == nil {
		var resp hubproto.MessagesResponse
		err := l.call(ctx, l.poll, http.MethodGet, hubproto.PathMessages+"?wait=50", nil, &resp)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			backoff = min(backoff*2, 5*time.Minute)
			l.log.Debug("hub message poll failed", "error", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			continue
		}
		backoff = 5 * time.Second
		for _, m := range resp.Messages {
			if m.Decision != "" || m.Command == hubproto.CommandStop || m.Command == hubproto.CommandUpgrade || slices.Contains(hubproto.RuleCommands, m.Command) {
				go l.answer(ctx, m)
				continue
			}
			select {
			case queue <- m:
			default:
				go l.sendReply(ctx, m.ID, hubproto.MessageReply{Status: "refused", Text: "Operator admission queue is full; try again later."})
			case <-ctx.Done():
				return
			}
		}
	}
}

func (l *Link) answer(ctx context.Context, m hubproto.OperatorMessage) {
	l.sendReply(ctx, m.ID, l.handle(ctx, m))
	if m.Decision != "" {
		l.agent.DecisionMade()
	}
	l.Nudge()
}

func (l *Link) handle(ctx context.Context, m hubproto.OperatorMessage) hubproto.MessageReply {
	if m.Decision != "" {
		return l.decide(ctx, m)
	}
	if m.Command != "" {
		l.st.Journal("hub:"+m.Author, "operator.command", fmt.Sprintf("#%d %s", m.ID, m.Command))
		if m.Command == hubproto.CommandStop {
			return l.agent.StopSession(ctx, m)
		}
		if slices.Contains(hubproto.VulnCommands, m.Command) {
			return l.vulnCommand(ctx, m)
		}
		if slices.Contains(hubproto.RuleCommands, m.Command) {
			return l.ruleCommand(ctx, m)
		}
		if m.Command == hubproto.CommandUpgrade {
			if !l.cfg.Hub.AcceptUpgrades {
				return hubproto.MessageReply{Status: "refused", Text: "This server does not take upgrades from the hub (hub.accept_upgrades = false in /etc/kodeblue/kodeblue.toml). Run on the server: sudo kodeblue upgrade " + m.Body}
			}
			return l.agent.Upgrade(m)
		}
		if m.Command != hubproto.CommandLearn && m.Command != hubproto.CommandRelearn {
			return hubproto.MessageReply{Status: "refused", Text: "Unknown command " + m.Command}
		}
		if !l.cfg.Hub.AcceptLearning {
			return hubproto.MessageReply{Status: "refused", Text: "This server does not take learning commands from the hub (hub.accept_learning = false in /etc/kodeblue/kodeblue.toml). Run on the server: kodeblue relearn"}
		}
		return l.agent.Learn(ctx, m)
	}
	return l.beginChat(ctx, m)()
}

// operatorMessageStarter separates admission from waiting for a final answer.
// Admission must finish before the next message is considered, so rapid input
// joins the same session in arrival order, including the first poll batch.
type operatorMessageStarter interface {
	BeginOperatorMessage(context.Context, hubproto.OperatorMessage) func() hubproto.MessageReply
}

func (l *Link) beginChat(ctx context.Context, m hubproto.OperatorMessage) func() hubproto.MessageReply {
	l.st.Journal("hub:"+m.Author, "operator.message", fmt.Sprintf("#%d %s", m.ID, clip(m.Body, 300)))
	if !l.cfg.Hub.AcceptMessages {
		return func() hubproto.MessageReply {
			return hubproto.MessageReply{Status: "refused", Text: "This server does not accept operator messages (hub.accept_messages = false in /etc/kodeblue/kodeblue.toml)."}
		}
	}
	l.mu.Lock()
	cut := 0
	for cut < len(l.recent) && time.Since(l.recent[cut]) > time.Hour {
		cut++
	}
	l.recent = l.recent[cut:]
	limited := l.cfg.Hub.MessagesPerHour > 0 && len(l.recent) >= l.cfg.Hub.MessagesPerHour
	if !limited {
		l.recent = append(l.recent, time.Now())
	}
	l.mu.Unlock()
	if limited {
		return func() hubproto.MessageReply {
			return hubproto.MessageReply{Status: "refused", Text: fmt.Sprintf("Rate limit: this server handles at most %d operator messages per hour.", l.cfg.Hub.MessagesPerHour)}
		}
	}
	if starter, ok := l.agent.(operatorMessageStarter); ok {
		return starter.BeginOperatorMessage(ctx, m)
	}
	return func() hubproto.MessageReply { return l.agent.HandleOperatorMessage(ctx, m) }
}

// vulnCommand applies an operator's change to a vulnerability. No model is
// involved: accepting a risk is the team's decision, and a recheck runs the
// vulnerability's own check.
func (l *Link) vulnCommand(ctx context.Context, m hubproto.OperatorMessage) hubproto.MessageReply {
	if !l.cfg.Hub.AcceptMessages {
		return hubproto.MessageReply{Status: "refused", Text: "This server does not take changes from the hub (hub.accept_messages = false in /etc/kodeblue/kodeblue.toml)."}
	}
	v := l.st.GetVulnerability(m.RequestID)
	if v == nil {
		return hubproto.MessageReply{Status: "refused", Text: "No vulnerability " + m.RequestID + " on this server."}
	}
	by, note := "hub:"+m.Author, strings.TrimSpace(m.Body)
	switch m.Command {
	case hubproto.CommandVulnAccept:
		if note == "" {
			return hubproto.MessageReply{Status: "refused", Text: "Say why the risk is accepted."}
		}
		if err := l.st.SetVulnerabilityStatus(v.ID, store.VulnAccepted, by, note); err != nil {
			return hubproto.MessageReply{Status: "failed", Text: err.Error()}
		}
		return hubproto.MessageReply{Status: "done", Text: "Accepted the risk of " + v.ID + "."}
	case hubproto.CommandVulnReopen:
		if err := l.st.SetVulnerabilityStatus(v.ID, store.VulnOpen, by, note); err != nil {
			return hubproto.MessageReply{Status: "failed", Text: err.Error()}
		}
		return hubproto.MessageReply{Status: "done", Text: "Reopened " + v.ID + "."}
	}
	vc := services.VulnContext{Store: l.st, StateDir: l.cfg.Server.StateDir, Env: &sensors.Env{Root: l.cfg.Server.Root}}
	res, err := vc.RecheckOne(ctx, v.ID)
	if err != nil {
		return hubproto.MessageReply{Status: "refused", Text: err.Error()}
	}
	return hubproto.MessageReply{Status: "done", Text: v.ID + ": " + res + "."}
}

// ruleCommand applies an operator's ruling on a containment rule. No model
// is involved. Approving and deleting go to the root helper, which accepts
// them from the hub only under hub.accept_approvals and checks that the
// approval names the content the operator saw.
func (l *Link) ruleCommand(ctx context.Context, m hubproto.OperatorMessage) hubproto.MessageReply {
	by, note, id := "hub:"+m.Author, strings.TrimSpace(m.Body), m.RequestID
	switch m.Command {
	case hubproto.CommandRuleApprove, hubproto.CommandRuleDelete:
		if m.Command == hubproto.CommandRuleApprove && l.cfg.Hub.AcceptApprovals && !l.cfg.Response.HubMayAutomate() {
			return hubproto.MessageReply{Status: "refused", Text: "An approved rule acts without asking, and this server's root has not let the hub turn that on ([response] hub_max_mode is not contain). Run on the server: sudo kodeblue rules approve " + id}
		}
		if !l.cfg.Hub.AcceptApprovals {
			verb := strings.TrimPrefix(m.Command, "rule_")
			return hubproto.MessageReply{Status: "refused", Text: "This server does not accept approvals from the hub (hub.accept_approvals = false in /etc/kodeblue/kodeblue.toml). Run on the server: sudo kodeblue rules " + verb + " " + id}
		}
	default:
		if !l.cfg.Hub.AcceptMessages {
			return hubproto.MessageReply{Status: "refused", Text: "This server does not take changes from the hub (hub.accept_messages = false in /etc/kodeblue/kodeblue.toml)."}
		}
	}
	if !l.claimRequest("rule:" + id) {
		return hubproto.MessageReply{Status: "refused", Text: "Another ruling on " + id + " is being carried out; this one was not."}
	}
	defer l.releaseRequest("rule:" + id)
	if containment.Get(l.cfg, l.st, id) == nil {
		return hubproto.MessageReply{Status: "refused", Text: "No containment rule " + id + " on this server."}
	}
	switch m.Command {
	case hubproto.CommandRuleApprove:
		r, err := containment.Approve(ctx, l.cfg, l.st, id, m.RuleHash, by)
		if err != nil {
			return hubproto.MessageReply{Status: "refused", Text: "Not approved: " + err.Error()}
		}
		l.st.Journal(by, "rule.approved", id+" until "+r.ExpiresAt.UTC().Format("2006-01-02"))
		return hubproto.MessageReply{Status: "done", Text: fmt.Sprintf("Approved %s. It acts on matching findings until %s.", id, r.ExpiresAt.UTC().Format("2006-01-02"))}
	case hubproto.CommandRuleReject:
		if err := containment.Reject(l.st, id, by, note); err != nil {
			return hubproto.MessageReply{Status: "failed", Text: err.Error()}
		}
		l.st.Journal(by, "rule.rejected", id+": "+note)
		return hubproto.MessageReply{Status: "done", Text: "Rejected the proposal " + id + "."}
	case hubproto.CommandRulePause:
		if _, err := containment.Pause(ctx, l.cfg, l.st, id, by, note); err != nil {
			return hubproto.MessageReply{Status: "refused", Text: "Not paused: " + err.Error()}
		}
		return hubproto.MessageReply{Status: "done", Text: "Paused " + id + ". Approve it again to resume."}
	default:
		if _, err := containment.Delete(ctx, l.cfg, l.st, id, by, note); err != nil {
			return hubproto.MessageReply{Status: "refused", Text: "Not deleted: " + err.Error()}
		}
		l.st.Journal(by, "rule.deleted", id)
		return hubproto.MessageReply{Status: "done", Text: "Deleted " + id + "."}
	}
}

// decide applies an operator's approve/deny on a pending containment request.
// No model is involved: the request is the one the agent recorded, and the
// root helper re-checks it against the root-owned policy before acting.
func (l *Link) decide(ctx context.Context, m hubproto.OperatorMessage) hubproto.MessageReply {
	l.st.Journal("hub:"+m.Author, "operator.decision", fmt.Sprintf("#%d %s %s", m.ID, m.Decision, m.RequestID))
	if !l.cfg.Hub.AcceptApprovals {
		return hubproto.MessageReply{Status: "refused", Text: "This server does not accept approvals from the hub (hub.accept_approvals = false in /etc/kodeblue/kodeblue.toml). Run on the server: kodeblue respond " + m.Decision + " " + m.RequestID}
	}
	// Rulings run concurrently (one goroutine per message): two on the same
	// request must not both find it pending.
	if !l.claimRequest(m.RequestID) {
		return hubproto.MessageReply{Status: "refused", Text: "Another ruling on " + m.RequestID + " is being carried out; this one was not."}
	}
	defer l.releaseRequest(m.RequestID)
	r := mcpserver.FindRequest(l.cfg, m.RequestID)
	if r == nil {
		return hubproto.MessageReply{Status: "refused", Text: "No pending containment request " + m.RequestID + " on this server (already approved, denied or settled)."}
	}
	if m.Decision == "approve" && l.cfg.ActionRule(r.Action) == hubproto.ActionOff {
		return hubproto.MessageReply{Status: "refused", Text: r.Action + " is turned off on this server, so it cannot be approved. Deny the request instead."}
	}
	// Protections and the rate limit the hub added since the request (the
	// root helper only knows the server's own).
	if m.Decision == "approve" {
		if err := respond.Check(l.cfg.Response, *r); err != nil {
			return hubproto.MessageReply{Status: "refused", Text: "This request cannot be approved: " + err.Error() + ". Deny it instead."}
		}
		if err := mcpserver.RateLimited(l.cfg); err != nil {
			return hubproto.MessageReply{Status: "refused", Text: "Not run now: " + err.Error() + ". Approve it again later, or deny it."}
		}
	}
	by := "hub:" + m.Author
	slack := notify.New(l.cfg.Hub.Enabled(), l.st, l.cfg.Notify.SlackWebhookURL, l.cfg.Notify.SlackWebhookFile, l.cfg.Notify.Direct, notify.TelegramFromConfig(l.cfg.Notify.TelegramBotToken, l.cfg.Notify.TelegramBotTokenFile, l.cfg.Notify.TelegramChatID, l.cfg.Notify.TelegramChatIDFile))
	note := func(title, body string) {
		slack.Async(notify.Message{Server: l.cfg.Server.Name, Kind: "action", Severity: "high", IncidentID: r.IncidentID,
			Title: title, Body: body, Fields: map[string]string{"Action id": r.ID, "Operator": m.Author}}, nil)
	}
	switch m.Decision {
	case "deny":
		if err := mcpserver.DenyRequest(l.cfg, r.ID, by); err != nil {
			return hubproto.MessageReply{Status: "failed", Text: "Could not record the denial: " + err.Error()}
		}
		note("Operator denied containment: "+r.Action, r.Justification)
		return hubproto.MessageReply{Status: "done", Text: fmt.Sprintf("Denied %s (%s). Nothing was changed on the host.", r.ID, r.Action)}
	case "approve":
		r.RequestedBy += "+" + by + "+operator"
		rec, err := mcpserver.RunHelper(ctx, l.cfg, *r)
		if err != nil {
			return hubproto.MessageReply{Status: "failed", Text: "The response helper failed: " + err.Error()}
		}
		note("Operator approved containment: "+r.Action+" ("+rec.Status+")", rec.Result)
		st := "done"
		if rec.Status != "done" {
			st = "failed"
		}
		return hubproto.MessageReply{Status: st, Text: fmt.Sprintf("%s %s: %s. %s", r.ID, r.Action, rec.Status, rec.Result)}
	}
	return hubproto.MessageReply{Status: "refused", Text: "Unknown decision " + m.Decision}
}

func (l *Link) claimRequest(id string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.deciding[id] {
		return false
	}
	if l.deciding == nil {
		l.deciding = map[string]bool{}
	}
	l.deciding[id] = true
	return true
}

func (l *Link) releaseRequest(id string) {
	l.mu.Lock()
	delete(l.deciding, id)
	l.mu.Unlock()
}

func (l *Link) sendReply(ctx context.Context, id int64, r hubproto.MessageReply) {
	r.Text = clip(r.Text, 60000)
	for attempt := 0; attempt < 20 && ctx.Err() == nil; attempt++ {
		err := l.call(ctx, l.client, http.MethodPost, fmt.Sprintf("%s/%d/reply", hubproto.PathMessages, id), r, nil)
		if err == nil {
			return
		}
		var he *httpError
		if errors.As(err, &he) && he.status < 500 && he.status != 429 {
			l.log.Warn("hub refused message reply", "message", id, "error", err)
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Duration(attempt+1) * 5 * time.Second):
		}
	}
}

// ---- transport ----

type httpError struct {
	status int
	body   string
}

func (e *httpError) Error() string { return fmt.Sprintf("hub HTTP %d: %s", e.status, e.body) }

func (l *Link) call(ctx context.Context, c *http.Client, method, path string, body, out any) error {
	return Call(ctx, c, l.base, l.key, method, path, body, out)
}

// Call performs one authenticated request against the hub.
func Call(ctx context.Context, c *http.Client, base, key, method, path string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		if len(b) > hubproto.MaxSyncBytes {
			return fmt.Errorf("request too large (%d bytes)", len(b))
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, rdr)
	if err != nil {
		return err
	}
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "kodeblue/"+hubproto.Version)
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 300 {
		return &httpError{status: resp.StatusCode, body: clip(strings.TrimSpace(string(raw)), 300)}
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:12])
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func firstLine(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.SplitN(string(b), "\n", 2)[0])
}

func osRelease(root string) string {
	b, err := os.ReadFile(filepath.Join(root, "etc/os-release"))
	if err != nil {
		return runtime.GOOS
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "PRETTY_NAME="); ok {
			return strings.Trim(v, `"`)
		}
	}
	return runtime.GOOS
}

func uptime(root string) string {
	f := strings.Fields(firstLine(filepath.Join(root, "proc/uptime")))
	if len(f) == 0 {
		return ""
	}
	var secs float64
	fmt.Sscan(f[0], &secs)
	return (time.Duration(secs) * time.Second).Round(time.Minute).String()
}
