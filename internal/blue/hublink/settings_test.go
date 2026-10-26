package hublink

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/config"
	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
	"github.com/Problem99-io/kodeblue/internal/blue/respond"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

// settingsAgent records ApplySettings calls; the rest is unused here.
type settingsAgent struct {
	Agent
	applied int
}

func (a *settingsAgent) ApplySettings() { a.applied++ }

func newSettingsLink(t *testing.T) (*Link, *settingsAgent) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Server.StateDir = dir
	cfg.Response.StateDir = filepath.Join(dir, "response")
	cfg.Hub.URL = "https://hub.example"
	st, err := store.Open(filepath.Join(dir, "kb.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	a := &settingsAgent{}
	return &Link{cfg: cfg, st: st, agent: a, log: slog.New(slog.NewTextHandler(io.Discard, nil))}, a
}

func TestSaveSettingsAppliesOncePerVersion(t *testing.T) {
	l, a := newSettingsLink(t)
	s := &hubproto.Settings{Version: "v1", Models: map[string]hubproto.ModelRef{hubproto.RoleResponder: {Model: "vendor/strong"}}, Approvals: map[string]string{"block_ip": hubproto.ActionOff}}
	l.saveSettings(s)
	l.saveSettings(s) // re-sent until the restart applies it
	if a.applied != 1 {
		t.Fatalf("ApplySettings calls: %d", a.applied)
	}
	if got := l.cfg.ReadHubSettings(); got == nil || got.Version != "v1" || got.Models[hubproto.RoleResponder].Model != "vendor/strong" {
		t.Fatalf("saved: %+v", got)
	}

	// The running version is not saved again.
	l2, a2 := newSettingsLink(t)
	l2.cfg.HubSettingsVersion = "v1"
	l2.saveSettings(s)
	if a2.applied != 0 {
		t.Fatal("restarted for the version already running")
	}

	// Opted out: nothing is written.
	l3, a3 := newSettingsLink(t)
	l3.cfg.Hub.AcceptSettings = false
	l3.saveSettings(s)
	if a3.applied != 0 || l3.cfg.ReadHubSettings() != nil {
		t.Fatal("accept_settings=false saved settings")
	}
}

func TestSaveSettingsRejectsBadPayloads(t *testing.T) {
	bad := []*hubproto.Settings{
		{Version: "x", Connections: []hubproto.Connection{{ID: "c1", Kind: hubproto.ConnOpenAI, BaseURL: "file:///etc/passwd"}}},
		{Version: "x", Connections: []hubproto.Connection{{ID: "Bad", Kind: hubproto.ConnOpenAI, BaseURL: "https://x.example"}}},
		{Version: "x", Connections: []hubproto.Connection{{ID: "c1", Kind: "vendor-direct", BaseURL: "https://x.example"}}},
		{Version: "x", Connections: []hubproto.Connection{{ID: "c1", Kind: hubproto.ConnOpenAI, BaseURL: "https://x.example"}, {ID: "c1", Kind: hubproto.ConnOpenAI, BaseURL: "https://y.example"}}},
		{Version: "x", Models: map[string]hubproto.ModelRef{"root": {Model: "m"}}},
		{Version: "x", Models: map[string]hubproto.ModelRef{hubproto.RoleTriage: {Model: "a\nb"}}},
		{Version: "x", Models: map[string]hubproto.ModelRef{hubproto.RoleTriage: {Connection: "missing", Model: "m"}}},
		{Version: "x", Models: map[string]hubproto.ModelRef{hubproto.RoleTriage: {Provider: "Bad Label", Model: "m"}}},
		{Version: "x", Instructions: map[string]string{hubproto.RoleTriage: "triage takes no instructions"}},
		{Version: "x", Instructions: map[string]string{hubproto.RoleAll: strings.Repeat("a", hubproto.MaxInstructions+1)}},
		{Version: "x", Approvals: map[string]string{"block_ip": "always"}},
	}
	for i, s := range bad {
		l, a := newSettingsLink(t)
		l.saveSettings(s)
		if a.applied != 0 || l.cfg.ReadHubSettings() != nil {
			t.Errorf("case %d was accepted: %+v", i, s)
		}
	}
}

func TestApproveRefusedWhenActionTurnedOff(t *testing.T) {
	l, _ := newSettingsLink(t)
	b, _ := json.Marshal(respond.Request{ID: "act_1", IncidentID: 7, Action: "block_ip", Params: map[string]string{"ip": "203.0.113.9"}, RequestedBy: "agent"})
	if err := os.WriteFile(filepath.Join(l.cfg.Server.StateDir, "response-requests.jsonl"), append(b, '\n'), 0o640); err != nil {
		t.Fatal(err)
	}
	l.cfg.ActionRules = map[string]string{"block_ip": hubproto.ActionOff}
	r := l.handle(context.Background(), hubproto.OperatorMessage{ID: 1, Author: "alice", Decision: "approve", RequestID: "act_1"})
	if r.Status != "refused" || !strings.Contains(r.Text, "turned off") {
		t.Fatalf("approve of a disabled action: %+v", r)
	}
}

// The status tells the hub how far the baseline is and that settings it sent
// are saved but not applied yet, so the console does not look stuck.
func TestStatusReportsBaselineAndSavedSettings(t *testing.T) {
	l, _ := newSettingsLink(t)
	l.agent = &phaseAgent{settingsAgent: settingsAgent{}, phase: "learning"}
	l.st.SetBaselineProgress(3, 10, time.Now().Add(21*time.Minute))
	l.saveSettings(&hubproto.Settings{Version: "v2", Models: map[string]hubproto.ModelRef{hubproto.RoleDefault: {Model: "vendor/m"}}})
	s := l.status()
	if s.BaselineSweep != 3 || s.BaselineSweeps != 10 || s.BaselineETA == "" {
		t.Fatalf("baseline: %d/%d %q", s.BaselineSweep, s.BaselineSweeps, s.BaselineETA)
	}
	if s.SettingsSaved != "v2" {
		t.Fatalf("settings_saved %q, want v2", s.SettingsSaved)
	}
	// Applied (after the restart) and watching: neither is reported.
	l.cfg.HubSettingsVersion = "v2"
	l.agent.(*phaseAgent).phase = "watching"
	if s := l.status(); s.SettingsSaved != "" || s.BaselineSweeps != 0 {
		t.Fatalf("after apply: saved %q, sweeps %d", s.SettingsSaved, s.BaselineSweeps)
	}
	if s := l.status(); s.Software == nil || s.Software.Feed.Total != 1 {
		t.Fatalf("software check not reported: %+v", s.Software)
	}
	if s := l.status(); !s.AcceptsUpgrades || s.Upgrade == nil || s.Upgrade.To != "v0.1.7" {
		t.Fatalf("upgrade not reported: %v %+v", s.AcceptsUpgrades, s.Upgrade)
	}
}

// phaseAgent answers what status() asks of the daemon.
type phaseAgent struct {
	settingsAgent
	phase string
}

func (a *phaseAgent) Phase() string       { return a.phase }
func (a *phaseAgent) ModelsEnabled() bool { return false }
func (a *phaseAgent) Learning() bool      { return a.phase == "learning" }
func (a *phaseAgent) Maintenance() string { return "" }
func (a *phaseAgent) DecisionMade()       {}
func (a *phaseAgent) Software() *hubproto.Software {
	return &hubproto.Software{Feed: hubproto.CVEFeedStatus{Sources: []string{"nvd"}, Total: 1}}
}
func (a *phaseAgent) ApplySettings() { a.applied++ }
func (a *phaseAgent) UpgradeStatus() *hubproto.UpgradeStatus {
	return &hubproto.UpgradeStatus{To: "v0.1.7", State: "waiting"}
}
