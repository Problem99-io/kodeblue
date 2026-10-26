package config

import (
	"os"
	"testing"

	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
)

func TestActionRuleNeverLoosensRootPolicy(t *testing.T) {
	cases := []struct {
		mode, hub, want string
	}{
		{"recommend", "", hubproto.ActionApprove},
		{"recommend", hubproto.ActionAuto, hubproto.ActionApprove},
		{"recommend", hubproto.ActionOff, hubproto.ActionOff},
		{"contain", "", hubproto.ActionAuto},
		{"contain", hubproto.ActionAuto, hubproto.ActionAuto},
		{"contain", hubproto.ActionApprove, hubproto.ActionApprove},
		{"contain", hubproto.ActionOff, hubproto.ActionOff},
		{"off", hubproto.ActionAuto, hubproto.ActionOff},
		{"off", "", hubproto.ActionOff},
	}
	for _, tc := range cases {
		c := Default()
		c.Response.Mode = tc.mode
		c.ActionRules = map[string]string{"block_ip": tc.hub}
		if got := c.ActionRule("block_ip"); got != tc.want {
			t.Errorf("mode=%s hub=%q: got %s, want %s", tc.mode, tc.hub, got, tc.want)
		}
	}
	c := Default()
	c.Response.Mode = "contain"
	c.Response.AllowedActions = []string{"kill_process"}
	c.ActionRules = map[string]string{"block_ip": hubproto.ActionAuto}
	if got := c.ActionRule("block_ip"); got != hubproto.ActionOff {
		t.Errorf("action outside allowed_actions: got %s, want off", got)
	}
}

func TestHubSettingsOverlay(t *testing.T) {
	c := Default()
	c.Server.StateDir = t.TempDir()
	c.Hub.URL = "https://hub.example"
	c.Inference = Inference{BaseURL: "https://local.example", Provider: "openai-compatible", TriageModel: "local-small", AgentModel: "local-agent", APIKeyFile: "/nonexistent"}
	c.Agents.Instructions = map[string]string{"all": "local note"}

	s := &hubproto.Settings{
		Version: "v1",
		Connections: []hubproto.Connection{
			{ID: "or", Kind: hubproto.ConnOpenRouter, BaseURL: "https://openrouter.ai/api/", APIKey: "sk-or-test"},
			{ID: "im", Kind: hubproto.ConnInferenceManager, BaseURL: "https://im.example", APIKey: "im-key"},
			{ID: "BAD ID", Kind: hubproto.ConnOpenAI, BaseURL: "https://x.example"},
		},
		Models: map[string]hubproto.ModelRef{
			hubproto.RoleDefault:   {Connection: "im", Provider: "z-ai", Model: "glm-small"},
			hubproto.RoleResponder: {Connection: "or", Model: "vendor/strong"},
			hubproto.RoleCritical:  {Connection: "or", Model: "vendor/strongest"},
			hubproto.RoleReviewer:  {Connection: "gone", Model: "dropped"},
			"bogus":                {Model: "dropped"},
		},
		Instructions: map[string]string{hubproto.RoleResponder: "Page the on-call for anything on prod-db.", "bogus": "dropped"},
		Approvals:    map[string]string{"block_ip": hubproto.ActionOff, "lock_user": "sometimes"},
	}
	if err := c.SaveHubSettings(s); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(c.HubSettingsPath()); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("settings file mode: %v %v", st, err)
	}

	got := c.WithHubSettings()
	if got.HubSettingsVersion != "v1" || len(got.Inference.Connections) != 2 || got.Inference.Connections["or"].BaseURL != "https://openrouter.ai/api" {
		t.Fatalf("connections not applied: %+v", got.Inference.Connections)
	}
	if err := got.ModelsReady(); err != nil {
		t.Fatalf("models not ready: %v", err)
	}
	// Triage and the learner take the hub default; the reviewer's ref names
	// a connection that does not exist, so it falls back to the default too.
	for role, want := range map[string]string{hubproto.RoleTriage: "im:z-ai/glm-small", hubproto.RoleLearner: "im:z-ai/glm-small", hubproto.RoleReviewer: "im:z-ai/glm-small",
		hubproto.RoleResponder: "or:openrouter/vendor/strong", hubproto.RoleCritical: "or:openrouter/vendor/strongest"} {
		r := got.ModelRef(role)
		if p := got.EngineProvider(r) + "/" + r.Model; p != want {
			t.Errorf("%s: %s, want %s", role, p, want)
		}
	}
	if u, k, err := got.Endpoint("or"); err != nil || u != "https://openrouter.ai/api" || k != "sk-or-test" {
		t.Fatalf("endpoint: %q %q %v", u, k, err)
	}
	keys := got.GatewayKeys()
	if keys["gateway:or"] != "sk-or-test" || keys["gateway:im"] != "im-key" || keys["gateway"] != "" {
		t.Fatalf("gateway keys: %v", keys)
	}
	if m := got.EffectiveModels(); m[hubproto.RoleResponder] != "or/vendor/strong" {
		t.Fatalf("effective models: %v", m)
	}
	if want := "local note\n\nPage the on-call for anything on prod-db."; got.InstructionsFor(hubproto.RoleResponder) != want {
		t.Fatalf("instructions: %q", got.InstructionsFor(hubproto.RoleResponder))
	}
	if got.InstructionsFor(hubproto.RoleLearner) != "local note" || got.Agents.Instructions["bogus"] != "" {
		t.Fatalf("instructions leaked: %+v", got.Agents.Instructions)
	}
	if got.ActionRule("block_ip") != hubproto.ActionOff || got.ActionRules["lock_user"] != "" {
		t.Fatalf("rules: %+v", got.ActionRules)
	}
	// The original value is untouched (maps are copied).
	if c.Agents.Instructions["responder"] != "" || c.Inference.Refs != nil {
		t.Fatal("overlay mutated the base config")
	}

	// Opted out, or no hub: the file is ignored.
	off := c
	off.Hub.AcceptSettings = false
	if off.WithHubSettings().ModelFor(hubproto.RoleResponder) != "local-agent" {
		t.Fatal("accept_settings=false still applied hub settings")
	}
	nohub := c
	nohub.Hub.URL = ""
	if nohub.WithHubSettings().HubSettingsVersion != "" {
		t.Fatal("settings applied without a hub")
	}

	// An empty version clears them.
	if err := c.SaveHubSettings(&hubproto.Settings{}); err != nil {
		t.Fatal(err)
	}
	if c.ReadHubSettings() != nil || c.WithHubSettings().HubSettingsVersion != "" {
		t.Fatal("settings not cleared")
	}
}

func TestLocalModelRefs(t *testing.T) {
	c := Default()
	c.Inference = Inference{BaseURL: "https://local.example", APIKey: "k", Provider: "openai-compatible", TriageModel: "small", AgentModel: "agent",
		AgentModels: map[string]string{hubproto.RoleReviewer: "reviewer-model"}}
	if err := c.ModelsReady(); err != nil {
		t.Fatal(err)
	}
	for role, want := range map[string]string{hubproto.RoleTriage: "small", hubproto.RoleResponder: "agent", hubproto.RoleReviewer: "reviewer-model", hubproto.RoleCritical: "agent"} {
		if got := c.ModelFor(role); got != want {
			t.Errorf("%s: %s, want %s", role, got, want)
		}
	}
	if p := c.EngineProvider(c.ModelRef(hubproto.RoleResponder)); p != "openai-compatible" {
		t.Fatalf("local provider: %s", p)
	}
	c.Inference.EscalationProvider, c.Inference.EscalationModel = "openai-compatible", "big"
	if c.ModelFor(hubproto.RoleCritical) != "big" {
		t.Fatal("escalation model ignored")
	}
	c.Inference.APIKey, c.Inference.APIKeyFile, c.Inference.APIKeyEnv = "", "", ""
	if c.ModelsReady() == nil {
		t.Fatal("ready without a key")
	}
}

func TestHubResponseModeIsCappedByRoot(t *testing.T) {
	cases := []struct{ root, max, hub, want string }{
		{"contain", "", "", "contain"},
		{"contain", "", "recommend", "recommend"},
		{"contain", "", "off", "off"},
		{"recommend", "", "contain", "recommend"}, // never above the root policy
		{"recommend", "", "off", "off"},
		{"off", "", "contain", "off"},
		{"contain", "", "bogus", "contain"},
		// Root lets the hub raise the mode up to hub_max_mode.
		{"recommend", "contain", "contain", "contain"},
		{"recommend", "contain", "", "recommend"},
		{"recommend", "contain", "off", "off"},
		{"off", "recommend", "contain", "off"},
		{"off", "recommend", "recommend", "recommend"},
		{"contain", "recommend", "contain", "contain"}, // a lower hub_max_mode never lowers mode
		{"recommend", "bogus", "contain", "recommend"},
	}
	for _, tc := range cases {
		c := Default()
		c.Server.StateDir = t.TempDir()
		c.Hub.URL = "https://hub.example"
		c.Response.Mode, c.Response.HubMaxMode = tc.root, tc.max
		if err := c.SaveHubSettings(&hubproto.Settings{Version: "v1", ResponseMode: tc.hub}); err != nil {
			t.Fatal(err)
		}
		got := c.WithHubSettings()
		if got.Response.Mode != tc.want || got.RootResponseMode != tc.root {
			t.Errorf("root=%s max=%s hub=%q: mode %s (root %s), want %s", tc.root, tc.max, tc.hub, got.Response.Mode, got.RootResponseMode, tc.want)
		}
	}
}

// The root helper allows up to the ceiling only while the hub's settings are
// accepted: hub_max_mode means nothing on a server that refuses them.
func TestModeCeiling(t *testing.T) {
	c := Default()
	c.Response.Mode, c.Response.HubMaxMode = "recommend", "contain"
	if got := c.ModeCeiling(); got != "recommend" {
		t.Errorf("no hub: ceiling %s", got)
	}
	c.Hub.URL = "https://hub.example"
	if got := c.ModeCeiling(); got != "contain" {
		t.Errorf("hub: ceiling %s", got)
	}
	c.Hub.AcceptSettings = false
	if got := c.ModeCeiling(); got != "recommend" {
		t.Errorf("accept_settings = false: ceiling %s", got)
	}
}

// The hub tunes cost, cadence and noise within bounds, never past the
// server's own budget ceiling, and only adds protections.
func TestHubTuningAndProtections(t *testing.T) {
	c := Default()
	c.Budget.HubMaxDailyUSD = 5
	c.Response.MaxActionsPerHour = 10
	s := &hubproto.Settings{Version: "v1",
		Tuning: map[string]string{
			"budget.daily_usd":            "50",   // above the server's ceiling
			"schedule.review_hours":       "6",    //
			"detect.bruteforce_threshold": "5000", // out of bounds: ignored
			"hub.share_transcripts":       "false",
			"notify.min_severity":         "medium",
			"no.such.key":                 "1",
		},
		ProtectedUsers: []string{"deploy"}, ProtectedIPs: []string{"10.0.0.0/8"}, ProtectedUnits: []string{"nginx"},
		MaxActionsPerHour: 3,
	}
	got := c.applyHubSettings(s)
	if got.Budget.DailyUSD != 5 {
		t.Errorf("daily budget %v, want the server's ceiling 5", got.Budget.DailyUSD)
	}
	if got.Schedule.ReviewHours != 6 || got.Hub.ShareTranscripts || got.Notify.MinSeverity != "medium" {
		t.Errorf("tuning not applied: review %d, share %v, severity %s", got.Schedule.ReviewHours, got.Hub.ShareTranscripts, got.Notify.MinSeverity)
	}
	if got.Detect.BruteForceThreshold != Default().Detect.BruteForceThreshold {
		t.Errorf("out-of-bounds threshold applied: %d", got.Detect.BruteForceThreshold)
	}
	if !contains(got.Response.ProtectedUsers, "root") || !contains(got.Response.ProtectedUsers, "deploy") || !contains(got.Response.ProtectedUnits, "nginx") || !contains(got.Response.ProtectedIPs, "10.0.0.0/8") {
		t.Errorf("protections: users %v, units %v, ips %v", got.Response.ProtectedUsers, got.Response.ProtectedUnits, got.Response.ProtectedIPs)
	}
	if contains(c.Response.ProtectedUsers, "deploy") {
		t.Error("the root-owned config's lists were modified in place")
	}
	if got.Response.MaxActionsPerHour != 3 {
		t.Errorf("rate limit %d, want 3", got.Response.MaxActionsPerHour)
	}
	// The hub cannot raise the limit.
	s.MaxActionsPerHour = 50
	if got := c.applyHubSettings(s); got.Response.MaxActionsPerHour != 10 {
		t.Errorf("rate limit raised to %d", got.Response.MaxActionsPerHour)
	}
	if v := got.TuningValues(); v["budget.daily_usd"] != "5" || v["schedule.review_hours"] != "6" || len(v) != len(hubproto.Tunings) {
		t.Errorf("tuning values: %v", v)
	}
}

// The hub tightens what a server sees, reports and keeps, never loosens it,
// and a value that is not a number never reaches the config.
func TestHubTuningOnlyTightens(t *testing.T) {
	c := Default()
	c.Budget.DailyUSD, c.Budget.HubMaxDailyUSD = 3, 0
	c.Budget.InputUSDPerMTok = 2
	c.Hub.ShareTranscripts = false
	c.Schedule.RetentionDays = 0 // 90 days
	c.Detect.BruteForceThreshold = 5
	c.Notify.MinSeverity = "medium"
	loosen := map[string]string{
		"budget.daily_usd":            "500", // no hub ceiling: the hub may only lower it
		"budget.input_usd_per_mtok":   "0",
		"hub.share_transcripts":       "true",
		"schedule.retention_days":     "7",
		"detect.bruteforce_threshold": "50",
		"notify.min_severity":         "critical",
	}
	got := c.applyHubSettings(&hubproto.Settings{Version: "v1", Tuning: loosen})
	if got.Budget.DailyUSD != 3 || got.Budget.InputUSDPerMTok != 2 || got.Hub.ShareTranscripts || got.Schedule.RetentionDays != 0 ||
		got.Detect.BruteForceThreshold != 5 || got.Notify.MinSeverity != "medium" {
		t.Errorf("hub loosened the server: %+v %+v %+v %+v %+v", got.Budget, got.Hub.ShareTranscripts, got.Schedule.RetentionDays, got.Detect.BruteForceThreshold, got.Notify.MinSeverity)
	}
	tighten := map[string]string{
		"budget.daily_usd":            "1",
		"budget.input_usd_per_mtok":   "3",
		"schedule.retention_days":     "365",
		"detect.bruteforce_threshold": "3",
		"notify.min_severity":         "low",
	}
	got = c.applyHubSettings(&hubproto.Settings{Version: "v2", Tuning: tighten})
	if got.Budget.DailyUSD != 1 || got.Budget.InputUSDPerMTok != 3 || got.Schedule.RetentionDays != 365 ||
		got.Detect.BruteForceThreshold != 3 || got.Notify.MinSeverity != "low" {
		t.Errorf("tightening not applied: %+v %v %v %v", got.Budget, got.Schedule.RetentionDays, got.Detect.BruteForceThreshold, got.Notify.MinSeverity)
	}
	c.Schedule.RetentionDays = -1 // keep everything
	if got := c.applyHubSettings(&hubproto.Settings{Version: "v3", Tuning: tighten}); got.Schedule.RetentionDays != -1 {
		t.Errorf("retention %d, want the server's keep-everything", got.Schedule.RetentionDays)
	}
	for _, v := range []string{"NaN", "nan", "Inf", "-Inf", "1e309"} {
		if hubproto.CheckTuning(map[string]string{"budget.daily_usd": v}) == nil {
			t.Errorf("daily budget %q accepted", v)
		}
		if got := c.applyHubSettings(&hubproto.Settings{Version: "v4", Tuning: map[string]string{"budget.daily_usd": v}}); got.Budget.DailyUSD != 3 {
			t.Errorf("daily budget %q applied: %v", v, got.Budget.DailyUSD)
		}
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// The hub switches the CVE feed and its sources, within what the server's
// own config allows: off there stays off.
func TestHubCVEFeedWithinRoot(t *testing.T) {
	c := Default()
	c.applyTuning(map[string]string{"cve_feed.nvd": "false"})
	if got := c.CVEFeed.Sources(); len(got) != 1 || got[0] != "cisa_kev" {
		t.Errorf("hub turning NVD off: %v", got)
	}
	c = Default()
	c.applyTuning(map[string]string{"cve_feed.enabled": "false"})
	if len(c.CVEFeed.Sources()) != 0 {
		t.Errorf("hub turning the feed off: %v", c.CVEFeed.Sources())
	}
	c = Default()
	c.CVEFeed.Enabled, c.CVEFeed.KEV = true, false // root: no CISA
	c.applyTuning(map[string]string{"cve_feed.cisa_kev": "true"})
	if c.CVEFeed.KEV {
		t.Error("hub turned on a source the root config turned off")
	}
	c = Default()
	c.CVEFeed.Enabled = false // root: no downloads at all
	c.applyTuning(map[string]string{"cve_feed.enabled": "true"})
	if c.CVEFeed.Enabled || len(c.CVEFeed.Sources()) != 0 {
		t.Error("hub turned on a feed the root config turned off")
	}
	if c.TuningValues()["cve_feed.enabled"] != "false" {
		t.Errorf("reported %q", c.TuningValues()["cve_feed.enabled"])
	}
}
