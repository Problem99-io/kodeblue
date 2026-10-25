// kodeblue is a host security agent: one per server, running
// as its own unprivileged user, watching the host like a blue-team analyst.
//
//	kodeblue run                      the daemon (systemd runs this)
//	kodeblue status                   heartbeat, spend, open incidents, monitors
//	kodeblue incidents [--all]        list incidents; kodeblue incident <id> shows the report
//	kodeblue findings [--status s]    list findings
//	kodeblue ack <finding-id> [--allow]   operator: accept a protected finding as legitimate
//	kodeblue allow <collector> <key-pattern> <reason>   operator allow rule
//	kodeblue maintenance <duration>|off   absorb non-critical changes during planned work
//	kodeblue snapshot <collector>     print what a collector sees now
//	kodeblue sensors [on|off <sensor> [reason]]   what each sensor can see here; turn one on or off
//	kodeblue relearn                  run the learning phase again on next start
//	kodeblue respond list|approve <id>|deny <id>|undo <id>
//	kodeblue enroll --hub URL [--pin P] connect this server to a kodeblue hub (token in $KODEBLUE_ENROLL_TOKEN)
//	kodeblue inference [--url U --model M [--provider P]]   show or set the model endpoint
//	kodeblue mcp                      stdio MCP server (spawned by the engine)
//	kodeblue respond exec             root helper (started by kodeblue-respond.socket)
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/config"
	"github.com/Problem99-io/kodeblue/internal/blue/daemon"
	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
	"github.com/Problem99-io/kodeblue/internal/blue/mcpserver"
	"github.com/Problem99-io/kodeblue/internal/blue/notify"
	"github.com/Problem99-io/kodeblue/internal/blue/respond"
	"github.com/Problem99-io/kodeblue/internal/blue/sdnotify"
	"github.com/Problem99-io/kodeblue/internal/blue/sensors"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	cfgPath := fs.String("config", envOr("KODEBLUE_CONFIG", config.DefaultPath), "config file")
	all := fs.Bool("all", false, "include resolved")
	status := fs.String("status", "", "filter by status")
	allow := fs.Bool("allow", false, "also add an operator allow rule for the exact item")
	verbose := fs.Bool("v", false, "debug logging")
	hubURL := fs.String("hub", "", "enroll: hub URL (https://…)")
	hubPin := fs.String("pin", "", "enroll: hub certificate pin (sha256//…), for a self-signed hub")
	hubCA := fs.String("ca-file", "", "enroll: CA certificate that signed the hub's certificate")
	name := fs.String("name", "", "enroll: server name shown on the hub (default: hostname)")
	infURL := fs.String("url", "", "inference: OpenAI-compatible base URL (https://…)")
	infModel := fs.String("model", "", "inference: model for triage and agents")
	infProvider := fs.String("provider", "", "inference: provider label, for gateways that serve several vendors")
	infKeyFile := fs.String("key-file", "", "inference: file with the endpoint's API key (- reads it from stdin, asking on a terminal)")
	// Positional args may come before or after flags.
	var pos []string
	for len(args) > 0 {
		_ = fs.Parse(args)
		args = fs.Args()
		if len(args) > 0 {
			pos = append(pos, args[0])
			args = args[1:]
		}
	}
	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fatal(err)
	}

	// Settings from the hub apply to the daemon, the agents' MCP server and
	// status. The root response helper (respond) reads only the root-owned
	// config.
	switch cmd {
	case "run", "mcp", "status":
		cfg = cfg.WithHubSettings()
	}

	switch cmd {
	case "run":
		runDaemon(cfg, logger)
	case "enroll":
		enrollCmd(cfg, *hubURL, *hubPin, *hubCA, *name)
	case "inference":
		inferenceCmd(cfg, *infURL, *infProvider, *infModel, *infKeyFile)
	case "mcp":
		st := mustStore(cfg)
		defer st.Close()
		if err := mcpserver.New(cfg, st).Serve(context.Background(), os.Stdin, os.Stdout); err != nil {
			fatal(err)
		}
	case "respond":
		respondCmd(cfg, pos)
	case "status":
		statusCmd(cfg)
	case "incidents":
		st := mustStore(cfg)
		where := `WHERE kind IN ('incident','coverage') AND status<>'resolved' ORDER BY id DESC LIMIT 50`
		if *all {
			where = `ORDER BY id DESC LIMIT 100`
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tKIND\tSEVERITY\tSTATUS\tVERDICT\tCOST\tCREATED\tTITLE")
		for _, in := range st.Incidents(where) {
			fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t$%.4f\t%s\t%s\n", in.ID, in.Kind, in.Severity, in.Status, in.Verdict, in.CostUSD, in.CreatedAt.Format("01-02 15:04"), trunc(in.Title, 70))
		}
		w.Flush()
	case "incident":
		st := mustStore(cfg)
		id := mustID(pos)
		in := st.GetIncident(id)
		if in == nil {
			fatal(fmt.Errorf("incident %d not found", id))
		}
		fmt.Printf("#%d %s\nkind=%s severity=%s status=%s verdict=%s session=%s cost=$%.4f\n\nSUMMARY\n%s\n\nREPORT\n%s\n\nFINDINGS\n", in.ID, in.Title, in.Kind, in.Severity, in.Status, in.Verdict, in.SessionID, in.CostUSD, in.Summary, in.Report)
		for _, f := range st.FindingsForIncident(id) {
			fmt.Printf("- #%d [%s/%s] %s (%s)\n", f.ID, f.Severity, f.Rule, f.Title, f.Status)
		}
	case "findings":
		st := mustStore(cfg)
		var list []store.Finding
		if *status != "" {
			list = st.FindingsByStatus(*status, 200)
		} else {
			list = st.FindingsSince(time.Now().Add(-7*24*time.Hour), 200)
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tSEVERITY\tSTATUS\tRULE\tSEEN\tINCIDENT\tTITLE")
		for _, f := range list {
			fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%d\t%d\t%s\n", f.ID, f.Severity, f.Status, f.Rule, f.Occurrences, f.IncidentID, trunc(f.Title, 80))
		}
		w.Flush()
	case "ack":
		st := mustStore(cfg)
		id := mustID(pos)
		f := st.GetFinding(id)
		if f == nil {
			fatal(fmt.Errorf("finding %d not found", id))
		}
		if f.ItemID != "" {
			parts := strings.SplitN(f.ItemID, "|", 2)
			_ = st.UpsertBaseline([]store.BaselineItem{{ID: f.ItemID, Collector: parts[0], Key: parts[1], Value: f.Value, Note: "acknowledged by operator"}}, "operator")
			if *allow {
				_ = st.AddAllowRule(&store.AllowRule{Collector: parts[0], KeyPattern: parts[1], Rule: f.Rule, Reason: "operator acknowledged finding #" + strconv.FormatInt(id, 10), CreatedBy: "operator"})
			}
		}
		_ = st.SetFindingStatus(id, "benign", "benign", "acknowledged by operator", 0)
		st.Journal("operator", "ack", fmt.Sprintf("#%d %s", id, f.Title))
		fmt.Println("acknowledged", id)
	case "allow":
		if len(pos) < 3 {
			fatal(errors.New("usage: kodeblue allow <collector> <key-pattern> <reason>"))
		}
		st := mustStore(cfg)
		r := &store.AllowRule{Collector: pos[0], KeyPattern: pos[1], Reason: strings.Join(pos[2:], " "), CreatedBy: "operator"}
		if err := st.AddAllowRule(r); err != nil {
			fatal(err)
		}
		fmt.Println("allow rule", r.ID)
	case "maintenance":
		if len(pos) < 1 {
			fatal(errors.New("usage: kodeblue maintenance <duration e.g. 2h> [reason…] | off"))
		}
		st := mustStore(cfg)
		if pos[0] == "off" {
			_ = os.Remove(cfg.MaintenanceFile())
			st.Journal("operator", "maintenance.off", "")
			fmt.Println("maintenance window closed")
			return
		}
		d, err := time.ParseDuration(pos[0])
		if err != nil || d > 24*time.Hour {
			fatal(errors.New("duration must be like 30m or 2h (max 24h)"))
		}
		until := time.Now().Add(d).UTC().Format(time.RFC3339)
		if err := os.WriteFile(cfg.MaintenanceFile(), []byte(until), 0o640); err != nil {
			fatal(err)
		}
		reason := strings.TrimSpace(strings.Join(pos[1:], " "))
		if reason == "" {
			reason = "planned work"
		}
		st.Journal("operator", "maintenance.on", "until "+until+": "+reason)
		fmt.Println("maintenance until", until, "— non-critical changes are absorbed into the baseline and journaled")
	case "snapshot":
		if len(pos) < 1 {
			fatal(errors.New("usage: kodeblue snapshot <collector>"))
		}
		env := &sensors.Env{Root: cfg.Server.Root}
		env.Pkg = sensors.LoadPackageIndex(env)
		var learned []string
		if st, err := store.Open(cfg.DBPath()); err == nil {
			_ = json.Unmarshal([]byte(st.Get("extra_integrity_paths")), &learned)
			st.Close()
		}
		snap := sensors.NewRegistry([]string{pos[0]}, cfg.IntegrityPaths(learned)).Sweep(context.Background(), env, true)
		out, _ := json.MarshalIndent(snap, "", " ")
		fmt.Println(string(out))
	case "sensors":
		sensorsCmd(cfg, pos)
	case "forget":
		// Remove items from the learned baseline (e.g. something absorbed by
		// mistake); the next sweep sees them as new and re-evaluates them.
		if len(pos) < 1 {
			fatal(errors.New("usage: kodeblue forget <item-id> ... | kodeblue forget match <substring>   (ids look like persistence|/etc/cron.d/x)"))
		}
		st := mustStore(cfg)
		var ids []string
		if pos[0] == "match" && len(pos) > 1 {
			for _, it := range st.QueryBaseline("", pos[1], 200) {
				ids = append(ids, it.ID)
			}
		} else {
			ids = pos
		}
		for _, id := range ids {
			if err := st.DeleteBaseline(id); err == nil {
				st.Journal("operator", "baseline.forget", id)
				fmt.Println("forgot", id)
			}
		}
	case "relearn":
		st := mustStore(cfg)
		_ = st.Set("learned_at", "")
		st.Journal("operator", "relearn", "")
		fmt.Println("learning phase will run on next start (systemctl restart kodeblue)")
	case "version":
		fmt.Println("kodeblue", hubproto.Version)
	default:
		usage()
		os.Exit(2)
	}
}

func runDaemon(cfg config.Config, logger *slog.Logger) {
	if os.Geteuid() == 0 {
		logger.Warn("kodeblue is running as root; the supported deployment is the dedicated kodeblue user with capabilities (see deploy/)")
	}
	if err := cfg.MigrateEngineDir(); err != nil {
		fatal(fmt.Errorf("migrate engine state: %w", err))
	}
	for _, d := range []string{cfg.Server.StateDir, cfg.WorkspaceDir(), cfg.EngineDir(), filepath.Join(cfg.Server.StateDir, "tmp")} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			fatal(err)
		}
	}
	st := mustStore(cfg)
	defer st.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	d := daemon.New(cfg, st, logger)
	// Read before the engine starts, so its environment never carries the
	// notify socket.
	d.Systemd = sdnotify.FromEnv()
	usr1 := make(chan os.Signal, 1)
	signal.Notify(usr1, syscall.SIGUSR1)
	go func() {
		for range usr1 {
			d.Wake("signal")
		}
	}()
	logger.Info("kodeblue starting", "server", cfg.Server.Name, "state", cfg.Server.StateDir, "models", cfg.EffectiveModels(), "response_mode", cfg.Response.Mode, "hub_settings", cfg.HubSettingsVersion)
	err := d.Run(ctx)
	if errors.Is(err, daemon.ErrRestart) {
		// Exit cleanly; systemd (Restart=always) starts kodeblue again with
		// the new settings.
		logger.Info(err.Error())
		return
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		fatal(err)
	}
}

func statusCmd(cfg config.Config) {
	st := mustStore(cfg)
	day := time.Now().UTC().Truncate(24 * time.Hour)
	usd, per, tokens := st.SpentSince(day)
	hb := st.Get("heartbeat")
	fmt.Printf("server:        %s\n", cfg.Server.Name)
	fmt.Printf("heartbeat:     %s\n", orDash(hb))
	learned := st.Get("learned_at")
	if learned == "" {
		learned = "(still learning)"
	}
	fmt.Printf("learned at:    %s\n", learned)
	if st.Get(store.LearnerPendingKey) != "" {
		fmt.Println("learning:      waiting for a model; the learner and the vulnerability assessment run once one is set (detection is on)")
	}
	fmt.Printf("last review:   %s\n", orDash(st.Get("last_review_at")))
	fmt.Printf("spend today:   $%.4f of $%.2f (%d tokens)%s\n", usd, cfg.Budget.DailyUSD, tokens, listCounts(per, func(v float64) string { return fmt.Sprintf("$%.4f", v) }))
	counts := st.BaselineCounts()
	total := 0
	for _, n := range counts {
		total += n
	}
	fmt.Printf("baseline:      %d items%s\n", total, listCounts(counts, strconv.Itoa))
	fmt.Printf("response mode: %s\n", cfg.Response.Mode)
	models := cfg.EffectiveModels()
	if models["triage"] == "" && models["responder"] == "" {
		fmt.Println("models:        off (no model set: pick one on the hub, or sudo kodeblue inference --url … --model … --key-file -)")
	} else {
		fmt.Printf("models:        triage=%s learner=%s responder=%s reviewer=%s operator=%s", models["triage"], models["learner"], models["responder"], models["reviewer"], models["operator"])
		if m := models["critical"]; m != "" {
			fmt.Printf(" critical=%s", m)
		}
		fmt.Println()
	}
	var rules []string
	for _, a := range respond.ActionNames() {
		rules = append(rules, a+"="+cfg.ActionRule(a))
	}
	fmt.Printf("actions:       %s\n", strings.Join(rules, " "))
	if cfg.HubSettingsVersion != "" {
		fmt.Printf("hub settings:  %s\n", cfg.HubSettingsVersion)
	}
	if cfg.Hub.Enabled() {
		fmt.Printf("hub:           %s (last sync %s)\n", cfg.Hub.URL, st.Get("hub_last_sync"))
	}
	if b, err := os.ReadFile(cfg.MaintenanceFile()); err == nil {
		// The daemon caps a window at 24 h from when the file was written.
		file := strings.TrimSpace(string(b))
		switch until, tamper, ok := daemon.MaintenanceStatus(st, file); {
		case ok && tamper != "":
			fmt.Printf("maintenance:   until %s (clamped: %s)\n", until.UTC().Format(time.RFC3339), tamper)
		case ok && time.Now().After(until):
			fmt.Printf("maintenance:   ended %s (file: %s)\n", until.UTC().Format(time.RFC3339), file)
		default:
			fmt.Printf("maintenance:   until %s\n", file)
		}
	}
	open := st.Incidents(`WHERE kind='incident' AND status<>'resolved' ORDER BY id DESC LIMIT 10`)
	fmt.Printf("\nopen incidents: %d\n", len(open))
	for _, in := range open {
		fmt.Printf("  #%d [%s] %s — %s %s\n", in.ID, in.Severity, trunc(in.Title, 70), in.Status, in.Verdict)
	}
	gaps := st.Incidents(`WHERE kind='coverage' AND status<>'resolved' ORDER BY id DESC LIMIT 10`)
	fmt.Printf("\ncoverage cases (services kodeblue cannot fully monitor): %d\n", len(gaps))
	for _, in := range gaps {
		fmt.Printf("  #%d [%s] %s\n", in.ID, in.Severity, trunc(in.Title, 70))
	}
	vulns := st.Vulnerabilities(`WHERE status='open' ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, service, id`)
	fmt.Printf("\nopen vulnerabilities: %d\n", len(vulns))
	for i, v := range vulns {
		if i == 15 {
			fmt.Printf("  … %d more (all of them on the hub's Services tab)\n", len(vulns)-15)
			break
		}
		fmt.Printf("  [%s] %s: %s (%s)\n", v.Severity, v.Service, trunc(v.Title, 70), v.ID)
	}
	ack := st.FindingsByStatus("needs_ack", 20)
	fmt.Printf("\nawaiting operator ack: %d\n", len(ack))
	for _, f := range ack {
		fmt.Printf("  #%d [%s] %s — %s\n", f.ID, f.Severity, trunc(f.Title, 70), trunc(f.VerdictReason, 80))
	}
	mons := st.Monitors(false)
	fmt.Printf("\nmonitors: %d\n", len(mons))
	for _, m := range mons {
		state := "ok"
		if !m.LastOK {
			state = "FAILING"
		}
		fmt.Printf("  %-28s %-7s runs=%d fails=%d\n", m.ID, state, m.Runs, m.Fails)
	}
	if pend := mcpserver.LoadRequests(cfg); len(pend) > 0 {
		fmt.Printf("\npending response actions: %d (kodeblue respond list)\n", len(pend))
	}
}

// helperEnvelope is what the unprivileged side sends to the root helper.
type helperEnvelope struct {
	Op      string          `json:"op"` // execute | undo
	Request respond.Request `json:"request"`
	UndoID  string          `json:"undo_id"`
}

func respondCmd(cfg config.Config, pos []string) {
	if len(pos) == 0 {
		fatal(errors.New("usage: kodeblue respond list|approve <id>|deny <id>|undo <id>"))
	}
	switch pos[0] {
	case "exec":
		rootHelper(cfg)
	case "list":
		out, _ := json.MarshalIndent(map[string]any{"executed": respond.Load(cfg.Response.StateDir), "pending_approval": mcpserver.LoadRequests(cfg)}, "", " ")
		fmt.Println(string(out))
	case "approve":
		if len(pos) < 2 {
			fatal(errors.New("usage: kodeblue respond approve <id>"))
		}
		for _, r := range mcpserver.LoadRequests(cfg) {
			if r.ID == pos[1] {
				r.RequestedBy += "+operator"
				rec, err := mcpserver.RunHelper(context.Background(), cfg, r)
				if err != nil {
					fatal(err)
				}
				fmt.Printf("%s: %s — %s\n", rec.ID, rec.Status, rec.Result)
				announce(cfg, "Operator approved containment: "+r.Action+" ("+rec.Status+")", rec.Result, r.ID, r.IncidentID)
				return
			}
		}
		fatal(fmt.Errorf("no pending request %s", pos[1]))
	case "deny":
		if len(pos) < 2 {
			fatal(errors.New("usage: kodeblue respond deny <id>"))
		}
		r := mcpserver.FindRequest(cfg, pos[1])
		if r == nil {
			fatal(fmt.Errorf("no pending request %s", pos[1]))
		}
		if err := mcpserver.DenyRequest(cfg, r.ID, "operator"); err != nil {
			fatal(err)
		}
		fmt.Printf("%s: denied\n", r.ID)
		announce(cfg, "Operator denied containment: "+r.Action, r.Justification, r.ID, r.IncidentID)
	case "undo":
		if len(pos) < 2 {
			fatal(errors.New("usage: kodeblue respond undo <id>"))
		}
		out, err := callHelper(cfg, helperEnvelope{Op: "undo", UndoID: pos[1]})
		if err != nil {
			fatal(err)
		}
		fmt.Println(out)
		var incident int64
		if rec := respond.Find(cfg.Response.StateDir, pos[1]); rec != nil {
			incident = rec.IncidentID
		}
		announce(cfg, "Containment undone by operator", out, pos[1], incident)
	default:
		fatal(fmt.Errorf("unknown respond subcommand %q", pos[0]))
	}
}

// rootHelper is the privileged half of the response layer. systemd starts it
// per connection on /run/kodeblue/respond.sock (or sudo runs it). It trusts
// nothing from the caller except the request: policy comes from the
// root-owned config, which must not be writable by anyone else. It always
// answers with one JSON record on stdout.
func rootHelper(cfg config.Config) {
	reply := func(rec respond.Record) {
		out, _ := json.Marshal(rec)
		fmt.Println(string(out))
	}
	refuse := func(msg string) {
		reply(respond.Record{Status: "refused", Result: msg})
		os.Exit(0)
	}
	if os.Geteuid() != 0 {
		refuse("respond exec must run as root (kodeblue-respond socket or sudoers rule)")
	}
	if err := checkRootOwned(cfg.Path()); err != nil {
		refuse(err.Error())
	}
	if cfg.Response.Mode == "off" {
		refuse("response disabled by policy")
	}
	// Who is on the other end: only uid 0 (the operator CLI run via sudo, or
	// root) may approve or undo; the kodeblue user gets only what the
	// root-owned policy grants agents. stdin is the accepted socket under
	// systemd, so the kernel vouches for the peer; sudo sets SUDO_UID.
	caller, err := respond.IdentifyCaller(os.Stdin)
	if err != nil {
		refuse("cannot identify caller: " + err.Error())
	}
	var env helperEnvelope
	if err := json.NewDecoder(os.Stdin).Decode(&env); err != nil {
		refuse("bad request: " + err.Error())
	}
	switch env.Op {
	case "undo":
		if err := respond.AuthorizeUndo(caller); err != nil {
			refuse(err.Error())
		}
		rec, err := respond.UndoByID(cfg.Response, env.UndoID)
		if err != nil {
			refuse(err.Error())
		}
		reply(rec)
	default:
		req := env.Request
		// The baseline-key/incident guards the MCP layer applies are advisory
		// (the unprivileged side can skip them); re-check that the request is
		// one this caller may make under the root-owned policy before acting.
		// A hub approval is honored only on a server actually enrolled with a
		// hub that is set to accept them; without a hub there is no hub
		// operator, so "+hub:" could only be a forgery.
		hubApprovals := cfg.Hub.Enabled() && cfg.Hub.AcceptApprovals
		if err := respond.Authorize(cfg.Response.Mode, hubApprovals, caller, req); err != nil {
			refuse(err.Error())
		}
		// incident_linked is computed by the MCP layer from the incident store
		// and widens kill_process; the helper cannot recompute it, so it trusts
		// it only when an operator (on the server or via the hub) vouches for
		// the request. A compromised kodeblue user cannot set it itself.
		if req.Params != nil && !respond.VouchedByOperator(hubApprovals, caller, req) {
			delete(req.Params, "incident_linked")
		}
		reply(respond.Execute(cfg.Response, req))
	}
}

func callHelper(cfg config.Config, env helperEnvelope) (string, error) {
	payload, _ := json.Marshal(env)
	out, err := respond.Invoke(context.Background(), cfg.Path(), payload)
	if err != nil {
		return "", err
	}
	var rec respond.Record
	if json.Unmarshal(out, &rec) != nil {
		return strings.TrimSpace(string(out)), nil
	}
	return fmt.Sprintf("%s: %s %s", rec.ID, rec.Status, rec.Result), nil
}

func announce(cfg config.Config, title, body, id string, incident int64) {
	var q notify.Queue
	if cfg.Hub.Enabled() {
		st, err := store.Open(cfg.DBPath())
		if err != nil {
			return
		}
		defer st.Close()
		q = st
	}
	sl := notify.New(cfg.Hub.Enabled(), q, cfg.Notify.SlackWebhookURL, cfg.Notify.SlackWebhookFile, cfg.Notify.Direct)
	if !notify.Enabled(sl) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = sl.Send(ctx, notify.Message{Server: cfg.Server.Name, Kind: "action", Severity: "high", Title: title, Body: body, Fields: map[string]string{"Action id": id}, IncidentID: incident})
}

func checkRootOwned(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("policy config %s: %w", path, err)
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || sys.Uid != 0 || st.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("refusing: %s must be owned by root and not group/world-writable", path)
	}
	return nil
}

func mustStore(cfg config.Config) *store.Store {
	st, err := store.Open(cfg.DBPath())
	if err != nil {
		if os.Geteuid() != 0 {
			fatal(fmt.Errorf("cannot open %s: kodeblue's state is readable by root only, run it with sudo", cfg.DBPath()))
		}
		fatal(err)
	}
	return st
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// listCounts formats a map as " (k1 v1, k2 v2)" sorted by key, or "".
func listCounts[V any](m map[string]V, f func(V) string) string {
	if len(m) == 0 {
		return ""
	}
	parts := make([]string, 0, len(m))
	for _, k := range slices.Sorted(maps.Keys(m)) {
		parts = append(parts, k+" "+f(m[k]))
	}
	return " (" + strings.Join(parts, ", ") + ")"
}

func mustID(pos []string) int64 {
	if len(pos) < 1 {
		fatal(errors.New("id required"))
	}
	id, err := strconv.ParseInt(strings.TrimPrefix(pos[0], "#"), 10, 64)
	if err != nil {
		fatal(err)
	}
	return id
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n-1] + "…"
	}
	return s
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "kodeblue:", err)
	os.Exit(1)
}

// sensorsCmd shows how much each sensor sees from where kodeblue runs, and
// lets the operator turn one on or off (agents may only turn off blind ones).
func sensorsCmd(cfg config.Config, pos []string) {
	st := mustStore(cfg)
	defer st.Close()
	off := sensors.ParseDisabled(st.Get(sensors.DisabledKey))
	save := func() {
		b, _ := json.Marshal(off)
		if err := st.Set(sensors.DisabledKey, string(b)); err != nil {
			fatal(err)
		}
	}
	if len(pos) >= 2 && (pos[0] == "on" || pos[0] == "off") {
		name := pos[1]
		known := false
		for _, n := range sensors.CollectorNames() {
			known = known || n == name
		}
		if !known {
			fatal(fmt.Errorf("unknown sensor %q (sensors: %s)", name, strings.Join(sensors.CollectorNames(), ", ")))
		}
		if pos[0] == "on" {
			delete(off, name)
			save()
			st.Journal("operator", "sensor.enable", name)
			fmt.Println(name, "is on from the next sweep")
			return
		}
		reason := strings.Join(pos[2:], " ")
		if reason == "" {
			fatal(errors.New("usage: kodeblue sensors off <sensor> <reason>"))
		}
		off[name] = sensors.DisabledSensor{Reason: reason, By: "operator", At: time.Now().UTC().Format(time.RFC3339)}
		save()
		st.Journal("operator", "sensor.disable", name+": "+reason)
		fmt.Println(name, "is off from the next sweep; kodeblue sensors on", name, "turns it back on")
		return
	}
	if len(pos) > 0 {
		fatal(errors.New("usage: kodeblue sensors [on <sensor> | off <sensor> <reason>]"))
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "SENSOR\tSTATUS\tWHY")
	for _, c := range sensors.CheckCoverage(&sensors.Env{Root: cfg.Server.Root}) {
		status, why := c.Status, c.Reason
		if d, ok := off[c.Collector]; ok {
			status += ", off"
			why = d.By + ": " + d.Reason
			if len(d.ReplacedBy) > 0 {
				why += " (covered by " + strings.Join(d.ReplacedBy, ", ") + ")"
			}
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", c.Collector, status, why)
	}
	_ = tw.Flush()
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: kodeblue <command> [--config /etc/kodeblue/kodeblue.toml]
  run | status | incidents [--all] | incident <id> | findings [--status s]
  ack <finding-id> [--allow] | allow <collector> <key-pattern> <reason>
  maintenance <duration>|off | snapshot <collector> | relearn | forget <item-id> | forget match <substring>
  sensors [on <sensor> | off <sensor> <reason>]   what each sensor can see on this server
  respond list|approve <id>|deny <id>|undo <id> | mcp | version
  enroll --hub https://hub.example [--pin sha256//…] [--ca-file f] [--name n]   (token in $KODEBLUE_ENROLL_TOKEN)
  inference [--url https://… --model m [--provider p]]   show or set the model endpoint`)
}
