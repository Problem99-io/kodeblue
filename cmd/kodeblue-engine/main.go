package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Problem99-io/kodeblue/internal/agent"
	"github.com/Problem99-io/kodeblue/internal/api"
	"github.com/Problem99-io/kodeblue/internal/logging"
	"github.com/Problem99-io/kodeblue/internal/mcp"
	"github.com/Problem99-io/kodeblue/internal/policy"
	"github.com/Problem99-io/kodeblue/internal/provider"
	"github.com/Problem99-io/kodeblue/internal/secrets"
	"github.com/Problem99-io/kodeblue/internal/skill"
	"github.com/Problem99-io/kodeblue/internal/state"
	"github.com/Problem99-io/kodeblue/internal/tools"
)

// runHardenSelfCheck backs `-selfcheck-harden`, a build/CI gate. It confirms
// the hardenProcess() call at the top of main() actually made this process
// non-dumpable and exits 0/1. CI runs the compiled binary with this flag, so a
// change that removes or reorders the startup hardening fails the build instead
// of shipping an engine whose /proc/<pid>/environ, fd and mem are readable by
// other processes running as the same uid.
func runHardenSelfCheck(hardenErr error) int {
	if hardenErr != nil {
		fmt.Fprintf(os.Stderr, "harden self-check FAILED: hardenProcess() errored: %v\n", hardenErr)
		return 1
	}
	ok, err := verifyNonDumpable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "harden self-check FAILED: cannot read dumpable state: %v\n", err)
		return 1
	}
	if !ok {
		fmt.Fprintln(os.Stderr, "harden self-check FAILED: process is DUMPABLE — its /proc/<pid>/environ, fd and mem would be readable by same-uid processes. hardenProcess() must run at startup.")
		return 1
	}
	fmt.Fprintln(os.Stdout, "harden self-check OK: process is non-dumpable")
	return 0
}

func main() {
	// Mark the engine non-dumpable as the very first thing. It holds model keys
	// in memory, and PR_SET_DUMPABLE=0 stops same-uid processes (MCP servers and
	// their children) reading its /proc/<pid>/environ, fd (the session database)
	// and mem. Keep this the first statement in main(): -selfcheck-harden below
	// verifies it ran, and CI fails if it did not. See harden_linux.go.
	hardenErr := hardenProcess()

	f := parseFlags()

	// Build/CI gate: confirm the hardenProcess() call above took effect, then
	// exit.
	if f.selfCheckHarden {
		os.Exit(runHardenSelfCheck(hardenErr))
	}

	logger := logging.NewLogger(slog.LevelInfo, true)
	apiKey := loadSupervisorSecrets(logger, f.secretsFD, f.apiKey)

	logging.SetDefault(logger)
	if hardenErr != nil {
		logger.Warn("failed to mark process non-dumpable; /proc secrets/fds not fully protected from same-uid readers", "error", hardenErr)
	}

	if f.configPath == "" || f.dbPath == "" {
		logger.Error("-config and -db are required")
		os.Exit(2)
	}
	absRoot, _ := filepath.Abs(f.projectRoot)
	definitionsRoot := resolveDefinitionsRoot(absRoot)
	tools.RemoveTempFiles(absRoot, definitionsRoot, 0)

	cfg, err := policy.LoadConfig(f.configPath)
	if err != nil {
		logger.Error("failed to load config", "path", f.configPath, "error", err)
		os.Exit(1)
	}
	cfg.Paths.ProjectRoot = absRoot
	if f.port > 0 {
		cfg.Server.Port = f.port
	}
	logger.Info("engine paths", "config", f.configPath, "project", absRoot, "definitions", definitionsRoot, "database", f.dbPath)

	db := openDatabase(logger, f.dbPath)
	defer db.Close()

	sessionRepo := state.NewSessionRepo(db)
	runRepo := state.NewRunRepo(db)
	messageRepo := state.NewMessageRepo(db)
	queueRepo := state.NewQueueRepo(db)
	eventRepo := state.NewEventRepo(db)
	if recovered, recoverErr := queueRepo.RecoverClaims(); recoverErr != nil {
		logger.Error("failed to recover claimed session queue items", "error", recoverErr)
		os.Exit(1)
	} else if recovered > 0 {
		logger.Warn("recovered claimed session queue items", "count", recovered)
	}
	questionRepo := state.NewPendingQuestionRepo(db)
	agentRepo := state.NewAgentRepo(db)

	eventHub := api.NewEventHub(logger.Logger)

	providerRegistry := provider.NewRegistry()
	api.RegisterConfiguredProvidersForStartup(providerRegistry, cfg, logger.Logger)
	go api.RefreshDynamicConfiguredProviders(providerRegistry, cfg, logger.Logger)

	eventSink := startEventSink(logger, eventRepo)
	go pruneEventsPeriodically(logger, eventRepo, state.DefaultEventRetention, eventPruneStartDelay(), time.Hour)

	// The same handler backs both the ask_user tool and the continuation
	// checkpoint, so a system-asked "keep going?" reaches the client through
	// the pending-question pipeline.
	askUserHandler := newAskUserHandler(eventHub, questionRepo, eventSink)
	toolRegistry, skillRegistry := buildToolRegistry(cfg, absRoot, definitionsRoot, askUserHandler, logger)
	mcpManager := connectMCP(cfg, toolRegistry, logger)
	defer mcpManager.Close()

	toolGuard, err := policy.NewToolGuard(cfg)
	if err != nil {
		logger.Error("failed to create tool guard", "error", err)
		os.Exit(1)
	}

	compactor := agent.NewCompactor(cfg.Agent.CompactionThresholdRatio, cfg.Agent.CompactionModel, eventSink)
	agentLoop := agent.NewLoop(toolRegistry, toolGuard, compactor, eventSink)
	agentLoop.SetContinuationGate(newContinuationGate(askUserHandler))

	loopAdapter := &agentLoopAdapter{
		loop:             agentLoop,
		compactor:        compactor,
		providerRegistry: providerRegistry,
		toolRegistry:     toolRegistry,
		cfg:              cfg,
		definitionsRoot:  definitionsRoot,
		sessionRepo:      sessionRepo,
		agentRepo:        agentRepo,
		runRepo:          runRepo,
		messageRepo:      messageRepo,
		skillRegistry:    skillRegistry,
		eventSink:        eventSink,
		logger:           logger,
		queueRepo:        queueRepo,
		maxIterations:    cfg.Agent.MaxIterations,
	}

	router := api.NewRouter(&api.Dependencies{
		DB:              db,
		Sessions:        sessionRepo,
		Runs:            runRepo,
		Messages:        messageRepo,
		Queue:           queueRepo,
		Events:          eventRepo,
		Questions:       questionRepo,
		Agents:          agentRepo,
		Providers:       providerRegistry,
		AgentLoop:       loopAdapter,
		MessageQueue:    loopAdapter,
		EventHub:        eventHub,
		Logger:          logger.Logger,
		ProjectRoot:     absRoot,
		DefinitionsRoot: definitionsRoot,
		Config:          cfg,
		ToolNames:       toolNames(toolRegistry),
		MCP:             mcpManager,
		APIKey:          apiKey,
	})
	serve(logger, fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port), router)
}

type startupFlags struct {
	projectRoot     string
	configPath      string
	port            int
	dbPath          string
	apiKey          string
	secretsFD       int
	selfCheckHarden bool
}

// parseFlags parses the command line and moves the key flags out of argv.
func parseFlags() startupFlags {
	projectRoot := flag.String("project", ".", "Project root directory")
	configPath := flag.String("config", "", "Config file (required)")
	port := flag.Int("port", 0, "Server port override (applied after config load)")
	dbPath := flag.String("db", "", "SQLite database path (required)")
	apiKeyFlag := flag.String("api-key", "", "API key required on every /v1 request except /v1/health (empty = no auth)")
	gatewayAPIKeyFlag := flag.String("gateway-api-key", "", "Model gateway API key; held in memory only (prefer -secrets-fd)")
	secretsFD := flag.Int("secrets-fd", 0, "Read a JSON secrets payload from this inherited file descriptor, then close it")
	selfCheckHarden := flag.Bool("selfcheck-harden", false, "verify PR_SET_DUMPABLE process hardening took effect and exit 0/1 (build/CI gate)")
	flag.Parse()

	// Copy every secret out of argv-backed memory, then zero it there: the parsed
	// flag values alias the original argv bytes on Linux, which stay visible in
	// world-readable /proc/<pid>/cmdline (non-dumpable covers environ/fd/mem, NOT
	// cmdline). strings.Clone must happen first — scrubbing argv in place would
	// otherwise blank the flag values themselves.
	//
	// These flags exist for standalone/CLI runs. The supervisor uses -secrets-fd
	// instead, which keeps key material out of argv entirely and so has no
	// exposure window at all between execve and this scrub.
	apiKey := strings.Clone(*apiKeyFlag)
	gatewayAPIKey := strings.Clone(*gatewayAPIKeyFlag)
	for _, secret := range []string{apiKey, gatewayAPIKey} {
		scrubArgvSecret(secret)
	}
	secrets.Set(secrets.GatewayAPIKey, gatewayAPIKey)

	return startupFlags{
		projectRoot:     *projectRoot,
		configPath:      *configPath,
		port:            *port,
		dbPath:          *dbPath,
		apiKey:          apiKey,
		secretsFD:       *secretsFD,
		selfCheckHarden: *selfCheckHarden,
	}
}

// loadSupervisorSecrets reads the secrets payload, the preferred delivery
// path: the supervisor writes JSON to an inherited pipe and closes it, so no
// credential is ever visible in this process's command line. Its values
// override the key flags. It returns the server API key to enforce.
func loadSupervisorSecrets(logger *logging.Logger, fd int, apiKey string) string {
	if fd <= 0 {
		return apiKey
	}
	if err := secrets.LoadFromFD(fd); err != nil {
		// Fail loudly rather than silently falling back to a keyless daemon:
		// every provider would register as unavailable and the failure would
		// surface much later as a confusing "no model" error.
		logger.Error("failed to read secrets payload from supervisor", "fd", fd, "error", err)
		os.Exit(1)
	}
	if injected := secrets.Get(secrets.ServerAPIKey); injected != "" {
		apiKey = injected
	}
	logger.Info("secrets received from supervisor",
		"gateway", secrets.Has(secrets.GatewayAPIKey),
		"server_api_key", secrets.Has(secrets.ServerAPIKey))
	return apiKey
}

func openDatabase(logger *logging.Logger, path string) *state.DB {
	db, err := state.NewDB(path)
	if err != nil {
		logger.Error("failed to open database", "path", path, "error", err)
		os.Exit(1)
	}
	if err := db.Migrate(); err != nil {
		logger.Error("failed to run migrations", "error", err)
		os.Exit(1)
	}
	if err := db.MigrateAgents(); err != nil {
		logger.Error("failed to run agent migrations", "error", err)
		os.Exit(1)
	}
	return db
}

// buildToolRegistry registers the built-in tools and, when enabled, the
// skill tool backed by the project's skills.
func buildToolRegistry(cfg *policy.Config, projectRoot, definitionsRoot string, askUser tools.AskUserHandler, logger *logging.Logger) (*tools.Registry, *skill.Registry) {
	toolCfg := tools.ToolConfig{
		ProjectRoot:     projectRoot,
		DefinitionsRoot: definitionsRoot,
		MaxOutputBytes:  1 << 20,
	}
	registry := tools.NewRegistry()
	registry.Register(tools.NewReadFile(toolCfg))
	registry.Register(tools.NewWriteFile(toolCfg))
	registry.Register(tools.NewListDir(toolCfg))
	registry.Register(tools.NewCreateDefinition(toolCfg))
	registry.Register(tools.NewReadDefinitions(toolCfg))
	registry.Register(tools.NewPatchDefinition(toolCfg))
	registry.Register(tools.NewAskUser(askUser))

	if !cfg.Skills.Enabled {
		return registry, nil
	}
	skillPerms := make(map[string]skill.PermissionAction, len(cfg.Skills.Permissions))
	for pattern, action := range cfg.Skills.Permissions {
		skillPerms[pattern] = skill.PermissionAction(action)
	}
	skillRegistry := skill.NewRegistry(projectRoot, skill.NewPermissions(skillPerms), logger.Logger)
	skillRegistry.Discover()
	registry.Register(tools.NewSkillTool(skillRegistry))
	return registry, skillRegistry
}

// connectMCP connects to the configured MCP servers and registers their tools
// so the agent can call them like any built-in tool (mcp__<server>__<tool>).
func connectMCP(cfg *policy.Config, registry *tools.Registry, logger *logging.Logger) *mcp.Manager {
	manager := mcp.NewManager(logger.Logger)
	if len(cfg.MCP.Servers) == 0 {
		return manager
	}
	register := func(handles []mcp.ToolHandle) {
		for _, handle := range handles {
			registry.Register(tools.NewMCPTool(manager, handle))
		}
		logger.Info("mcp tools registered", "servers", len(cfg.MCP.Servers), "tools", len(handles))
	}
	// A server that was down at startup, or comes back with new tools,
	// registers them when it connects; each run reads the registry afresh.
	manager.OnToolsChanged(register)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	manager.Connect(ctx, toMCPServerConfigs(cfg.MCP.Servers))
	cancel()
	register(manager.Tools())
	return manager
}

// serve runs the HTTP server until SIGINT or SIGTERM.
func serve(logger *logging.Logger, addr string, handler http.Handler) {
	srv := &http.Server{Addr: addr, Handler: handler}
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		logger.Info("shutting down...")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}()

	logger.Info("kodeblue engine starting", "addr", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("server error", "error", err)
		os.Exit(1)
	}
	logger.Info("server stopped")
}

// toMCPServerConfigs converts the policy-layer MCP server configs (TOML targets)
// into the mcp package's connection configs.
func toMCPServerConfigs(servers []policy.MCPServerConfig) []mcp.ServerConfig {
	out := make([]mcp.ServerConfig, 0, len(servers))
	for _, s := range servers {
		out = append(out, mcp.ServerConfig{
			Name:      s.Name,
			Transport: s.Transport,
			Command:   s.Command,
			Args:      s.Args,
			URL:       s.URL,
			Env:       s.Env,
			Headers:   s.Headers,
			Enabled:   s.Enabled,
		})
	}
	return out
}

func resolveDefinitionsRoot(projectRoot string) string {
	root := strings.TrimSpace(os.Getenv("KODEBLUE_DEFINITIONS_ROOT"))
	if root == "" {
		return projectRoot
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return root
	}
	return abs
}
