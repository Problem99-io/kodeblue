package main

import (
	"os"

	internal "github.com/Problem99-io/kodeblue/internal"
	"github.com/Problem99-io/kodeblue/internal/agent"
	"github.com/Problem99-io/kodeblue/internal/definitions"
	"github.com/Problem99-io/kodeblue/internal/tools"
)

// promptConfig builds the part of a RunConfig that makes up the system prompt
// and tool list: base directory, instructions, tools, definitions and skills.
// Live runs and manual compaction share it, so a compaction request has a
// byte-identical prefix with the last live request and hits the provider's
// prompt cache.
func (a *agentLoopAdapter) promptConfig(session *internal.Session, agentDef *internal.AgentDefinition) agent.RunConfig {
	// Pick up skills installed since the last run before the tool
	// descriptions are rendered: the skill tool lists them in its description.
	if a.skillRegistry != nil {
		a.skillRegistry.Refresh()
	}
	tools, unknown := toolsForAgent(a.toolRegistry.List(), agentDef)
	if len(unknown) > 0 {
		a.logger.Warn("agent allowlist names tools that are not registered; the run cannot use them",
			"agent", agentDef.Name, "unknown_tools", unknown, "usable_tools", len(tools))
	}
	cfg := agent.RunConfig{
		BaseDirectory: effectiveBaseDirectory(session.CWD, a.cfg.Paths.ProjectRoot),
		Instructions:  a.instructionsFor(session, agentDef),
		Tools:         tools,
	}
	appendDefinitionsToRunConfig(&cfg, a.definitionsRoot)

	// Advertise skills only to an agent that holds the skill tool. Otherwise
	// it is told about skills it has no way to load.
	if a.skillRegistry != nil && hasTool(cfg.Tools, "skill") {
		for _, s := range a.skillRegistry.List() {
			cfg.AvailableSkills = append(cfg.AvailableSkills, agent.AvailableSkill{
				Name:        s.Name,
				Description: s.Description,
			})
		}
	}
	return cfg
}

// instructionsFor layers a run's instructions, most specific first: the
// session's, the agent's, then the configured global and project files.
func (a *agentLoopAdapter) instructionsFor(session *internal.Session, agentDef *internal.AgentDefinition) []string {
	var instructions []string
	instructions = append(instructions, session.Instructions...)
	if agentDef != nil && agentDef.Instructions != "" {
		instructions = append(instructions, agentDef.Instructions)
	}
	for _, files := range [][]string{a.cfg.Instructions.GlobalFiles, a.cfg.Instructions.ProjectFiles} {
		for _, path := range files {
			if data, err := os.ReadFile(path); err == nil {
				instructions = append(instructions, string(data))
			}
		}
	}
	return instructions
}

func effectiveBaseDirectory(sessionCWD, projectRoot string) string {
	if sessionCWD != "" {
		return sessionCWD
	}
	return projectRoot
}

func toolNames(registry *tools.Registry) []string {
	defs := registry.List()
	names := make([]string, 0, len(defs))
	for _, def := range defs {
		names = append(names, string(def.Name))
	}
	return names
}

// toolsForAgent applies an agent's tool allowlist. No agent, or an empty
// list, means every registered tool. An allowlist always yields a non-nil
// slice, so one that names only unregistered tools (a tool since removed, an
// MCP server that did not connect) restricts the run to no tools rather than
// lifting the restriction. unknown lists the allowlisted names that are not
// registered.
func toolsForAgent(allTools []internal.ToolDefinition, agentDef *internal.AgentDefinition) (selected []internal.ToolDefinition, unknown []string) {
	allowed := map[string]bool{}
	hasAllowlist := agentDef != nil && len(agentDef.Tools) > 0
	if hasAllowlist {
		for _, name := range agentDef.Tools {
			allowed[internal.CanonicalToolNameString(name)] = true
		}
	}
	registered := make(map[string]bool, len(allTools))
	selected = make([]internal.ToolDefinition, 0, len(allTools))
	for _, definition := range allTools {
		name := internal.CanonicalToolNameString(string(definition.Name))
		registered[name] = true
		if !hasAllowlist || allowed[name] {
			selected = append(selected, definition)
		}
	}
	if hasAllowlist {
		for _, name := range agentDef.Tools {
			if !registered[internal.CanonicalToolNameString(name)] {
				unknown = append(unknown, name)
			}
		}
	}
	return selected, unknown
}

// hasTool reports whether name survived the agent's tool allowlist.
func hasTool(defs []internal.ToolDefinition, name internal.ToolName) bool {
	canonical := internal.CanonicalToolName(name)
	for _, def := range defs {
		if internal.CanonicalToolName(def.Name) == canonical {
			return true
		}
	}
	return false
}

func appendDefinitionsToRunConfig(cfg *agent.RunConfig, projectRoot string) {
	if cfg == nil {
		return
	}
	items, err := definitions.NewStore(projectRoot).List()
	if err != nil {
		return
	}
	for _, item := range items {
		def := agent.AvailableDefinition{
			ID:        item.ID,
			Title:     item.Title,
			Snippet:   item.Snippet,
			Content:   item.Content,
			Important: item.Important,
			Scope:     append([]string(nil), item.Scope...),
		}
		for _, note := range item.Notes {
			def.Notes = append(def.Notes, agent.AvailableDefinitionItem{ID: note.ID, Title: note.Title, Content: note.Content})
		}
		for _, rule := range item.Rules {
			def.Rules = append(def.Rules, agent.AvailableDefinitionItem{ID: rule.ID, Title: rule.Title, Content: rule.Content})
		}
		cfg.AvailableDefinitions = append(cfg.AvailableDefinitions, def)
	}
}
