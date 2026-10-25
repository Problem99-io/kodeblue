package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	internal "github.com/Problem99-io/kodeblue/internal"
	"github.com/Problem99-io/kodeblue/internal/definitions"
)

type definitionsTool struct {
	cfg ToolConfig
}

func newDefinitionsTool(cfg ToolConfig) *definitionsTool {
	return &definitionsTool{cfg: cfg}
}

type createDefinitionTool struct{ *definitionsTool }

type readDefinitionsTool struct{ *definitionsTool }

type patchDefinitionTool struct{ *definitionsTool }

func NewCreateDefinition(cfg ToolConfig) Tool {
	return &createDefinitionTool{definitionsTool: newDefinitionsTool(cfg)}
}

func NewPatchDefinition(cfg ToolConfig) Tool {
	return &patchDefinitionTool{definitionsTool: newDefinitionsTool(cfg)}
}

func NewReadDefinitions(cfg ToolConfig) Tool {
	return &readDefinitionsTool{definitionsTool: newDefinitionsTool(cfg)}
}

func (t *createDefinitionTool) Name() internal.ToolName { return "create_definition" }

func (t *readDefinitionsTool) Name() internal.ToolName { return "read_definitions" }

func (t *patchDefinitionTool) Name() internal.ToolName { return "patch_definition" }

func (t *createDefinitionTool) Description() string {
	return "Create a persisted definition for a part of the server: a service, a user or access setup, network configuration, a set of files or directories, or another constrained area. Definitions are your long-term memory; their titles and snippets are indexed in every prompt, and relevant details are loaded on demand. Create one the moment you encounter any non-trivial component during investigation. The snippet is a short summary always visible in your prompt. The content is the full explanation: what it is, how it is configured, ports, paths, owners, dependencies, and anything else that would otherwise require re-reading files or re-running commands. Rules capture hard constraints that MUST be respected in this area. Notes capture important context, gotchas, and known-normal behaviour. " + definitions.ImportanceGuidance
}

func (t *patchDefinitionTool) Description() string {
	return "Update an existing definition when a service or other part of the server changes, new constraints emerge, or the user states a rule or convention that must be remembered. Use snippet: to update the short summary shown in the prompt, content: to update the full explanation, and add/update/delete rules to keep hard constraints current. Keeping definitions accurate is critical — stale or incomplete definitions will cause future investigations to go wrong. " + definitions.ImportanceGuidance
}

func (t *readDefinitionsTool) Description() string {
	return "Read one definition or all definitions. ALWAYS call this at the start of any task that touches a system that may already have a definition. Reading definitions first means you work from accumulated knowledge instead of re-exploring from scratch every time, which saves tokens and prevents drift."
}

func (t *createDefinitionTool) Parameters() json.RawMessage {
	return makeSchema(map[string]any{
		"title":     map[string]any{"type": "string", "description": "Definition title"},
		"snippet":   map[string]any{"type": "string", "description": "Short one or two sentence summary shown in the system prompt alongside the title"},
		"content":   map[string]any{"type": "string", "description": "Full detailed explanation of the service, component, or area this definition covers"},
		"important": map[string]any{"type": "boolean", "default": false, "description": definitions.ImportanceGuidance},
		"scope": map[string]any{
			"type":        "array",
			"description": "Related files, folders, or paths covered by this definition. Use paths relative to the project root (\"src/api/routes.ts\"), not absolute paths — a definition outlives the working copy it was written in.",
			"items":       map[string]any{"type": "string"},
		},
		"notes": map[string]any{
			"type":        "array",
			"description": "Initial notes for create_definition",
			"items":       definitionItemSchema("note"),
		},
		"rules": map[string]any{
			"type":        "array",
			"description": "Initial rules for create_definition",
			"items":       definitionItemSchema("rule"),
		},
	}, []string{"title", "snippet", "content", "scope"})
}

func (t *patchDefinitionTool) Parameters() json.RawMessage {
	return makeSchema(map[string]any{
		"definition_id": map[string]any{"type": "string", "description": "Definition id from the Definitions prompt section"},
		"patchText": map[string]any{
			"type":        "string",
			"description": "Patch operations. Supported lines: title:, snippet:, content:, important: true|false, add_scope:, remove_scope:, reset_scope:, *** Add Note: id, *** Update Note: id, *** Delete Note: id, *** Add Rule: id, *** Update Rule: id, *** Delete Rule: id. Item bodies may include Title: and Content: lines. " + definitions.ImportanceGuidance,
		},
	}, []string{"definition_id", "patchText"})
}

func (t *readDefinitionsTool) Parameters() json.RawMessage {
	return makeSchema(map[string]any{
		"definition_id": map[string]any{"type": "string", "description": "Optional definition id. When omitted, returns all definitions."},
	}, nil)
}

func (t *createDefinitionTool) Execute(ctx context.Context, args json.RawMessage) (*Result, error) {
	var params struct {
		Title     string                       `json:"title"`
		Snippet   string                       `json:"snippet"`
		Content   string                       `json:"content"`
		Important bool                         `json:"important"`
		Scope     []string                     `json:"scope"`
		Notes     []definitions.DefinitionNote `json:"notes"`
		Rules     []definitions.DefinitionRule `json:"rules"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return &Result{Content: "invalid arguments: " + err.Error(), IsError: true}, nil
	}
	doc := definitions.Definition{
		Title:     params.Title,
		Snippet:   params.Snippet,
		Content:   params.Content,
		Important: params.Important,
		Scope:     params.Scope,
		Notes:     params.Notes,
		Rules:     params.Rules,
	}

	created, err := t.storeForContext(ctx).Create(doc)
	if err != nil {
		return &Result{Content: err.Error(), IsError: true}, nil
	}
	return marshalDefinitionResult("create_definition", created)
}

func (t *readDefinitionsTool) Execute(ctx context.Context, args json.RawMessage) (*Result, error) {
	_ = ctx
	var params struct {
		DefinitionID string `json:"definition_id"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return &Result{Content: "invalid arguments: " + err.Error(), IsError: true}, nil
	}
	id := strings.TrimSpace(params.DefinitionID)
	if id != "" {
		item, err := t.storeForContext(ctx).Get(id)
		if err != nil {
			return &Result{Content: err.Error(), IsError: true}, nil
		}
		if item == nil {
			return &Result{Content: "definition not found", IsError: true}, nil
		}
		return &Result{Content: renderDefinitionMarkdown(*item), Metadata: map[string]any{"tool": "read_definitions", "count": 1, "definition_id": item.ID, "title": item.Title}}, nil
	}
	items, err := t.storeForContext(ctx).List()
	if err != nil {
		return &Result{Content: err.Error(), IsError: true}, nil
	}
	if len(items) == 0 {
		return &Result{Content: "# Definitions\n\n_None_", Metadata: map[string]any{"tool": "read_definitions", "count": 0}}, nil
	}
	blocks := make([]string, 0, len(items)+1)
	blocks = append(blocks, "# Definitions")
	for _, item := range items {
		blocks = append(blocks, renderDefinitionMarkdown(item))
	}
	return &Result{Content: strings.Join(blocks, "\n\n"), Metadata: map[string]any{"tool": "read_definitions", "count": len(items)}}, nil
}

func (t *patchDefinitionTool) Execute(ctx context.Context, args json.RawMessage) (*Result, error) {
	var params struct {
		DefinitionID string `json:"definition_id"`
		PatchText    string `json:"patchText"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return &Result{Content: "invalid arguments: " + err.Error(), IsError: true}, nil
	}
	id := strings.TrimSpace(params.DefinitionID)
	if id == "" {
		return &Result{Content: "definition_id is required", IsError: true}, nil
	}

	current, err := t.storeForContext(ctx).Get(id)
	if err != nil {
		return &Result{Content: err.Error(), IsError: true}, nil
	}
	if current == nil {
		return &Result{Content: "definition not found", IsError: true}, nil
	}
	updated, err := patchDefinition(*current, params.PatchText)
	if err != nil {
		return &Result{Content: err.Error(), IsError: true}, nil
	}

	persisted, err := t.storeForContext(ctx).Update(updated)
	if err != nil {
		return &Result{Content: err.Error(), IsError: true}, nil
	}
	if persisted == nil {
		return &Result{Content: "definition not found", IsError: true}, nil
	}
	return marshalDefinitionResult("patch_definition", persisted)
}

func marshalDefinitionResult(action string, def *definitions.Definition) (*Result, error) {
	return &Result{
		Content: renderDefinitionMarkdown(*def),
		Metadata: map[string]any{
			"tool":          action,
			"action":        action,
			"definition_id": def.ID,
			"title":         def.Title,
			"important":     def.Important,
		},
	}, nil
}

func renderDefinitionMarkdown(def definitions.Definition) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("## %s\n\n", fallbackMarkdown(def.Title, "Untitled Definition")))
	sb.WriteString(fmt.Sprintf("- ID: `%s`\n", def.ID))
	sb.WriteString(fmt.Sprintf("- Snippet: %s\n", fallbackMarkdown(def.Snippet, "(none)")))
	sb.WriteString(fmt.Sprintf("- Content: %s\n", fallbackMarkdown(def.Content, "(none)")))
	if def.Important {
		sb.WriteString("- Important: yes\n")
	}
	if len(def.Scope) == 0 {
		sb.WriteString("- Scope: _(none)_\n")
	} else {
		sortedScope := append([]string(nil), def.Scope...)
		sort.Strings(sortedScope)
		sb.WriteString("- Scope:\n")
		for _, item := range sortedScope {
			sb.WriteString(fmt.Sprintf("  - `%s`\n", item))
		}
	}
	if len(def.Rules) > 0 {
		sb.WriteString("\n### Rules\n")
		for _, rule := range def.Rules {
			sb.WriteString(fmt.Sprintf("- `%s` %s: %s\n", rule.ID, fallbackMarkdown(rule.Title, "Untitled"), fallbackMarkdown(rule.Content, "(empty)")))
		}
	}
	if len(def.Notes) > 0 {
		sb.WriteString("\n### Notes\n")
		for _, note := range def.Notes {
			sb.WriteString(fmt.Sprintf("- `%s` %s: %s\n", note.ID, fallbackMarkdown(note.Title, "Untitled"), fallbackMarkdown(note.Content, "(empty)")))
		}
	}
	return strings.TrimRight(sb.String(), "\n")
}

func fallbackMarkdown(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

// storeForContext returns a definitions store rooted at the configured
// definitions root. Multi-repo task runs set this to the shared project root;
// other runs fall back to the active project root.
func (t *definitionsTool) storeForContext(_ context.Context) *definitions.Store {
	root := strings.TrimSpace(t.cfg.DefinitionsRoot)
	if root == "" {
		root = t.cfg.ProjectRoot
	}
	return definitions.NewStore(root)
}

func definitionItemSchema(kind string) map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"id":      map[string]any{"type": "string", "description": kind + " identifier"},
			"title":   map[string]any{"type": "string", "description": kind + " title"},
			"content": map[string]any{"type": "string", "description": kind + " content"},
		},
		"required": []string{"id", "title", "content"},
	}
}

func patchDefinition(def definitions.Definition, patchText string) (definitions.Definition, error) {
	patchText = strings.TrimSpace(strings.ReplaceAll(patchText, "\r\n", "\n"))
	if patchText == "" {
		return def, fmt.Errorf("patchText is required for patch_definition")
	}
	lines := strings.Split(patchText, "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "title:"):
			def.Title = strings.TrimSpace(strings.TrimPrefix(line, "title:"))
		case strings.HasPrefix(line, "snippet:"):
			def.Snippet = strings.TrimSpace(strings.TrimPrefix(line, "snippet:"))
		case strings.HasPrefix(line, "content:"):
			// The content runs to the next directive, so it may span lines.
			body := []string{strings.TrimPrefix(line, "content:")}
			for i+1 < len(lines) && !isPatchDirective(strings.TrimSpace(lines[i+1])) {
				i++
				body = append(body, lines[i])
			}
			def.Content = strings.TrimSpace(strings.Join(body, "\n"))
		case strings.HasPrefix(line, "important:"):
			important, err := parseImportantValue(strings.TrimSpace(strings.TrimPrefix(line, "important:")))
			if err != nil {
				return def, err
			}
			def.Important = important
		case strings.HasPrefix(line, "add_scope:"):
			def.Scope = append(def.Scope, parseCSV(strings.TrimPrefix(line, "add_scope:"))...)
		case strings.HasPrefix(line, "remove_scope:"):
			def.Scope = removeScope(def.Scope, parseCSV(strings.TrimPrefix(line, "remove_scope:")))
		case strings.HasPrefix(line, "reset_scope:"):
			def.Scope = parseCSV(strings.TrimPrefix(line, "reset_scope:"))
		case strings.HasPrefix(line, "*** Add Note: "):
			id := strings.TrimSpace(strings.TrimPrefix(line, "*** Add Note: "))
			item, next, err := parsePatchItem(lines, i+1, id)
			if err != nil {
				return def, err
			}
			def.Notes = upsertNote(def.Notes, definitions.DefinitionNote(item), false)
			i = next - 1
		case strings.HasPrefix(line, "*** Update Note: "):
			id := strings.TrimSpace(strings.TrimPrefix(line, "*** Update Note: "))
			item, next, err := parsePatchItem(lines, i+1, id)
			if err != nil {
				return def, err
			}
			def.Notes = upsertNote(def.Notes, definitions.DefinitionNote(item), true)
			i = next - 1
		case strings.HasPrefix(line, "*** Delete Note: "):
			id := strings.TrimSpace(strings.TrimPrefix(line, "*** Delete Note: "))
			def.Notes = deleteNote(def.Notes, id)
		case strings.HasPrefix(line, "*** Add Rule: "):
			id := strings.TrimSpace(strings.TrimPrefix(line, "*** Add Rule: "))
			item, next, err := parsePatchItem(lines, i+1, id)
			if err != nil {
				return def, err
			}
			def.Rules = upsertRule(def.Rules, definitions.DefinitionRule(item), false)
			i = next - 1
		case strings.HasPrefix(line, "*** Update Rule: "):
			id := strings.TrimSpace(strings.TrimPrefix(line, "*** Update Rule: "))
			item, next, err := parsePatchItem(lines, i+1, id)
			if err != nil {
				return def, err
			}
			def.Rules = upsertRule(def.Rules, definitions.DefinitionRule(item), true)
			i = next - 1
		case strings.HasPrefix(line, "*** Delete Rule: "):
			id := strings.TrimSpace(strings.TrimPrefix(line, "*** Delete Rule: "))
			def.Rules = deleteRule(def.Rules, id)
		default:
			return def, fmt.Errorf("unsupported patch line: %s\n%s", line, patchSyntax)
		}
	}
	definitions.SortDefinitionItems(&def)
	return def, nil
}

func parseImportantValue(raw string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "true", "yes", "1", "important", "on":
		return true, nil
	case "false", "no", "0", "off":
		return false, nil
	default:
		return false, fmt.Errorf("important must be true or false")
	}
}

type patchItem struct {
	ID      string
	Title   string
	Content string
}

func parsePatchItem(lines []string, start int, id string) (patchItem, int, error) {
	item := patchItem{ID: strings.TrimSpace(id)}
	i := start
	for ; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "*** ") || strings.HasPrefix(trimmed, "title:") || strings.HasPrefix(trimmed, "snippet:") || strings.HasPrefix(trimmed, "content:") || strings.HasPrefix(trimmed, "add_scope:") || strings.HasPrefix(trimmed, "remove_scope:") || strings.HasPrefix(trimmed, "reset_scope:") {
			break
		}
		if strings.HasPrefix(trimmed, "Title:") {
			item.Title = strings.TrimSpace(strings.TrimPrefix(trimmed, "Title:"))
			continue
		}
		if strings.HasPrefix(trimmed, "Content:") {
			content := strings.TrimSpace(strings.TrimPrefix(trimmed, "Content:"))
			body := []string{content}
			for j := i + 1; j < len(lines); j++ {
				nextTrimmed := strings.TrimSpace(lines[j])
				if nextTrimmed == "" {
					body = append(body, "")
					continue
				}
				if strings.HasPrefix(nextTrimmed, "*** ") || strings.HasPrefix(nextTrimmed, "title:") || strings.HasPrefix(nextTrimmed, "snippet:") || strings.HasPrefix(nextTrimmed, "content:") || strings.HasPrefix(nextTrimmed, "add_scope:") || strings.HasPrefix(nextTrimmed, "remove_scope:") || strings.HasPrefix(nextTrimmed, "reset_scope:") || strings.HasPrefix(nextTrimmed, "Title:") {
					i = j - 1
					break
				}
				body = append(body, lines[j])
				i = j
			}
			item.Content = strings.TrimSpace(strings.Join(body, "\n"))
			continue
		}
		return item, i, fmt.Errorf("unexpected patch item line: %s\n%s", trimmed, patchSyntax)
	}
	if item.ID == "" {
		return item, i, fmt.Errorf("patch item id is required")
	}
	if item.Title == "" {
		return item, i, fmt.Errorf("patch item %q requires Title:", item.ID)
	}
	if item.Content == "" {
		return item, i, fmt.Errorf("patch item %q requires Content:", item.ID)
	}
	return item, i, nil
}

// patchSyntax is returned with a parse error so the model can correct its
// patch instead of guessing again.
const patchSyntax = `patchText is one directive per line, for example:
snippet: one-line summary
content: the full explanation; it may run over
several lines up to the next directive
*** Add Note: relearn-2026-10-21
Title: Relearn re-verification
Content: what was re-checked and what changed
*** Delete Rule: old-rule-id`

// isPatchDirective reports whether a trimmed line starts a new patch
// directive, which ends a multi-line content: block.
func isPatchDirective(line string) bool {
	for _, p := range []string{"*** ", "title:", "snippet:", "content:", "important:", "add_scope:", "remove_scope:", "reset_scope:"} {
		if strings.HasPrefix(line, p) {
			return true
		}
	}
	return false
}

func parseCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	cleaned := make([]string, 0, len(parts))
	for _, part := range parts {
		part = filepath.ToSlash(strings.TrimSpace(part))
		if part == "" {
			continue
		}
		cleaned = append(cleaned, part)
	}
	return cleaned
}

func removeScope(scope []string, remove []string) []string {
	if len(remove) == 0 {
		return scope
	}
	blocked := make(map[string]struct{}, len(remove))
	for _, item := range remove {
		blocked[item] = struct{}{}
	}
	kept := make([]string, 0, len(scope))
	for _, item := range scope {
		if _, ok := blocked[item]; ok {
			continue
		}
		kept = append(kept, item)
	}
	return kept
}

func upsertNote(notes []definitions.DefinitionNote, note definitions.DefinitionNote, mustExist bool) []definitions.DefinitionNote {
	updated := false
	for i := range notes {
		if notes[i].ID != note.ID {
			continue
		}
		notes[i] = note
		updated = true
		break
	}
	if !updated && !mustExist {
		notes = append(notes, note)
	}
	if mustExist && !updated {
		return notes
	}
	sort.Slice(notes, func(i, j int) bool { return notes[i].ID < notes[j].ID })
	return notes
}

func upsertRule(rules []definitions.DefinitionRule, rule definitions.DefinitionRule, mustExist bool) []definitions.DefinitionRule {
	updated := false
	for i := range rules {
		if rules[i].ID != rule.ID {
			continue
		}
		rules[i] = rule
		updated = true
		break
	}
	if !updated && !mustExist {
		rules = append(rules, rule)
	}
	if mustExist && !updated {
		return rules
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	return rules
}

func deleteNote(notes []definitions.DefinitionNote, id string) []definitions.DefinitionNote {
	kept := make([]definitions.DefinitionNote, 0, len(notes))
	for _, note := range notes {
		if note.ID == strings.TrimSpace(id) {
			continue
		}
		kept = append(kept, note)
	}
	return kept
}

func deleteRule(rules []definitions.DefinitionRule, id string) []definitions.DefinitionRule {
	kept := make([]definitions.DefinitionRule, 0, len(rules))
	for _, rule := range rules {
		if rule.ID == strings.TrimSpace(id) {
			continue
		}
		kept = append(kept, rule)
	}
	return kept
}
