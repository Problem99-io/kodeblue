package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	internal "github.com/Problem99-io/kodeblue/internal"
	"github.com/Problem99-io/kodeblue/internal/skill"
)

// skillTool lets agents discover and load skill definitions on-demand.
type skillTool struct {
	registry *skill.Registry
}

// NewSkillTool creates a tool that provides skill loading for agents.
func NewSkillTool(registry *skill.Registry) Tool {
	return &skillTool{registry: registry}
}

func (t *skillTool) Name() internal.ToolName { return "skill" }

func (t *skillTool) Description() string {
	summaries := t.registry.List()
	if len(summaries) == 0 {
		return "Load a skill by name. No skills are currently available."
	}

	var sb strings.Builder
	sb.WriteString("Load a skill by name to get specialized instructions. Available skills:\n\n")
	sb.WriteString("<available_skills>\n")
	for _, s := range summaries {
		sb.WriteString(fmt.Sprintf("  <skill>\n    <name>%s</name>\n    <description>%s</description>\n  </skill>\n", s.Name, s.Description))
	}
	sb.WriteString("</available_skills>")
	return sb.String()
}

func (t *skillTool) Parameters() json.RawMessage {
	return makeSchema(
		map[string]any{
			"name": map[string]any{
				"type":        "string",
				"description": "The name of the skill to load",
			},
		},
		[]string{"name"},
	)
}

func (t *skillTool) Execute(ctx context.Context, args json.RawMessage) (*Result, error) {
	var params struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return &Result{Content: "invalid arguments: " + err.Error(), IsError: true}, nil
	}

	if params.Name == "" {
		return &Result{Content: "skill name is required", IsError: true}, nil
	}

	def, ok := t.registry.Load(params.Name)
	if !ok {
		return &Result{
			Content: fmt.Sprintf("skill %q not found. Use the skill tool description to see available skills.", params.Name),
			IsError: true,
		}, nil
	}

	// Build response: frontmatter summary + full content
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# Skill: %s\n\n", def.Name))
	sb.WriteString(fmt.Sprintf("**Description:** %s\n", def.Description))
	if def.License != "" {
		sb.WriteString(fmt.Sprintf("**License:** %s\n", def.License))
	}
	if len(def.Metadata) > 0 {
		sb.WriteString("**Metadata:**\n")
		for k, v := range def.Metadata {
			sb.WriteString(fmt.Sprintf("  - %s: %s\n", k, v))
		}
	}
	// Skills published to the agent-skills ecosystem (e.g. anything installed by
	// `npx skills add <owner>/<repo>`) routinely ship references/, templates/ and
	// scripts/ alongside SKILL.md and point at them with paths relative to the
	// skill directory. Without the directory and its contents the model has no
	// way to resolve those pointers.
	if def.DirectoryPath != "" {
		sb.WriteString(fmt.Sprintf("**Directory:** %s\n", def.DirectoryPath))
		if bundled := listBundledFiles(def.DirectoryPath); len(bundled) > 0 {
			sb.WriteString("**Bundled files** (read with the file tools, paths are relative to the directory above):\n")
			for _, f := range bundled {
				sb.WriteString(fmt.Sprintf("  - %s\n", f))
			}
		}
	}

	sb.WriteString("\n")
	sb.WriteString(def.Content)

	return &Result{
		Content: sb.String(),
		Metadata: map[string]any{
			"skill_name":     def.Name,
			"description":    def.Description,
			"file_path":      def.FilePath,
			"directory_path": def.DirectoryPath,
		},
	}, nil
}

// maxBundledFiles caps the listing so a skill shipping a large template tree
// cannot flood the tool result.
const maxBundledFiles = 100

// listBundledFiles returns paths of files shipped alongside SKILL.md, relative
// to the skill directory and sorted. SKILL.md itself is omitted — its content is
// already in the result.
func listBundledFiles(dir string) []string {
	var files []string
	truncated := false

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entry — skip it, keep walking
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "node_modules" {
				return fs.SkipDir
			}
			return nil
		}
		rel, relErr := filepath.Rel(dir, path)
		if relErr != nil || rel == "SKILL.md" {
			return nil
		}
		if len(files) >= maxBundledFiles {
			truncated = true
			return filepath.SkipAll
		}
		files = append(files, rel)
		return nil
	})
	if err != nil {
		return nil
	}

	sort.Strings(files)
	if truncated {
		files = append(files, fmt.Sprintf("... (listing truncated at %d files)", maxBundledFiles))
	}
	return files
}
