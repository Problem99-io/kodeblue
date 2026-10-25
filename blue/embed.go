// Package blue holds kodeblue's model-facing assets: the agent definitions
// (instructions + tool allowlists for each role), the triage prompt, the base
// system prompt, and the seed skills copied into the agents' workspace. They
// are plain files so they can be reviewed and edited like code.
package blue

import (
	"embed"
	"io/fs"
	"strconv"
	"strings"
)

//go:embed prompts/triage.md
var TriagePrompt string

//go:embed agents/*.md
var agentFS embed.FS

//go:embed all:skills
var SkillsFS embed.FS

// Agent is one kodeblue role, registered as an engine agent definition.
type Agent struct {
	Name            string
	Description     string
	Model           string // empty = daemon's configured model for the role
	Tools           []string
	MaxIterations   int
	MaxOutputTokens int
	Instructions    string
}

// Agents parses agents/*.md. Each file has a frontmatter block:
//
//	---
//	name: blue-responder
//	description: ...
//	tools: a, b, c
//	max_iterations: 30
//	---
//
// max_output_tokens may also be set, but kodeblue's agents leave it out: a
// cap cuts a reasoning model off mid-thought, so by default the engine sends
// none (-1) and only the provider's own limit applies.
func Agents() ([]Agent, error) {
	entries, err := fs.ReadDir(agentFS, "agents")
	if err != nil {
		return nil, err
	}
	var out []Agent
	for _, e := range entries {
		b, err := agentFS.ReadFile("agents/" + e.Name())
		if err != nil {
			return nil, err
		}
		s := strings.ReplaceAll(string(b), "\r\n", "\n")
		if !strings.HasPrefix(s, "---\n") {
			continue
		}
		end := strings.Index(s[4:], "\n---\n")
		if end < 0 {
			continue
		}
		a := Agent{Instructions: strings.TrimSpace(s[4+end+5:]), MaxOutputTokens: -1}
		for _, line := range strings.Split(s[4:4+end], "\n") {
			k, v, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			v = strings.TrimSpace(v)
			switch strings.TrimSpace(k) {
			case "name":
				a.Name = v
			case "description":
				a.Description = v
			case "model":
				a.Model = v
			case "tools":
				for _, t := range strings.Split(v, ",") {
					if t = strings.TrimSpace(t); t != "" {
						a.Tools = append(a.Tools, t)
					}
				}
			case "max_iterations":
				a.MaxIterations, _ = strconv.Atoi(v)
			case "max_output_tokens":
				a.MaxOutputTokens, _ = strconv.Atoi(v)
			}
		}
		if a.Name != "" {
			out = append(out, a)
		}
	}
	return out, nil
}
