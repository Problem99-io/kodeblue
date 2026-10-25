package skill

import (
	"fmt"
	"regexp"
	"strings"
)

var nameRegex = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// PermissionAction controls how a skill is accessed.
type PermissionAction string

const (
	PermissionAllow PermissionAction = "allow"
	PermissionDeny  PermissionAction = "deny"
	PermissionAsk   PermissionAction = "ask"
)

// Definition represents a parsed SKILL.md file.
type Definition struct {
	Name          string            `json:"name"`
	Description   string            `json:"description"`
	License       string            `json:"license,omitempty"`
	Compatibility string            `json:"compatibility,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	Content       string            `json:"content"`
	FilePath      string            `json:"file_path"`
	DirectoryPath string            `json:"directory_path"`
}

// Summary is a lightweight view for listing skills.
type Summary struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// ValidateName checks that a skill name conforms to the required format.
func ValidateName(name string) error {
	if len(name) < 1 || len(name) > 64 {
		return fmt.Errorf("skill name must be 1-64 characters, got %d", len(name))
	}
	if !nameRegex.MatchString(name) {
		return fmt.Errorf("skill name %q must match ^[a-z0-9]+(-[a-z0-9]+)*$", name)
	}
	return nil
}

// ParseMarkdown parses a SKILL.md file's raw content into a Definition.
func ParseMarkdown(raw string) (*Definition, error) {
	normalized := strings.ReplaceAll(raw, "\r\n", "\n")

	if !strings.HasPrefix(normalized, "---\n") {
		return nil, fmt.Errorf("SKILL.md must start with YAML frontmatter (---)")
	}
	end := strings.Index(normalized[4:], "\n---")
	if end < 0 {
		return nil, fmt.Errorf("SKILL.md frontmatter not closed (missing closing ---)")
	}

	frontmatter := normalized[4 : 4+end]
	body := ""
	afterClose := 4 + end + 4
	if afterClose < len(normalized) {
		body = strings.TrimLeft(normalized[afterClose:], "\n")
	}

	def := &Definition{Content: body}

	lines := strings.Split(frontmatter, "\n")
	i := 0
	for i < len(lines) {
		line := lines[i]

		if isBlankLine(line) {
			i++
			continue
		}

		// Indented lines belong to the entry above; readScalar and the metadata
		// block below consume their own, so anything left here is stray.
		if indentWidth(line) > 0 {
			i++
			continue
		}

		trimmed := strings.TrimSpace(line)
		sep := strings.IndexByte(trimmed, ':')
		if sep <= 0 {
			i++
			continue
		}

		key := strings.TrimSpace(trimmed[:sep])
		rest := strings.TrimSpace(trimmed[sep+1:])
		i++

		if key == "metadata" && rest == "" {
			metadata := make(map[string]string)
			for i < len(lines) {
				nested := lines[i]
				if isBlankLine(nested) || indentWidth(nested) == 0 {
					break
				}
				nt := strings.TrimSpace(nested)
				nsep := strings.IndexByte(nt, ':')
				i++
				if nsep <= 0 {
					continue
				}
				nkey := strings.TrimSpace(nt[:nsep])
				nval, next := readScalar(strings.TrimSpace(nt[nsep+1:]), lines, i, indentWidth(nested))
				i = next
				if nkey != "" {
					metadata[nkey] = nval
				}
			}
			if len(metadata) > 0 {
				def.Metadata = metadata
			}
			continue
		}

		val, next := readScalar(rest, lines, i, 0)
		i = next

		switch key {
		case "name":
			def.Name = val
		case "description":
			def.Description = val
		case "license":
			def.License = val
		case "compatibility":
			def.Compatibility = val
		}
	}

	if def.Name == "" {
		return nil, fmt.Errorf("SKILL.md frontmatter missing required field: name")
	}
	if def.Description == "" {
		return nil, fmt.Errorf("SKILL.md frontmatter missing required field: description")
	}
	if err := ValidateName(def.Name); err != nil {
		return nil, err
	}
	// Third-party skills (e.g. installed via `npx skills add`) sometimes carry a
	// description longer than the limit. Clamp rather than reject: a long
	// description still routes the model correctly, whereas dropping the skill
	// makes it invisible.
	def.Description = truncateRunes(def.Description, maxDescriptionLen)

	return def, nil
}

const maxDescriptionLen = 1024

// blockScalarHeaders are the YAML block scalar indicators we understand, mapped
// to whether the block is folded (">" joins lines with spaces) or literal
// ("|" keeps the line breaks).
var blockScalarHeaders = map[string]bool{
	">": true, ">-": true, ">+": true,
	"|": false, "|-": false, "|+": false,
}

// readScalar reads the value for a key whose inline remainder is `rest`, pulling
// in any continuation lines that are indented deeper than parentIndent. It
// handles YAML block scalars (>, >-, |, |-, ...), plain multi-line scalars and
// quoted scalars that span lines — all three shapes appear in skills published
// to the agent-skills ecosystem. Returns the value and the next line index.
func readScalar(rest string, lines []string, i int, parentIndent int) (string, int) {
	if folded, ok := blockScalarHeaders[rest]; ok {
		var block []string
		for i < len(lines) {
			if isBlankLine(lines[i]) {
				block = append(block, "")
				i++
				continue
			}
			if indentWidth(lines[i]) <= parentIndent {
				break
			}
			block = append(block, strings.TrimSpace(lines[i]))
			i++
		}
		for len(block) > 0 && block[len(block)-1] == "" {
			block = block[:len(block)-1]
		}
		if folded {
			return foldLines(block), i
		}
		return strings.Join(block, "\n"), i
	}

	parts := []string{rest}
	for i < len(lines) {
		if isBlankLine(lines[i]) || indentWidth(lines[i]) <= parentIndent {
			break
		}
		parts = append(parts, strings.TrimSpace(lines[i]))
		i++
	}
	return unquoteScalar(foldLines(parts)), i
}

// foldLines joins lines with spaces, turning blank lines into paragraph breaks —
// YAML's folding rule for ">" blocks and plain multi-line scalars.
func foldLines(lines []string) string {
	var b strings.Builder
	pendingBreak := false
	for _, l := range lines {
		if l == "" {
			pendingBreak = true
			continue
		}
		if b.Len() > 0 {
			if pendingBreak {
				b.WriteByte('\n')
			} else {
				b.WriteByte(' ')
			}
		}
		pendingBreak = false
		b.WriteString(l)
	}
	return b.String()
}

func unquoteScalar(s string) string {
	s = strings.TrimSpace(s)
	if len(s) < 2 {
		return s
	}
	if s[0] == '"' && s[len(s)-1] == '"' {
		return strings.ReplaceAll(s[1:len(s)-1], `\"`, `"`)
	}
	if s[0] == '\'' && s[len(s)-1] == '\'' {
		return strings.ReplaceAll(s[1:len(s)-1], "''", "'")
	}
	return s
}

func indentWidth(s string) int {
	n := 0
	for n < len(s) && (s[n] == ' ' || s[n] == '\t') {
		n++
	}
	return n
}

func isBlankLine(s string) bool { return strings.TrimSpace(s) == "" }

func truncateRunes(s string, max int) string {
	if len(s) <= max {
		return s
	}
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max])
}
