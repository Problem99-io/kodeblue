package skill

import (
	"strings"
)

// Permissions resolves skill access based on pattern rules.
type Permissions struct {
	// Global rules from config: pattern → action
	GlobalRules map[string]PermissionAction
}

// NewPermissions creates a Permissions resolver.
func NewPermissions(globalRules map[string]PermissionAction) *Permissions {
	if globalRules == nil {
		globalRules = make(map[string]PermissionAction)
	}
	return &Permissions{GlobalRules: globalRules}
}

// Resolve returns the permission action for a skill name using global rules.
func (p *Permissions) Resolve(skillName string) PermissionAction {
	return resolveRules(skillName, p.GlobalRules)
}

// resolveRules checks a skill name against a set of pattern rules and returns
// the action of the most specific matching pattern, or "allow" if none match.
// An exact name beats any glob, a glob beats the bare "*", and among globs the
// longest pattern wins. Rules arrive as a map, so equally specific patterns are
// settled by the more restrictive action (deny, then ask, then allow) and then
// by pattern text, keeping the result independent of map iteration order.
func resolveRules(skillName string, rules map[string]PermissionAction) PermissionAction {
	result := PermissionAllow
	bestPattern := ""
	found := false

	for pattern, action := range rules {
		if !matchPattern(pattern, skillName) {
			continue
		}
		if !found || morePreciseRule(pattern, action, bestPattern, result) {
			result, bestPattern, found = action, pattern, true
		}
	}

	return result
}

// morePreciseRule reports whether rule (pattern, action) should take
// precedence over the current best rule.
func morePreciseRule(pattern string, action PermissionAction, bestPattern string, bestAction PermissionAction) bool {
	if a, b := patternSpecificity(pattern), patternSpecificity(bestPattern); a != b {
		return a > b
	}
	if len(pattern) != len(bestPattern) {
		return len(pattern) > len(bestPattern)
	}
	if a, b := actionRestrictiveness(action), actionRestrictiveness(bestAction); a != b {
		return a > b
	}
	return pattern < bestPattern
}

// patternSpecificity ranks pattern kinds: exact name > glob > "*".
func patternSpecificity(pattern string) int {
	switch {
	case pattern == "*":
		return 0
	case strings.Contains(pattern, "*"):
		return 1
	default:
		return 2
	}
}

func actionRestrictiveness(action PermissionAction) int {
	switch action {
	case PermissionDeny:
		return 2
	case PermissionAsk:
		return 1
	default:
		return 0
	}
}

// matchPattern matches a skill name against a glob-like pattern with * wildcards.
func matchPattern(pattern, name string) bool {
	// Simple wildcard matching
	if pattern == "*" {
		return true
	}
	if !strings.Contains(pattern, "*") {
		return pattern == name
	}

	// Convert glob pattern to prefix/suffix match
	parts := strings.SplitN(pattern, "*", 2)
	prefix := parts[0]
	suffix := ""
	if len(parts) > 1 {
		suffix = parts[1]
	}

	if !strings.HasPrefix(name, prefix) {
		return false
	}
	if suffix != "" && !strings.HasSuffix(name, suffix) {
		return false
	}
	return len(name) >= len(prefix)+len(suffix)
}
