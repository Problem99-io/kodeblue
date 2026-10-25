// Package childenv builds the environment for processes the engine spawns:
// stdio MCP servers.
//
// The engine itself is non-dumpable (see cmd/kodeblue-engine/harden_linux.go), so a
// same-uid peer cannot read its /proc/<pid>/environ. That protection does not
// survive execve: the dumpable flag resets for every child, so a secret left
// in the environment would be readable in the child's /proc/<pid>/environ by
// any process running as the same user. Filtering the child's environment
// keeps credentials out of reach, and it applies to every spawn path.
//
// NOTE: this is a fail-open, hardcoded list. Any new secret environment
// variable must be added to Denylist too.
package childenv

import "os"

// Denylist names the environment variables that must never reach a child
// process the daemon spawns.
var Denylist = map[string]struct{}{
	// The gateway key, for standalone runs that pass it as an environment
	// variable (see policy.GatewayConfig.APIKeyEnv).
	"KODEBLUE_GATEWAY_API_KEY": {},
	// kodeblue's own key variable ([inference] api_key_env), in case a
	// standalone run inherits it.
	"KODEBLUE_INFERENCE_API_KEY": {},
	// Provider keys an operator may have exported in a standalone run.
	"OPENAI_API_KEY":    {},
	"ANTHROPIC_API_KEY": {},
}

// IsDenied reports whether key is a secret that must be stripped from a child's
// environment.
func IsDenied(key string) bool {
	_, denied := Denylist[key]
	return denied
}

// Filtered returns the daemon's own environment with every denylisted key
// removed, in "KEY=VALUE" form. Callers append their own entries afterwards.
func Filtered() []string {
	base := os.Environ()
	out := make([]string, 0, len(base))
	for _, entry := range base {
		key, _, found := SplitEntry(entry)
		if !found {
			continue
		}
		if IsDenied(key) {
			continue
		}
		out = append(out, entry)
	}
	return out
}

// SplitEntry splits a "KEY=VALUE" environment entry. The final return value
// reports whether the entry was well formed.
func SplitEntry(entry string) (string, string, bool) {
	for index := 0; index < len(entry); index++ {
		if entry[index] == '=' {
			return entry[:index], entry[index+1:], true
		}
	}
	return "", "", false
}
