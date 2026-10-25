// Package secrets holds the credentials the supervisor (kodeblue) hands this
// process at startup.
//
// A secret placed here exists only in this process's heap. It is never:
//
//   - written to disk: the generated config.toml carries settings but no key
//     material, so an agent that can read its own config learns nothing;
//   - put in the environment: every child the engine spawns (MCP
//     servers) inherits the environment, and hardenProcess() only protects
//     /proc/<pid>/environ from outside readers, not from descendants;
//   - left in argv: the supervisor sends secrets over an inherited pipe, and
//     the fallback command-line flags are zeroed out of argv right after they
//     are parsed (see cmd/kodeblue-engine/scrub_argv_linux.go), because
//     /proc/<pid>/cmdline stays world-readable even for a non-dumpable process.
//
// Values are read back through the ResolveAPIKey methods in internal/policy,
// where they take precedence over the config file and the environment. There
// is no persistence and no reload: a credential change takes effect on the
// next start.
package secrets

import "sync"

// Slot names: the keys of the JSON payload on the secrets pipe.
const (
	// GatewayAPIKey authenticates the engine to its model gateway.
	GatewayAPIKey = "gateway"

	// ServerAPIKey gates this daemon's own HTTP API against other local
	// processes.
	ServerAPIKey = "server"
)

// NamedGatewayAPIKey is the slot of the key for the named gateway id
// ([providers.gateways.<id>]).
func NamedGatewayAPIKey(id string) string { return GatewayAPIKey + ":" + id }

var (
	mu    sync.RWMutex
	store = map[string]string{}
)

// Set records a secret under name. An empty value clears the slot, so callers
// can pass through "unset" without a special case.
func Set(name, value string) {
	mu.Lock()
	defer mu.Unlock()
	if value == "" {
		delete(store, name)
		return
	}
	store[name] = value
}

// Get returns the secret stored under name, or "" if the supervisor did not
// provide one.
func Get(name string) string {
	mu.RLock()
	defer mu.RUnlock()
	return store[name]
}

// Has reports whether a non-empty secret is stored under name. Useful for
// logging and status endpoints, which must report presence without ever
// handling the value itself.
func Has(name string) bool {
	return Get(name) != ""
}
