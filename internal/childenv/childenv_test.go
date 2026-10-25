package childenv

import "testing"

// TestFilteredStripsDaemonSecrets is a security regression gate. The daemon is
// non-dumpable, but that flag resets on execve: every variable that survives
// into a child is readable in the child's /proc/<pid>/environ by any process
// running as the same uid — which includes previewed apps, since /proc is in
// the preview sandbox's Landlock read allowlist so bun can start. If this test
// fails, a daemon credential is reachable by arbitrary project code.
func TestFilteredStripsDaemonSecrets(t *testing.T) {
	secrets := map[string]string{
		"KODEBLUE_GATEWAY_API_KEY": "gateway-secret",
		"OPENAI_API_KEY":           "openai-secret",
		"ANTHROPIC_API_KEY":        "anthropic-secret",
	}
	for key, value := range secrets {
		t.Setenv(key, value)
	}
	t.Setenv("PATH", "/usr/bin:/bin")
	t.Setenv("KODEBLUE_CONFIG_PROFILE", "project-42")

	env := Filtered()
	seen := make(map[string]string, len(env))
	for _, entry := range env {
		key, value, found := SplitEntry(entry)
		if !found {
			t.Fatalf("Filtered() returned a malformed entry: %q", entry)
		}
		seen[key] = value
	}

	for key, value := range secrets {
		if got, present := seen[key]; present {
			t.Errorf("SECURITY REGRESSION: %s reached a child process (value %q); "+
				"it is readable in the child's /proc/<pid>/environ by any same-uid "+
				"process, including previewed apps", key, got)
		}
		// The value must not survive under any other name either.
		for otherKey, otherValue := range seen {
			if otherValue == value {
				t.Errorf("SECURITY REGRESSION: secret value of %s leaked as %s", key, otherKey)
			}
		}
	}

	// Non-secret configuration the daemon's children legitimately need must
	// still get through — over-filtering breaks run_shell and MCP servers.
	if seen["PATH"] != "/usr/bin:/bin" {
		t.Errorf("PATH was dropped from the child environment; got %q", seen["PATH"])
	}
	if seen["KODEBLUE_CONFIG_PROFILE"] != "project-42" {
		t.Errorf("KODEBLUE_CONFIG_PROFILE was dropped; got %q", seen["KODEBLUE_CONFIG_PROFILE"])
	}
}

func TestIsDeniedMatchesExactKeysOnly(t *testing.T) {
	if !IsDenied("KODEBLUE_GATEWAY_API_KEY") {
		t.Error("the gateway API key must be denied to children")
	}
	// The denylist is exact-match by design: KODEBLUE_* carries the agent's own
	// non-secret config, so a prefix rule would strip configuration it needs.
	if IsDenied("KODEBLUE_GATEWAY_API_KEY_ENV") {
		t.Error("KODEBLUE_GATEWAY_API_KEY_ENV is not a secret and must reach children")
	}
	if IsDenied("PATH") {
		t.Error("PATH must reach children")
	}
}

func TestSplitEntry(t *testing.T) {
	key, value, found := SplitEntry("FOO=bar=baz")
	if !found || key != "FOO" || value != "bar=baz" {
		t.Errorf("SplitEntry split on the wrong '='; got (%q, %q, %v)", key, value, found)
	}
	if _, _, found := SplitEntry("NOEQUALS"); found {
		t.Error("SplitEntry accepted a malformed entry")
	}
}
