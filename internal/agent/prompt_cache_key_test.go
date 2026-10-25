package agent

import "testing"

func TestPromptCacheKeyIsSessionID(t *testing.T) {
	cfg := RunConfig{SessionID: "sess_1", RunID: "run_a"}
	if got := promptCacheKey(cfg); got != "sess_1" {
		t.Fatalf("key = %q, want the session id", got)
	}
}
