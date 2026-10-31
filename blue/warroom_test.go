package blue

import "testing"

func TestWarRoomRoleDelegatesHaveOnlyTheScopedReadBroker(t *testing.T) {
	delegates := WarRoomDelegates()
	if len(delegates) != 4 {
		t.Fatal("missing native role delegates")
	}
	for _, agent := range delegates {
		if len(agent.Tools) != 1 || agent.Tools[0] != "mcp__kodeblue__research_context" || agent.MaxIterations > 12 || agent.Instructions == "" {
			t.Fatalf("delegate gained unrelated permissions: %+v", agent)
		}
	}
}
