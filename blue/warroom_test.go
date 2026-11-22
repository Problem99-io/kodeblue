package blue

import (
	"strings"
	"testing"
)

func TestWarRoomRoleDelegatesHaveOnlyTheScopedReadBroker(t *testing.T) {
	defs, err := Agents()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range defs {
		if a.Name == "blue-investigator" {
			t.Fatal("independent Investigator role returned")
		}
	}
	delegates := WarRoomDelegates()
	if len(delegates) != 4 {
		t.Fatal("missing native role delegates")
	}
	for _, agent := range delegates {
		if !strings.Contains(agent.Instructions, "Protocol: evidence-investigation/v1") {
			t.Fatal("protocol was not explicitly loaded")
		}
		if len(agent.Tools) != 1 || agent.Tools[0] != "mcp__kodeblue__research_context" || agent.MaxIterations > 12 || agent.Instructions == "" {
			t.Fatalf("delegate gained unrelated permissions: %+v", agent)
		}
	}
}
