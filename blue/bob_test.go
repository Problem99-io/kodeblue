package blue

import "testing"

func TestBobHasOnlyReadOnlyTools(t *testing.T) {
	agents, err := Agents()
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"mcp__kodeblue__incident_get": true, "mcp__kodeblue__findings_list": true, "mcp__kodeblue__stats": true, "mcp__kodeblue__baseline_query": true, "mcp__kodeblue__monitor_list": true, "mcp__kodeblue__sensor_coverage": true, "mcp__kodeblue__service_inventory": true, "mcp__kodeblue__response_list": true, "mcp__kodeblue__vulnerability_list": true}
	for _, a := range agents {
		if a.Name == "blue-bob" {
			if a.MaxIterations > 12 || a.MaxIterations < 1 {
				t.Fatal("unbounded Bob session")
			}
			for _, tool := range a.Tools {
				if !allowed[tool] {
					t.Fatalf("Bob acquired a non-read-only capability: %s", tool)
				}
				delete(allowed, tool)
			}
			if len(allowed) != 0 {
				t.Fatal("Bob lost required evidence tools")
			}
			return
		}
	}
	t.Fatal("Bob agent not registered")
}
