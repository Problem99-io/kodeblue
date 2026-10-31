package runtime

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Problem99-io/kodeblue/internal/blue/config"
	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
)

func TestInvestigatorRegistersThroughNormalEngineCatalog(t *testing.T) {
	seen := false
	delegateSeen := false
	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.URL.Path == "/v1/agents" {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		if r.Method != "POST" || r.URL.Path != "/v1/agents" {
			t.Errorf("unexpected catalog call %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		var agent struct {
			Name         string   `json:"name"`
			Model        string   `json:"model"`
			Tools        []string `json:"tools"`
			Iterations   int      `json:"max_iterations"`
			Instructions string   `json:"instructions"`
		}
		if err := json.NewDecoder(r.Body).Decode(&agent); err != nil {
			t.Error(err)
		}
		if agent.Name == "blue-investigator" {
			seen = true
			if agent.Model != "research-only" || agent.Iterations != 3 || len(agent.Tools) != 1 || agent.Tools[0] != "mcp__kodeblue__research_context" || !strings.Contains(agent.Instructions, "native-review-note") {
				t.Errorf("bad native registration %+v", agent)
			}
		}
		if agent.Name == "blue-warroom-responder" {
			delegateSeen = true
			if agent.Model != "incident-role-model" || agent.Iterations != 3 || len(agent.Tools) != 1 || agent.Tools[0] != "mcp__kodeblue__research_context" || !strings.Contains(agent.Instructions, "responder-role-note") {
				t.Errorf("unsafe or incorrectly configured delegate %+v", agent)
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"id": "agent-" + agent.Name})
	}))
	defer engine.Close()
	cfg := config.Default()
	cfg.Inference.AgentModel = "native-default"
	cfg.Inference.AgentModels = map[string]string{hubproto.RoleInvestigator: "research-only", hubproto.RoleResponder: "incident-role-model"}
	cfg.Budget.IncidentMaxIterations = 3
	cfg.Agents.Instructions = map[string]string{hubproto.RoleInvestigator: "native-review-note", hubproto.RoleResponder: "responder-role-note"}
	k := &Engine{cfg: cfg, baseURL: engine.URL, http: engine.Client(), agents: map[string]string{}}
	if err := k.registerAgents(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !seen || !delegateSeen || k.agents["blue-investigator"] == "" {
		t.Fatal("investigator was not registered in the native catalog")
	}
}
