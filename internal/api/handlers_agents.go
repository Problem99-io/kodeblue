package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	internal "github.com/Problem99-io/kodeblue/internal"
)

type createAgentRequest struct {
	Name            string   `json:"name"`
	Disabled        bool     `json:"disabled"`
	Description     string   `json:"description"`
	Instructions    string   `json:"instructions"`
	Tools           []string `json:"tools"`
	Provider        string   `json:"provider"`
	Model           string   `json:"model"`
	ReasoningEffort string   `json:"reasoning_effort"`
	MaxIterations   int      `json:"max_iterations"`
	MaxOutputTokens int      `json:"max_output_tokens"`
}

type updateAgentRequest struct {
	Name            *string  `json:"name"`
	Disabled        *bool    `json:"disabled"`
	Description     *string  `json:"description"`
	Instructions    *string  `json:"instructions"`
	Tools           []string `json:"tools"`
	Provider        *string  `json:"provider"`
	Model           *string  `json:"model"`
	ReasoningEffort *string  `json:"reasoning_effort"`
	MaxIterations   *int     `json:"max_iterations"`
	MaxOutputTokens *int     `json:"max_output_tokens"`
}

// maxAgentOutputTokens is deliberately no larger than the biggest context
// window currently advertised by the model catalog (1,000,000 tokens).
const maxAgentOutputTokens = 1_000_000

// warnUnknownTools logs the allowlisted tools that are not registered. Such an
// agent is still stored (an MCP server may connect later), but its runs cannot
// use those tools, and an allowlist that matches nothing allows no tool at all.
func warnUnknownTools(deps *Dependencies, agent *internal.AgentDefinition) {
	if deps.Logger == nil || len(deps.ToolNames) == 0 {
		return
	}
	registered := make(map[string]bool, len(deps.ToolNames))
	for _, name := range deps.ToolNames {
		registered[internal.CanonicalToolNameString(name)] = true
	}
	var unknown []string
	for _, name := range agent.Tools {
		if !registered[internal.CanonicalToolNameString(name)] {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) > 0 {
		deps.Logger.Warn("agent allowlist names tools that are not registered", "agent", agent.Name, "unknown_tools", unknown)
	}
}

func validateMaxOutputTokens(value int) error {
	if value < -1 || value > maxAgentOutputTokens {
		return fmt.Errorf("max_output_tokens must be -1 or between 0 and %d (-1 uses the provider boundary; 0 uses the default of 32768), got %d", maxAgentOutputTokens, value)
	}
	return nil
}

func validateReasoningEffort(value string) error {
	value = strings.ToLower(strings.TrimSpace(value))
	for _, allowed := range []string{"", "default", "none", "minimal", "low", "medium", "high", "xhigh", "max", "on", "off"} {
		if value == allowed {
			return nil
		}
	}
	return fmt.Errorf("reasoning_effort must be one of default, none, minimal, low, medium, high, xhigh, max, on, or off")
}

func handleCreateAgent(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req createAgentRequest
		if err := readJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}

		name := strings.TrimSpace(req.Name)
		if name == "" {
			writeError(w, http.StatusBadRequest, "name is required")
			return
		}

		existing, _ := deps.Agents.GetByName(name)
		if existing != nil {
			writeError(w, http.StatusConflict, "agent with this name already exists")
			return
		}

		if err := validateMaxOutputTokens(req.MaxOutputTokens); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := validateReasoningEffort(req.ReasoningEffort); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		now := time.Now()
		agent := &internal.AgentDefinition{
			ID:              internal.NewAgentDefinitionID(),
			Name:            name,
			Disabled:        req.Disabled,
			Description:     req.Description,
			Instructions:    req.Instructions,
			Tools:           req.Tools,
			Provider:        req.Provider,
			Model:           req.Model,
			ReasoningEffort: strings.ToLower(strings.TrimSpace(req.ReasoningEffort)),
			MaxIterations:   req.MaxIterations,
			MaxOutputTokens: req.MaxOutputTokens,
			CreatedAt:       now,
			UpdatedAt:       now,
		}
		if agent.Tools == nil {
			agent.Tools = []string{}
		}
		warnUnknownTools(deps, agent)

		if err := deps.Agents.Create(agent); err != nil {
			writeStoreError(w, deps.Logger, http.StatusInternalServerError, "failed to create agent", err)
			return
		}

		writeJSON(w, http.StatusCreated, agent)
	}
}

func handleGetAgent(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("agentId")

		agent, err := deps.Agents.Get(id)
		if err != nil {
			deps.Logger.Error("failed to get agent", "error", err)
			writeError(w, http.StatusInternalServerError, "failed to get agent")
			return
		}
		if agent == nil {
			writeError(w, http.StatusNotFound, "agent not found")
			return
		}

		writeJSON(w, http.StatusOK, agent)
	}
}

func handleListAgents(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		agents, err := deps.Agents.List()
		if err != nil {
			deps.Logger.Error("failed to list agents", "error", err)
			writeError(w, http.StatusInternalServerError, "failed to list agents")
			return
		}
		if agents == nil {
			agents = []*internal.AgentDefinition{}
		}

		writeJSON(w, http.StatusOK, agents)
	}
}

func handleUpdateAgent(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("agentId")

		agent, err := deps.Agents.Get(id)
		if err != nil {
			deps.Logger.Error("failed to get agent", "error", err)
			writeError(w, http.StatusInternalServerError, "failed to get agent")
			return
		}
		if agent == nil {
			writeError(w, http.StatusNotFound, "agent not found")
			return
		}

		var req updateAgentRequest
		if err := readJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}

		if req.Name != nil {
			name := strings.TrimSpace(*req.Name)
			if name == "" {
				writeError(w, http.StatusBadRequest, "name cannot be empty")
				return
			}
			if name != agent.Name {
				existing, _ := deps.Agents.GetByName(name)
				if existing != nil {
					writeError(w, http.StatusConflict, "agent with this name already exists")
					return
				}
			}
			agent.Name = name
		}
		if req.Disabled != nil {
			agent.Disabled = *req.Disabled
		}
		if req.Description != nil {
			agent.Description = *req.Description
		}
		if req.Instructions != nil {
			agent.Instructions = *req.Instructions
		}
		if req.Tools != nil {
			agent.Tools = req.Tools
			warnUnknownTools(deps, agent)
		}
		if req.Provider != nil {
			agent.Provider = *req.Provider
		}
		if req.Model != nil {
			agent.Model = *req.Model
		}
		if req.MaxIterations != nil {
			agent.MaxIterations = *req.MaxIterations
		}
		if req.MaxOutputTokens != nil {
			if err := validateMaxOutputTokens(*req.MaxOutputTokens); err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			agent.MaxOutputTokens = *req.MaxOutputTokens
		}
		if req.ReasoningEffort != nil {
			if err := validateReasoningEffort(*req.ReasoningEffort); err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			agent.ReasoningEffort = strings.ToLower(strings.TrimSpace(*req.ReasoningEffort))
		}

		if err := deps.Agents.Update(agent); err != nil {
			writeStoreError(w, deps.Logger, http.StatusInternalServerError, "failed to update agent", err)
			return
		}

		writeJSON(w, http.StatusOK, agent)
	}
}

func handleDeleteAgent(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("agentId")

		agent, err := deps.Agents.Get(id)
		if err != nil {
			deps.Logger.Error("failed to get agent", "error", err)
			writeError(w, http.StatusInternalServerError, "failed to get agent")
			return
		}
		if agent == nil {
			writeError(w, http.StatusNotFound, "agent not found")
			return
		}

		if err := deps.Agents.Delete(id); err != nil {
			writeStoreError(w, deps.Logger, http.StatusInternalServerError, "failed to delete agent", err)
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "id": id})
	}
}
