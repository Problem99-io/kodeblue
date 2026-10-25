package api

import (
	"net/http"
	"strings"

	"github.com/Problem99-io/kodeblue/internal/definitions"
)

func definitionsStore(deps *Dependencies) *definitions.Store {
	root := strings.TrimSpace(deps.DefinitionsRoot)
	if root == "" {
		root = deps.ProjectRoot
	}
	return definitions.NewStore(root)
}

// handleListDefinitions returns all definitions for the project.
func handleListDefinitions(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		store := definitionsStore(deps)
		items, err := store.List()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, items)
	}
}

// handleGetDefinition returns a single definition by ID.
func handleGetDefinition(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimSpace(r.PathValue("id"))
		if id == "" {
			writeError(w, http.StatusBadRequest, "id is required")
			return
		}
		store := definitionsStore(deps)
		def, err := store.Get(id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if def == nil {
			writeError(w, http.StatusNotFound, "definition not found")
			return
		}
		writeJSON(w, http.StatusOK, def)
	}
}

// handleCreateDefinition creates a new definition.
func handleCreateDefinition(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var input definitions.Definition
		if err := readJSON(r, &input); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
			return
		}
		store := definitionsStore(deps)
		created, err := store.Create(input)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, created)
	}
}

// handleUpdateDefinition updates an existing definition by ID.
func handleUpdateDefinition(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimSpace(r.PathValue("id"))
		if id == "" {
			writeError(w, http.StatusBadRequest, "id is required")
			return
		}
		var input definitions.Definition
		if err := readJSON(r, &input); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
			return
		}
		input.ID = id
		store := definitionsStore(deps)
		updated, err := store.Update(input)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if updated == nil {
			writeError(w, http.StatusNotFound, "definition not found")
			return
		}
		writeJSON(w, http.StatusOK, updated)
	}
}

// handleDeleteDefinition deletes a definition by ID.
func handleDeleteDefinition(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimSpace(r.PathValue("id"))
		if id == "" {
			writeError(w, http.StatusBadRequest, "id is required")
			return
		}
		store := definitionsStore(deps)
		deleted, err := store.Delete(id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if !deleted {
			writeError(w, http.StatusNotFound, "definition not found")
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
	}
}
