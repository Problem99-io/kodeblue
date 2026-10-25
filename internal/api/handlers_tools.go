package api

import (
	"net/http"
	"sort"
)

func handleListTools(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		names := []string{}
		if deps != nil {
			names = append(names, deps.ToolNames...)
		}
		sort.Strings(names)
		writeJSON(w, http.StatusOK, map[string]any{"tools": names})
	}
}
