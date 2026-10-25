package api

import (
	"net/http"

	"github.com/Problem99-io/kodeblue/internal/buildinfo"
)

func handleHealth(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":  "ok",
			"version": buildinfo.Version,
		})
	}
}

func handleBuildInfo(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, buildinfo.Current())
	}
}
