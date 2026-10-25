package api

import (
	"context"
	"net/http"
)

type providerModelsResponse struct {
	Providers []providerModelsItem `json:"providers"`
}

type providerModelsItem struct {
	Provider     string   `json:"provider"`
	DefaultModel string   `json:"default_model,omitempty"`
	Models       []string `json:"models"`
}

type defaultModeler interface {
	DefaultModel() string
}

type modelLister interface {
	Models(ctx context.Context) ([]string, error)
}

func handleListProviderModels(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if deps.Providers == nil {
			writeError(w, http.StatusServiceUnavailable, "provider registry unavailable")
			return
		}

		RefreshDynamicConfiguredProviders(deps.Providers, deps.Config, deps.Logger)

		names := deps.Providers.List()
		items := make([]providerModelsItem, 0, len(names))
		for i := range names {
			name := names[i]
			p, ok := deps.Providers.Get(name)
			if !ok || p == nil {
				continue
			}

			item := providerModelsItem{Provider: name, Models: []string{}}
			if dm, ok := p.(defaultModeler); ok {
				item.DefaultModel = dm.DefaultModel()
			}
			if ml, ok := p.(modelLister); ok {
				models, err := ml.Models(r.Context())
				if err == nil {
					item.Models = models
				}
			}
			if len(item.Models) == 0 && item.DefaultModel != "" {
				item.Models = []string{item.DefaultModel}
			}
			if item.Models == nil {
				item.Models = []string{}
			}
			items = append(items, item)
		}

		writeJSON(w, http.StatusOK, providerModelsResponse{Providers: items})
	}
}
