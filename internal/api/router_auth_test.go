package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Problem99-io/kodeblue/internal/buildinfo"
)

// The per-instance API key (minted by the supervising process and passed via
// -api-key) must gate every route except the /v1/health liveness probe, and be
// accepted as a Bearer token, an X-API-Key header, or an api_key query param
// (the header-less WebSocket/SSE path).
func TestRouterAPIKeyEnforcement(t *testing.T) {
	deps, _ := setupTestDeps(t)
	deps.APIKey = "test-instance-key"
	router := NewRouter(deps)

	do := func(t *testing.T, path string, decorate func(*http.Request)) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if decorate != nil {
			decorate(req)
		}
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}

	if rec := do(t, "/v1/health", nil); rec.Code != http.StatusOK {
		t.Errorf("health without key: got %d, want %d", rec.Code, http.StatusOK)
	}
	if rec := do(t, "/v1/sessions", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("sessions without key: got %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if rec := do(t, "/v1/sessions", func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer wrong-key")
	}); rec.Code != http.StatusUnauthorized {
		t.Errorf("sessions with wrong bearer key: got %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if rec := do(t, "/v1/sessions", func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer test-instance-key")
	}); rec.Code != http.StatusOK {
		t.Errorf("sessions with bearer key: got %d, want %d", rec.Code, http.StatusOK)
	}
	if rec := do(t, "/v1/sessions", func(r *http.Request) {
		r.Header.Set("X-API-Key", "test-instance-key")
	}); rec.Code != http.StatusOK {
		t.Errorf("sessions with X-API-Key: got %d, want %d", rec.Code, http.StatusOK)
	}
	if rec := do(t, "/v1/sessions?api_key=test-instance-key", nil); rec.Code != http.StatusOK {
		t.Errorf("sessions with api_key query param: got %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestBuildInfoRequiresInstanceKeyAndReturnsObservedIdentity(t *testing.T) {
	deps, _ := setupTestDeps(t)
	deps.APIKey = "test-instance-key"
	router := NewRouter(deps)

	unauthorized := httptest.NewRecorder()
	router.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/v1/build-info", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("build-info without key: got %d, want %d", unauthorized.Code, http.StatusUnauthorized)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/build-info", nil)
	req.Header.Set("Authorization", "Bearer test-instance-key")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("build-info with key: got %d: %s", rec.Code, rec.Body.String())
	}
	var got buildinfo.Info
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	want := buildinfo.Current()
	if got != want {
		t.Fatalf("build-info = %#v, want %#v", got, want)
	}
}

// Without a configured key (dev/CLI runs), the router must stay open so
// existing local workflows keep working.
func TestRouterNoAPIKeyStaysOpen(t *testing.T) {
	deps, _ := setupTestDeps(t)
	router := NewRouter(deps)

	req := httptest.NewRequest(http.MethodGet, "/v1/sessions", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("sessions without configured key: got %d, want %d", rec.Code, http.StatusOK)
	}
}
