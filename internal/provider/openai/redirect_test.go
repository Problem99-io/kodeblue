package openai

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// A gateway key must never follow a redirect to another host: the request
// carries the key (possibly under a custom header the standard library does
// not strip) and, for chat requests, the whole conversation.
func TestClientRefusesCrossHostRedirect(t *testing.T) {
	var foreignHits atomic.Int32
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		foreignHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer foreign.Close()

	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, foreign.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer gateway.Close()

	c := NewClientWithAdvancedOptions("secret-key", "m", ClientOptions{
		BaseURL:        gateway.URL,
		ModelsPath:     "/v1/models",
		AuthHeaderName: "X-Api-Key",
	})
	_, err := c.getModelsResponse(context.Background())
	if err == nil || !strings.Contains(err.Error(), "refusing redirect") {
		t.Fatalf("err = %v, want refused redirect", err)
	}
	if n := foreignHits.Load(); n != 0 {
		t.Fatalf("foreign host received %d request(s)", n)
	}
}

func TestClientFollowsSameOriginRedirect(t *testing.T) {
	var gotKey string
	mux := http.NewServeMux()
	mux.HandleFunc("/old/models", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/v1/models", http.StatusTemporaryRedirect)
	})
	mux.HandleFunc("/v1/models", func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"m"}]}`))
	})
	gateway := httptest.NewServer(mux)
	defer gateway.Close()

	c := NewClientWithAdvancedOptions("secret-key", "m", ClientOptions{
		BaseURL:    gateway.URL,
		ModelsPath: "/old/models",
	})
	out, err := c.getModelsResponse(context.Background())
	if err != nil {
		t.Fatalf("same-origin redirect: %v", err)
	}
	if out == nil || len(out.Data) != 1 {
		t.Fatalf("models = %+v", out)
	}
	if gotKey != "Bearer secret-key" {
		t.Fatalf("auth header after redirect = %q", gotKey)
	}
}
