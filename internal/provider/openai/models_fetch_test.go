package openai

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// shortenModelsTimeouts makes catalog fetches give up and retry quickly:
// fetch bounds a request, fail is the retry delay after a timeout and quick
// the one after a fast failure.
func shortenModelsTimeouts(t *testing.T, fetch, fail, quick time.Duration) {
	t.Helper()
	oldFetch, oldFail, oldQuick := modelsFetchTimeout, modelsFailTTL, modelsQuickFailTTL
	modelsFetchTimeout, modelsFailTTL, modelsQuickFailTTL = fetch, fail, quick
	t.Cleanup(func() { modelsFetchTimeout, modelsFailTTL, modelsQuickFailTTL = oldFetch, oldFail, oldQuick })
}

// hangingModelsServer never answers /v1/models until the request is abandoned.
func hangingModelsServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(func() { close(release); server.Close() })
	return server, &hits
}

func catalogClient(baseURL string) *Client {
	return NewClientWithAdvancedOptions("test-key", "MiniMax-M3", ClientOptions{
		Name:       "minimax",
		BaseURL:    baseURL,
		ModelsPath: "/v1/models?provider=minimax",
	})
}

// A hanging catalog used to be fetched under the cache mutex with no
// deadline, so every run start and compaction queued behind it for up to the
// two-minute header timeout, whatever their own context said.
func TestModelsHangingCatalogRespectsCallerContext(t *testing.T) {
	shortenModelsTimeouts(t, 500*time.Millisecond, time.Minute, time.Minute)
	server, _ := hangingModelsServer(t)
	client := catalogClient(server.URL)

	// One caller is already stuck on the catalog.
	stuck := make(chan struct{})
	go func() {
		defer close(stuck)
		_, _ = client.getModelsResponse(context.Background())
	}()
	defer func() { <-stuck }() // let the fetch end before the timeouts are restored
	time.Sleep(50 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, ok := client.ReportedContextWindow(ctx, "MiniMax-M3"); ok {
		t.Fatal("hanging catalog reported a window")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("caller with a 100ms deadline waited %s", elapsed)
	}
}

// Concurrent callers share one request, it is bounded by modelsFetchTimeout,
// and its timeout is remembered for modelsFailTTL (not the short
// modelsQuickFailTTL, which is set to 1ms here).
func TestModelsHangingCatalogSingleFlightTimeoutAndNegativeCache(t *testing.T) {
	shortenModelsTimeouts(t, 200*time.Millisecond, 400*time.Millisecond, time.Millisecond)
	server, hits := hangingModelsServer(t)
	client := catalogClient(server.URL)

	start := time.Now()
	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = client.getModelsResponse(context.Background())
		}(i)
	}
	wg.Wait()
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("hanging catalog held callers for %s, want about modelsFetchTimeout", elapsed)
	}
	for i, err := range errs {
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("caller %d: err = %v, want deadline exceeded", i, err)
		}
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("catalog requested %d times by concurrent callers, want 1", n)
	}

	// Within modelsFailTTL the failure is answered from memory.
	start = time.Now()
	if _, err := client.getModelsResponse(context.Background()); err == nil {
		t.Fatal("negative cache returned no error")
	}
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Fatalf("negatively cached failure took %s", elapsed)
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("catalog re-requested inside modelsFailTTL (%d requests)", n)
	}

	// After it, the catalog is tried again.
	time.Sleep(450 * time.Millisecond)
	_, _ = client.getModelsResponse(context.Background())
	if n := hits.Load(); n != 2 {
		t.Fatalf("catalog requests after modelsFailTTL = %d, want 2", n)
	}
}

// A failing refresh keeps serving the last good catalog rather than dropping
// to the built-in context-window guess.
func TestModelsFailedRefreshServesStaleCatalog(t *testing.T) {
	shortenModelsTimeouts(t, time.Second, time.Minute, time.Minute)
	var fail atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			http.Error(w, "upstream down", http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(`{"data":[{"id":"MiniMax-M3","context_window":250000}]}`))
	}))
	defer server.Close()
	client := catalogClient(server.URL)

	if w, ok := client.ReportedContextWindow(context.Background(), "MiniMax-M3"); !ok || w != 250_000 {
		t.Fatalf("first read = (%d, %v)", w, ok)
	}
	fail.Store(true)
	client.modelsMu.Lock()
	client.modelsAt = time.Now().Add(-2 * modelsTTL)
	client.modelsMu.Unlock()

	for i := 0; i < 2; i++ { // starts the refresh, then while it fails
		if w, ok := client.ReportedContextWindow(context.Background(), "MiniMax-M3"); !ok || w != 250_000 {
			t.Fatalf("read %d with failing catalog = (%d, %v), want stale (250000, true)", i, w, ok)
		}
		waitModelsFetch(t, client)
	}
}

// waitModelsFetch waits until no catalog fetch is in flight.
func waitModelsFetch(t *testing.T, c *Client) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		c.modelsMu.Lock()
		idle := c.modelsCall == nil
		c.modelsMu.Unlock()
		if idle {
			return
		}
	}
	t.Fatal("catalog fetch still in flight")
}

// expireCatalog makes the cached catalog stale without dropping it.
func expireCatalog(c *Client) {
	c.modelsMu.Lock()
	c.modelsAt = time.Now().Add(-2 * modelsTTL)
	c.modelsMu.Unlock()
}

// With a stale catalog in hand a caller never waits on a refresh, however
// slow: it gets the stale catalog at once while one background fetch runs.
func TestModelsStaleCatalogServedWithoutWaitingOnRefresh(t *testing.T) {
	shortenModelsTimeouts(t, 300*time.Millisecond, time.Minute, time.Minute)
	var hang atomic.Bool
	var hits atomic.Int32
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if hang.Load() {
			select {
			case <-r.Context().Done():
			case <-release:
			}
			return
		}
		_, _ = w.Write([]byte(`{"data":[{"id":"MiniMax-M3","context_length":12345}]}`))
	}))
	defer server.Close()
	defer close(release)
	client := catalogClient(server.URL)
	if w, ok := client.ReportedContextWindow(context.Background(), "MiniMax-M3"); !ok || w != 12345 {
		t.Fatalf("prime = (%d, %v)", w, ok)
	}
	hang.Store(true)
	expireCatalog(client)

	for i := 0; i < 5; i++ {
		start := time.Now()
		w, ok := client.ReportedContextWindow(context.Background(), "MiniMax-M3")
		if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
			t.Fatalf("call %d waited %s on a hanging refresh with a stale catalog in hand", i, elapsed)
		}
		if !ok || w != 12345 {
			t.Fatalf("call %d = (%d, %v), want stale (12345, true)", i, w, ok)
		}
		time.Sleep(100 * time.Millisecond)
	}
	// One refresh for all of them: it timed out, and the timeout is remembered.
	if n := hits.Load(); n != 2 {
		t.Fatalf("catalog requested %d times, want 2 (prime + one refresh)", n)
	}

	// Once the gateway answers again, a refresh picks up the new value.
	hang.Store(false)
	client.modelsMu.Lock()
	client.modelsRest = time.Time{}
	client.modelsMu.Unlock()
	_, _ = client.getModelsResponse(context.Background()) // stale answer, starts the refresh
	deadline := time.Now().Add(2 * time.Second)
	for {
		client.modelsMu.Lock()
		fresh := time.Since(client.modelsAt) < modelsTTL
		client.modelsMu.Unlock()
		if fresh {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("background refresh never stored the recovered catalog")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A fast failure (one 502) is retried after modelsQuickFailTTL, not the long
// modelsFailTTL: a run reads its context window only at start, so a long
// negative cache would leave every run in that window on the built-in guess.
func TestModelsQuickFailureRetriedSoon(t *testing.T) {
	shortenModelsTimeouts(t, time.Second, time.Minute, 200*time.Millisecond)
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 {
			http.Error(w, "bad gateway", http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(`{"data":[{"id":"MiniMax-M3","context_length":777}]}`))
	}))
	defer server.Close()
	client := catalogClient(server.URL)

	if _, ok := client.ReportedContextWindow(context.Background(), "MiniMax-M3"); ok {
		t.Fatal("first read succeeded against a 502")
	}
	if _, ok := client.ReportedContextWindow(context.Background(), "MiniMax-M3"); ok || hits.Load() != 1 {
		t.Fatalf("read inside modelsQuickFailTTL: ok=%v requests=%d, want cached failure and 1 request", ok, hits.Load())
	}
	time.Sleep(250 * time.Millisecond)
	if w, ok := client.ReportedContextWindow(context.Background(), "MiniMax-M3"); !ok || w != 777 {
		t.Fatalf("read after modelsQuickFailTTL = (%d, %v), want (777, true)", w, ok)
	}
}

// One caller giving up does not abort the fetch another caller shares.
func TestModelsCallerCancelDoesNotAbortSharedFetch(t *testing.T) {
	shortenModelsTimeouts(t, 2*time.Second, time.Minute, time.Minute)
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		time.Sleep(300 * time.Millisecond)
		_, _ = w.Write([]byte(`{"data":[{"id":"MiniMax-M3","context_length":777}]}`))
	}))
	defer server.Close()
	client := catalogClient(server.URL)

	ctxA, cancelA := context.WithCancel(context.Background())
	errA := make(chan error, 1)
	go func() { _, err := client.getModelsResponse(ctxA); errA <- err }()
	time.Sleep(50 * time.Millisecond)
	windowB := make(chan int64, 1)
	go func() { w, _ := client.ReportedContextWindow(context.Background(), "MiniMax-M3"); windowB <- w }()
	time.Sleep(50 * time.Millisecond)
	cancelA()

	if err := <-errA; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled caller err = %v, want context.Canceled", err)
	}
	if w := <-windowB; w != 777 {
		t.Fatalf("other caller window = %d, want 777", w)
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("catalog requested %d times, want 1 shared fetch", n)
	}
}
