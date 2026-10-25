package secrets

import (
	"os"
	"strings"
	"testing"
)

func reset(t *testing.T) {
	t.Helper()
	mu.Lock()
	store = map[string]string{}
	mu.Unlock()
}

func TestSetGetAndClear(t *testing.T) {
	reset(t)

	if got := Get(GatewayAPIKey); got != "" {
		t.Fatalf("expected empty slot, got %q", got)
	}
	if Has(GatewayAPIKey) {
		t.Fatal("Has reported a secret that was never set")
	}

	Set(GatewayAPIKey, "im-key")
	if got := Get(GatewayAPIKey); got != "im-key" {
		t.Errorf("Get = %q, want %q", got, "im-key")
	}
	if !Has(GatewayAPIKey) {
		t.Error("Has = false after Set")
	}

	// An empty value clears the slot, so callers can pass "unset" straight
	// through without branching.
	Set(GatewayAPIKey, "")
	if got := Get(GatewayAPIKey); got != "" {
		t.Errorf("Get after clearing = %q, want empty", got)
	}
}

func TestLoadFromReader(t *testing.T) {
	reset(t)

	payload := `{"gateway":"im-key","gateway:alt":"alt-key","server":"session-key"}`
	if err := LoadFromReader(strings.NewReader(payload)); err != nil {
		t.Fatalf("LoadFromReader: %v", err)
	}

	for name, want := range map[string]string{
		GatewayAPIKey:             "im-key",
		NamedGatewayAPIKey("alt"): "alt-key",
		ServerAPIKey:              "session-key",
	} {
		if got := Get(name); got != want {
			t.Errorf("Get(%q) = %q, want %q", name, got, want)
		}
	}
}

// The supervisor sends "" for a credential the operator has not configured;
// that must land as an unset slot, not as an empty-string "key" that would make
// a provider look configured.
func TestLoadFromReaderTreatsEmptyValuesAsUnset(t *testing.T) {
	reset(t)

	if err := LoadFromReader(strings.NewReader(`{"gateway":"im-key","server":""}`)); err != nil {
		t.Fatalf("LoadFromReader: %v", err)
	}
	if !Has(GatewayAPIKey) {
		t.Error("gateway should be set")
	}
	if Has(ServerAPIKey) {
		t.Error("server was empty and must stay unset")
	}
}

// A supervisor with nothing to hand over writes an empty payload; that is a
// normal startup, not a failure.
func TestLoadFromReaderAcceptsEmptyPayload(t *testing.T) {
	reset(t)

	for _, payload := range []string{"", "   ", "\n"} {
		if err := LoadFromReader(strings.NewReader(payload)); err != nil {
			t.Errorf("LoadFromReader(%q) = %v, want nil", payload, err)
		}
	}
}

func TestLoadFromReaderRejectsMalformedPayload(t *testing.T) {
	reset(t)

	if err := LoadFromReader(strings.NewReader("not json")); err == nil {
		t.Fatal("expected an error for a malformed payload")
	}
}

// Unknown keys are ignored so the backend can start sending a new credential
// before the engine has a slot name for it.
func TestLoadFromReaderIgnoresUnknownKeys(t *testing.T) {
	reset(t)

	if err := LoadFromReader(strings.NewReader(`{"future_provider":"x","gateway":"im"}`)); err != nil {
		t.Fatalf("LoadFromReader: %v", err)
	}
	if got := Get(GatewayAPIKey); got != "im" {
		t.Errorf("known key lost: got %q", got)
	}
}

// The production path: the payload arrives on an inherited descriptor and the
// descriptor is consumed to EOF and closed.
func TestLoadFromFD(t *testing.T) {
	reset(t)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	go func() {
		_, _ = w.WriteString(`{"gateway":"piped-key"}`)
		_ = w.Close()
	}()

	if err := LoadFromFD(int(r.Fd())); err != nil {
		t.Fatalf("LoadFromFD: %v", err)
	}
	if got := Get(GatewayAPIKey); got != "piped-key" {
		t.Errorf("Get = %q, want %q", got, "piped-key")
	}
}

func TestLoadFromFDRejectsStdio(t *testing.T) {
	reset(t)

	for _, fd := range []int{0, 1, 2} {
		if err := LoadFromFD(fd); err == nil {
			t.Errorf("LoadFromFD(%d) succeeded; stdio must be refused", fd)
		}
	}
}
