package main

import (
	"testing"

	"github.com/Problem99-io/kodeblue/internal/hub"
)

// server add pins what serve last served: nothing before the hub has run,
// and no pin once it serves --tls-cert or --behind-proxy, whatever
// self-signed certificate is still in <data>/tls.
func TestServedPin(t *testing.T) {
	st, err := hub.OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, ok := servedPin(st); ok {
		t.Fatal("a hub that never ran has no served pin")
	}
	if err := recordServedPin(st, "sha256//abc="); err != nil {
		t.Fatal(err)
	}
	if pin, ok := servedPin(st); !ok || pin != "sha256//abc=" {
		t.Fatalf("self-signed: got %q %v", pin, ok)
	}
	if err := recordServedPin(st, ""); err != nil {
		t.Fatal(err)
	}
	if pin, ok := servedPin(st); !ok || pin != "" {
		t.Fatalf("moved off self-signed: got %q %v, want no pin", pin, ok)
	}
}
