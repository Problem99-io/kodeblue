package hubproto

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPinnedClient(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer ts.Close()
	pin := Pin(ts.Certificate())

	good, err := HTTPClient(pin, "", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := good.Get(ts.URL); err != nil {
		t.Fatalf("pinned self-signed hub refused: %v", err)
	} else {
		resp.Body.Close()
	}

	bad, _ := HTTPClient("sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "", 5*time.Second)
	if _, err := bad.Get(ts.URL); err == nil {
		t.Fatal("wrong pin accepted")
	}
	plain, _ := HTTPClient("", "", 5*time.Second)
	if _, err := plain.Get(ts.URL); err == nil {
		t.Fatal("self-signed certificate accepted without a pin")
	}
	if _, err := HTTPClient("md5//x", "", time.Second); err == nil {
		t.Fatal("malformed pin accepted")
	}
}

func TestCheckURL(t *testing.T) {
	for raw, ok := range map[string]bool{
		"https://hub.example.com":  true,
		"http://127.0.0.1:8080":    true,
		"http://localhost:8080":    true,
		"http://hub.example.com":   false,
		"ftp://hub.example.com":    false,
		"hub.example.com":          false,
		"https://hub.example.com/": true,
	} {
		if _, err := CheckURL(raw); (err == nil) != ok {
			t.Errorf("CheckURL(%q) err=%v, want ok=%v", raw, err, ok)
		}
	}
}

// A redirect, above all one to plain HTTP, is never followed: the request
// carries the server's credential.
func TestClientRefusesRedirects(t *testing.T) {
	var leaked bool
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Get("Authorization") != ""
	}))
	defer plain.Close()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer ts.Close()

	c, err := HTTPClient(Pin(ts.Certificate()), "", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, ts.URL+PathSync, strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer kbk_secret")
	resp, err := c.Do(req)
	if err == nil {
		resp.Body.Close()
		t.Fatal("redirect followed")
	}
	if !strings.Contains(err.Error(), "does not follow redirects") {
		t.Fatalf("unexpected error: %v", err)
	}
	if leaked {
		t.Fatal("credential sent over plain HTTP")
	}
}
