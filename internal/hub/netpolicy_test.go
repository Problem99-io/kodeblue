package hub

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
)

func netServer(t *testing.T, opt Options) *Server {
	t.Helper()
	st, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return NewServer(opt, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func mustPrefixes(t *testing.T, s string) Options {
	t.Helper()
	p, err := ParsePrefixes(s)
	if err != nil {
		t.Fatal(err)
	}
	return Options{ConsoleAllow: p}
}

func TestClientIP(t *testing.T) {
	trusted, _ := ParsePrefixes("10.0.0.2, 10.0.1.0/24")
	cases := []struct {
		name   string
		opt    Options
		remote string
		xff    []string
		want   string
	}{
		{"direct, header ignored", Options{}, "198.51.100.4:5000", []string{"203.0.113.9"}, "198.51.100.4"},
		{"proxy on loopback", Options{BehindProxy: true}, "127.0.0.1:5000", []string{"203.0.113.9"}, "203.0.113.9"},
		{"spoofed client appends to the chain", Options{BehindProxy: true}, "127.0.0.1:5000", []string{"1.2.3.4, 203.0.113.9"}, "203.0.113.9"},
		{"untrusted peer cannot pick its address", Options{BehindProxy: true}, "198.51.100.4:5000", []string{"10.66.0.5"}, "198.51.100.4"},
		{"chain of trusted proxies", Options{BehindProxy: true, TrustedProxies: trusted}, "10.0.0.2:5000", []string{"203.0.113.9, 10.0.1.7"}, "203.0.113.9"},
		{"several headers", Options{BehindProxy: true, TrustedProxies: trusted}, "10.0.0.2:5000", []string{"192.0.2.1", "203.0.113.9"}, "203.0.113.9"},
		{"garbage hop", Options{BehindProxy: true}, "127.0.0.1:5000", []string{"nonsense"}, "127.0.0.1"},
		{"mapped v4", Options{BehindProxy: true}, "[::ffff:127.0.0.1]:5000", []string{"203.0.113.9"}, "203.0.113.9"},
	}
	for _, c := range cases {
		s := netServer(t, c.opt)
		r := httptest.NewRequest("GET", "/api/me", nil)
		r.RemoteAddr = c.remote
		for _, v := range c.xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		if got := s.clientIP(r); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

func TestConsoleAllow(t *testing.T) {
	s := netServer(t, mustPrefixes(t, "10.66.0.0/24 203.0.113.7"))
	h := s.Handler()
	get := func(path, remote string) int {
		r := httptest.NewRequest("GET", path, nil)
		r.RemoteAddr = remote
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	for _, p := range []string{"/", "/assets/app.js", "/api/me", "/api/fleet"} {
		if code := get(p, "198.51.100.4:5000"); code != http.StatusNotFound {
			t.Errorf("%s from outside: %d", p, code)
		}
	}
	if code := get("/", "10.66.0.9:5000"); code != http.StatusOK {
		t.Errorf("console from the allowed range: %d", code)
	}
	if code := get("/", "203.0.113.7:5000"); code != http.StatusOK {
		t.Errorf("console from the allowed address: %d", code)
	}
	// Servers keep working from anywhere.
	if code := get("/healthz", "198.51.100.4:5000"); code != http.StatusOK {
		t.Errorf("healthz: %d", code)
	}
	// (No dist dir here, so the installer itself is a 404 for everyone.)
	if out, in := get("/install.sh", "198.51.100.4:5000"), get("/install.sh", "10.66.0.9:5000"); out != in {
		t.Errorf("install.sh: %d from outside, %d inside", out, in)
	}
	if code := get(hubproto.PathMessages, "198.51.100.4:5000"); code != http.StatusUnauthorized {
		t.Errorf("agent API without a key: %d (want 401, not hidden)", code)
	}
	if _, err := ParsePrefixes("10.0.0.0/33"); err == nil {
		t.Error("bad CIDR accepted")
	}
}
