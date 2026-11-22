package hublink

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/config"
	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
)

// ModelForwarder hands this server's model clients (triage and the agent
// engine) the hub's model proxy on loopback. They authenticate with a token
// that lives as long as the daemon; the forwarder adds the server's hub key
// and the hub adds the connection's key, so neither key reaches the engine
// and no provider key is on the server at all.
type ModelForwarder struct {
	URL   string
	Token string
}

// StartModelForwarder listens on 127.0.0.1 until ctx ends.
func StartModelForwarder(ctx context.Context, cfg config.Config, logger *slog.Logger) (*ModelForwarder, error) {
	if logger == nil {
		logger = slog.Default()
	}
	u, err := hubproto.CheckURL(cfg.Hub.URL)
	if err != nil {
		return nil, err
	}
	key, err := cfg.Hub.APIKey()
	if err != nil {
		return nil, err
	}
	// No overall time limit: the caller's request bounds a streamed answer.
	client, err := hubproto.HTTPClient(cfg.Hub.Pin, cfg.Hub.CAFile, 0)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	f := &ModelForwarder{URL: "http://" + ln.Addr().String(), Token: hex.EncodeToString(b)}
	srv := &http.Server{Handler: f.handler(u.String(), key, client, logger), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	go func() { <-ctx.Done(); _ = srv.Close() }()
	return f, nil
}

func (f *ModelForwarder) handler(base, key string, client *http.Client, logger *slog.Logger) http.Handler {
	want := []byte("Bearer " + f.Token)
	hub, _ := url.Parse(base)
	rp := &httputil.ReverseProxy{
		// The hub client's transport (pin, CA, HTTPS_PROXY). A redirect from
		// the hub reaches the caller as it is, never followed with the key.
		Transport:     client.Transport,
		FlushInterval: -1,
		Rewrite: func(pr *httputil.ProxyRequest) {
			in := pr.In
			u := *hub
			u.Path = strings.TrimRight(hub.Path, "/") + hubproto.PathModels + strings.TrimPrefix(in.URL.Path, "/")
			u.RawPath, u.RawQuery = "", in.URL.RawQuery
			pr.Out.URL, pr.Out.Host = &u, ""
			pr.Out.Header = http.Header{}
			pr.Out.Header.Set("Authorization", "Bearer "+key)
			pr.Out.Header.Set("User-Agent", "kodeblue/"+hubproto.Version)
			for _, k := range []string{"Content-Type", "Accept"} {
				if v := in.Header.Get(k); v != "" {
					pr.Out.Header.Set(k, v)
				}
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			logger.Warn("model call via the hub failed", "path", r.URL.Path, "error", err)
			http.Error(w, "the hub could not be reached", http.StatusBadGateway)
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), want) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		conn, rest, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
		if !hubproto.ValidConnectionID(conn) || !(r.Method == http.MethodPost && rest == "v1/chat/completions" || r.Method == http.MethodGet && rest == "v1/models") {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, hubproto.MaxModelRequestBytes)
		rp.ServeHTTP(w, r)
	})
}
