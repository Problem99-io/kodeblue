package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/cloudflare"
	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
)

func (s *Server) cloudflareContext(ctx context.Context, args json.RawMessage) (string, error) {
	var q cloudflare.Query
	if err := decode(args, &q); err != nil {
		return "", err
	}
	// A bounded per-server local budget survives short-lived MCP processes.
	if q.IP != "" {
		n := 0
		for _, j := range s.st.JournalSince(time.Now().Add(-time.Minute), 500) {
			if j.Action == "cloudflare.lookup" {
				n++
			}
		}
		if n >= 10 {
			return "", errors.New("Cloudflare lookup budget reached; wait a minute")
		}
		s.st.Journal("agent", "cloudflare.lookup", "read-only security context")
	}
	if s.cfg.Hub.Enabled() {
		return s.cloudflareViaHub(ctx, q)
	}
	token, err := s.cfg.Cloudflare.Token()
	if err != nil {
		return "", err
	}
	result, err := (&cloudflare.Client{Token: token}).Lookup(ctx, q, s.cfg.Cloudflare.ZoneIDs)
	if err != nil {
		return "", err
	}
	return jsonOut(result) + untrusted, nil
}

func (s *Server) cloudflareViaHub(ctx context.Context, q cloudflare.Query) (string, error) {
	u, err := hubproto.CheckURL(s.cfg.Hub.URL)
	if err != nil {
		return "", errors.New("invalid hub URL")
	}
	key, err := s.cfg.Hub.APIKey()
	if err != nil {
		return "", errors.New("could not load hub credentials")
	}
	client, err := hubproto.HTTPClient(s.cfg.Hub.Pin, s.cfg.Hub.CAFile, 35*time.Second)
	if err != nil {
		return "", errors.New("could not initialize hub connection")
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	body, _ := json.Marshal(q)
	req, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(u.String(), "/")+cloudflare.HubPath, bytes.NewReader(body))
	if err != nil {
		return "", errors.New("could not construct hub query")
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", errors.New("Cloudflare context unavailable: could not reach hub")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", errors.New("Cloudflare context unavailable: check this server's Cloudflare settings, access and lookup budget on the hub")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, (2<<20)+1))
	if err != nil || len(data) > 2<<20 {
		return "", errors.New("invalid Cloudflare hub response")
	}
	var result cloudflare.Result
	if json.Unmarshal(data, &result) != nil {
		return "", errors.New("invalid Cloudflare hub response")
	}
	return strings.ReplaceAll(jsonOut(result), key, "[redacted]") + untrusted, nil
}
