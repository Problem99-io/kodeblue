package hub

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"

	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
)

// loopbackProxies are trusted to set X-Forwarded-For when --behind-proxy is
// on and no --trusted-proxy is given: a proxy on the same host.
var loopbackProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}

// ParsePrefixes reads a comma- or space-separated list of addresses and
// CIDRs ("203.0.113.7, 10.66.0.0/24").
func ParsePrefixes(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' }) {
		if p, err := netip.ParsePrefix(f); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(f)
		if err != nil {
			return nil, fmt.Errorf("%q is not an address or CIDR", f)
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

func inPrefixes(a netip.Addr, list []netip.Prefix) bool {
	a = a.Unmap()
	for _, p := range list {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func peerAddr(r *http.Request) netip.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

// clientAddr is the address a request came from. X-Forwarded-For counts
// only when the hub runs behind a proxy and the connection comes from a
// trusted proxy; then the rightmost address that is not itself a trusted
// proxy is the client. Anyone else's header is ignored, so a client that
// reaches the hub directly cannot pick the address the sign-in throttle,
// the console allow-list and the audit log see.
func (s *Server) clientAddr(r *http.Request) netip.Addr {
	peer := peerAddr(r)
	if !s.opt.BehindProxy || !inPrefixes(peer, s.trusted) {
		return peer
	}
	var hops []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(v, ",")...)
	}
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			return peer
		}
		if a = a.Unmap(); !inPrefixes(a, s.trusted) {
			return a
		}
	}
	return peer
}

func (s *Server) clientIP(r *http.Request) string {
	if a := s.clientAddr(r); a.IsValid() {
		return a.String()
	}
	return r.RemoteAddr
}

// agentFacing reports whether path must stay reachable for servers: the
// agent API, the installer and release files, and the health check.
func agentFacing(path string) bool {
	return strings.HasPrefix(path, hubproto.PathPrefix) || strings.HasPrefix(path, "/collect/research/") || path == "/research-tracker.js" || path == "/install.sh" || strings.HasPrefix(path, "/dist/") || path == "/healthz"
}

// consoleGate hides the console and operator API from addresses outside
// --console-allow. They get a plain 404, as if nothing were there.
func (s *Server) consoleGate(next http.Handler) http.Handler {
	if len(s.opt.ConsoleAllow) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !agentFacing(r.URL.Path) && !inPrefixes(s.clientAddr(r), s.opt.ConsoleAllow) {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}
