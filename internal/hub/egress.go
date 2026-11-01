package hub

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

// The hub itself calls model endpoints (the connection test and the model
// catalog) at URLs operators type in. Those requests must not become a way
// into the hub's own host or its cloud metadata service, so the hub refuses
// to connect to loopback, link-local (169.254.0.0/16 holds the metadata
// service of every major cloud), unspecified and multicast addresses and
// the known metadata addresses, whatever a name resolves to. Private LAN
// ranges stay allowed: self-hosted model gateways live there.
// --endpoint-allow lists addresses that are allowed anyway.

// blockedEndpointPrefixes are refused beyond what netip classifies.
var blockedEndpointPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),          // "this network": 0.0.0.0 reaches the host itself
	netip.MustParsePrefix("fd00:ec2::254/128"),  // AWS metadata over IPv6
	netip.MustParsePrefix("100.100.100.200/32"), // Alibaba Cloud metadata
}

// nat64 is the well-known NAT64 prefix; the IPv4 address inside is checked.
var nat64 = netip.MustParsePrefix("64:ff9b::/96")

// endpointAddrErr says why the hub will not connect to a, or nil.
func endpointAddrErr(a netip.Addr, allow []netip.Prefix) error {
	a = a.Unmap()
	if inPrefixes(a, allow) {
		return nil
	}
	if nat64.Contains(a) {
		b := a.As16()
		if err := endpointAddrErr(netip.AddrFrom4([4]byte(b[12:])), allow); err != nil {
			return err
		}
	}
	what := ""
	switch {
	case a.IsLoopback():
		what = "loopback"
	case a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast():
		what = "link-local (cloud metadata)"
	case a.IsUnspecified(), a.IsMulticast(), a.IsInterfaceLocalMulticast():
		what = "unspecified or multicast"
	case inPrefixes(a, blockedEndpointPrefixes):
		what = "reserved (cloud metadata)"
	default:
		return nil
	}
	return fmt.Errorf("the hub does not connect to the %s address %s (list it in --endpoint-allow if this endpoint is meant to be there)", what, a)
}

// errRedirect refuses a redirect that leaves the endpoint.
var errRedirect = errors.New("the endpoint redirected to another host; use the final URL as the base URL")

// endpointClient is the HTTP client for model endpoints: bounded in time,
// direct (no proxy from the environment, which would bypass the address
// check), following redirects only within the same scheme and host, and
// connecting only to addresses endpointAddrErr allows.
func endpointClient(allow []netip.Prefix) *http.Client {
	return &http.Client{Transport: endpointTransport(allow, 15*time.Second), Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("the endpoint redirected too many times")
			}
			if req.URL.Scheme != via[0].URL.Scheme || req.URL.Host != via[0].URL.Host {
				return errRedirect
			}
			return nil
		}}
}

// proxyClient is the model proxy's client: the same guarded connections,
// but no overall time limit (the request's context bounds a streamed
// answer), a model's time to its first byte, and no redirects at all, which
// would replay a server's request somewhere else.
func proxyClient(allow []netip.Prefix) *http.Client {
	return &http.Client{Transport: endpointTransport(allow, 10*time.Minute),
		CheckRedirect: func(*http.Request, []*http.Request) error { return errRedirect }}
}

func endpointTransport(allow []netip.Prefix, headerTimeout time.Duration) *http.Transport {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second,
		// Control sees the resolved address of every connection attempt, so
		// a name that resolves (or rebinds) to a refused address fails too.
		Control: func(network, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil {
				return fmt.Errorf("unexpected address %q", address)
			}
			return endpointAddrErr(ap.Addr(), allow)
		}}
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          16,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: headerTimeout,
		ExpectContinueTimeout: time.Second,
	}
}
