package hubproto

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Version is stamped at build time (-ldflags -X).
var Version = "dev"

// Pin is the public-key pin of a certificate in curl's --pinnedpubkey format:
// "sha256//" + base64(sha256(SubjectPublicKeyInfo)).
func Pin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return "sha256//" + base64.StdEncoding.EncodeToString(sum[:])
}

// CheckURL enforces https for the hub, except on loopback (tests, or a hub
// reached through an SSH tunnel).
func CheckURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(raw), "/"))
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("hub url %q is not a valid URL", raw)
	}
	if u.Scheme == "https" {
		return u, nil
	}
	if u.Scheme == "http" {
		if ip := net.ParseIP(u.Hostname()); (ip != nil && ip.IsLoopback()) || u.Hostname() == "localhost" {
			return u, nil
		}
	}
	return nil, errors.New("hub url must be https:// (plain http is only allowed to localhost)")
}

// HTTPClient builds the agent's client for the hub. With a pin, the hub's
// certificate may be self-signed: the connection is accepted only when the
// leaf's public key matches the pin. With caFile, that CA is trusted in
// addition to the system roots.
func HTTPClient(pin, caFile string, timeout time.Duration) (*http.Client, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pool, _ := x509.SystemCertPool()
		if pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates in %s", caFile)
		}
		cfg.RootCAs = pool
	}
	if pin = strings.TrimSpace(pin); pin != "" {
		if !strings.HasPrefix(pin, "sha256//") {
			return nil, errors.New(`hub pin must look like "sha256//<base64>"`)
		}
		cfg.InsecureSkipVerify = true // replaced by the pin check below
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("hub presented no certificate")
			}
			if got := Pin(cs.PeerCertificates[0]); got != pin {
				return fmt.Errorf("hub certificate pin mismatch: got %s", got)
			}
			return nil
		}
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = cfg
	tr.Proxy = http.ProxyFromEnvironment
	return &http.Client{Transport: tr, Timeout: timeout, CheckRedirect: refuseRedirect}, nil
}

// refuseRedirect stops every redirect. The hub never sends one, and
// following it could carry the server's credential to another host or over
// plain HTTP (a proxy in front of the hub answering with http://…).
func refuseRedirect(req *http.Request, via []*http.Request) error {
	return fmt.Errorf("hub answered with a redirect to %s: kodeblue does not follow redirects (check the hub URL and any proxy in front of the hub)", req.URL.Redacted())
}
