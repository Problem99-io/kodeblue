// Package research is the model-free evidence and analytics foundation. It has
// no dependency on agent execution, incident ownership or containment.
package research

import (
	"errors"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"
)

var (
	ErrInvalid  = errors.New("invalid research observation")
	ErrCapacity = errors.New("research storage capacity reached")
	ErrScope    = errors.New("research source is not authorized for this site")
	idPattern   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,96}$`)
	longValue   = regexp.MustCompile(`(?i)[a-f0-9]{24,}|[0-9]{7,}|[A-Za-z0-9_-]{40,}`)
)

// Limits bound persisted records and physical database/journal growth. The
// defaults are prototype limits, not a claim of production throughput.
type Limits struct {
	MaxBytes      int64
	MaxEvents     int
	MaxSiteEvents int
	MaxBuckets    int
	DetailTTL     time.Duration
	SummaryTTL    time.Duration
}

func DefaultLimits() Limits {
	return Limits{MaxBytes: 256 << 20, MaxEvents: 50000, MaxSiteEvents: 10000,
		MaxBuckets: 20000, DetailTTL: 72 * time.Hour, SummaryTTL: 30 * 24 * time.Hour}
}

type Site struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Origins        []string `json:"origins"`
	Servers        []string `json:"servers"`
	Timezone       string   `json:"timezone"`
	BrowserEnabled bool     `json:"browser_enabled"`
	BrowserPaths   []string `json:"browser_paths"`
}

// Fingerprints are producer observations, never universal actor identifiers.
type Fingerprint struct {
	Algorithm    string `json:"algorithm"`
	Version      string `json:"version"`
	Value        string `json:"value"`
	CapturePoint string `json:"capture_point"`
}

type Event struct {
	ID            string       `json:"id"`
	At            time.Time    `json:"at"`
	Kind          string       `json:"kind"`
	Path          string       `json:"path,omitempty"`
	Name          string       `json:"name,omitempty"`
	Method        string       `json:"method,omitempty"`
	Status        int          `json:"status,omitempty"`
	PeerIP        string       `json:"peer_ip,omitempty"`
	DestinationIP string       `json:"destination_ip,omitempty"`
	Fingerprint   *Fingerprint `json:"fingerprint,omitempty"`
	Value         float64      `json:"value,omitempty"`
}

type Observation struct {
	Sequence   int64     `json:"sequence"`
	Site       string    `json:"site"`
	Source     string    `json:"source"`
	Provenance string    `json:"provenance"`
	ObservedAt time.Time `json:"observed_at"`
	Event      Event     `json:"event"`
}

var eventNames = map[string]bool{
	"contact_click": true, "booking_intent": true, "navigation": true,
	"service_interest": true, "gallery_interaction": true, "scroll_25": true,
	"scroll_50": true, "scroll_75": true, "scroll_100": true,
	"active_30": true, "active_60": true, "active_120": true,
	"lcp": true, "inp": true, "cls": true, "fcp": true, "ttfb": true,
}

func clean(s string, n int) string {
	var out []rune
	for _, c := range s {
		if unicode.IsControl(c) || unicode.Is(unicode.Cf, c) || c == 0x2028 || c == 0x2029 {
			continue
		}
		out = append(out, c)
		if len(out) == n {
			break
		}
	}
	return string(out)
}

// NormalizePath removes query/hash values and common path-embedded secrets.
// Original request targets must never be stored alongside the sanitized path.
func NormalizePath(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	if len(raw) > 2048 || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") {
		return "", ErrInvalid
	}
	raw, _, _ = strings.Cut(raw, "#")
	u, err := url.ParseRequestURI(raw)
	if err != nil || u.Host != "" || u.Scheme != "" {
		return "", ErrInvalid
	}
	parts := strings.Split(clean(u.Path, 2048), "/")
	hide := false
	for i, p := range parts {
		lower := strings.ToLower(p)
		if hide || strings.Contains(p, "@") || longValue.MatchString(p) {
			parts[i] = ":redacted"
		}
		hide = lower == "token" || lower == "secret" || lower == "password" || lower == "reset" || lower == "invite" || lower == "auth" || lower == "users" || lower == "user" || lower == "accounts" || lower == "email" || lower == "apikey" || lower == "api_key" || lower == "session"
	}
	return clean(strings.Join(parts, "/"), 256), nil
}

func validate(e Event, browser bool, now time.Time, ttl time.Duration) (Event, error) {
	if !idPattern.MatchString(e.ID) || e.At.IsZero() || e.At.After(now.Add(5*time.Minute)) || e.At.Before(now.Add(-ttl)) {
		return e, ErrInvalid
	}
	if browser {
		if e.Kind != "pageview" && e.Kind != "interaction" && e.Kind != "performance" {
			return e, ErrInvalid
		}
		if e.PeerIP != "" || e.DestinationIP != "" || e.Fingerprint != nil || e.Method != "" || e.Status != 0 {
			return e, ErrInvalid
		}
	} else if e.Kind != "request" && e.Kind != "connection" && e.Kind != "artifact" {
		return e, ErrInvalid
	}
	if e.Kind == "interaction" || e.Kind == "performance" {
		if !eventNames[e.Name] {
			return e, ErrInvalid
		}
	} else if e.Name != "" {
		return e, ErrInvalid
	}
	performance := e.Name == "lcp" || e.Name == "inp" || e.Name == "cls" || e.Name == "fcp" || e.Name == "ttfb"
	if e.Kind == "performance" && !performance || e.Kind == "interaction" && performance || e.Kind != "performance" && e.Value != 0 || e.Name == "cls" && e.Value > 100 {
		return e, ErrInvalid
	}
	if e.Value < 0 || e.Value > 60000 || e.Value != e.Value {
		return e, ErrInvalid
	}
	var err error
	if e.Path, err = NormalizePath(e.Path); err != nil {
		return e, err
	}
	if e.Status != 0 && (e.Status < 100 || e.Status > 599) {
		return e, ErrInvalid
	}
	if e.Method != "" && e.Method != "GET" && e.Method != "POST" && e.Method != "PUT" && e.Method != "DELETE" && e.Method != "PATCH" && e.Method != "HEAD" && e.Method != "OPTIONS" && e.Method != "CONNECT" && e.Method != "TRACE" {
		return e, ErrInvalid
	}
	for _, p := range []*string{&e.PeerIP, &e.DestinationIP} {
		if *p == "" {
			continue
		}
		ip, x := netip.ParseAddr(*p)
		if x != nil || ip.Zone() != "" {
			return e, ErrInvalid
		}
		*p = ip.Unmap().String()
	}
	if e.Kind == "connection" && (e.PeerIP == "" || e.DestinationIP == "") {
		return e, ErrInvalid
	}
	if f := e.Fingerprint; f != nil {
		if (f.Algorithm != "ja3" && f.Algorithm != "ja4" && f.Algorithm != "http_sequence") || !idPattern.MatchString(f.Version) || !idPattern.MatchString(f.Value) || !idPattern.MatchString(f.CapturePoint) {
			return e, ErrInvalid
		}
	}
	e.At = e.At.UTC()
	return e, nil
}

func category(path string) string {
	p := strings.ToLower(path)
	for _, s := range []string{"/.env", "/.git", "/wp-config", "/phpunit", "/etc/passwd"} {
		if strings.Contains(p, s) {
			return "sensitive"
		}
	}
	if strings.Contains(p, "/login") || strings.Contains(p, "/auth") {
		return "auth"
	}
	if strings.HasPrefix(p, "/api/") {
		return "api"
	}
	return "other"
}
