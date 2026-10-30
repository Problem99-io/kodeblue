// Package cloudflare provides bounded, read-only security analytics queries.
package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
)

const Endpoint = "https://api.cloudflare.com/client/v4/graphql"
const HubPath = "/api/agent/v1/cloudflare"

var zonePattern = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)
var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{20,512}$`)

type Query struct {
	IP     string `json:"ip"`
	ZoneID string `json:"zone_id"`
	Hours  int    `json:"hours"`
}

type Event struct {
	Action    string `json:"action"`
	Source    string `json:"source"`
	ClientIP  string `json:"clientIP"`
	ClientASN string `json:"clientAsn"`
	Country   string `json:"clientCountryName"`
	Path      string `json:"clientRequestPath"`
	Time      string `json:"datetime"`
	UserAgent string `json:"userAgent"`
	RuleID    string `json:"ruleId"`
}

type BotGroup struct {
	Count      int `json:"count"`
	Dimensions struct {
		BotScore *int   `json:"botScore"`
		Decision string `json:"botManagementDecision"`
	} `json:"dimensions"`
}

type Result struct {
	ZoneLabels map[string]string `json:"zone_labels,omitempty"`
	Configured bool              `json:"configured"`
	Zones      []string          `json:"zone_ids"`
	IP         string            `json:"ip,omitempty"`
	ZoneID     string            `json:"zone_id,omitempty"`
	Since      string            `json:"since,omitempty"`
	Until      string            `json:"until,omitempty"`
	Events     []Event           `json:"security_events,omitempty"`
	Bots       []BotGroup        `json:"bot_traffic,omitempty"`
	Truncated  bool              `json:"possibly_truncated"`
	Notes      []string          `json:"notes"`
}

func ValidToken(token string) bool { return tokenPattern.MatchString(token) }

func ValidateZones(zones []string) error {
	if len(zones) > 10 {
		return errors.New("at most 10 Cloudflare zones may be configured per server")
	}
	for _, zone := range zones {
		if !zonePattern.MatchString(zone) {
			return errors.New("Cloudflare zone IDs must be 32 hexadecimal characters")
		}
	}
	return nil
}

func Normalize(q Query, zones []string) (Query, error) {
	if err := ValidateZones(zones); err != nil {
		return q, err
	}
	if q.IP == "" {
		return q, nil
	}
	ip, err := netip.ParseAddr(q.IP)
	if err != nil || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() {
		return q, errors.New("ip must be a single IPv4 or IPv6 address")
	}
	q.IP = ip.Unmap().String()
	if q.ZoneID == "" && len(zones) == 1 {
		q.ZoneID = zones[0]
	}
	if !slices.Contains(zones, q.ZoneID) {
		return q, errors.New("choose a configured zone_id (call cloudflare_context without ip to list them)")
	}
	if q.Hours == 0 {
		q.Hours = 1
	}
	if q.Hours < 1 || q.Hours > 24 {
		return q, errors.New("hours must be between 1 and 24")
	}
	return q, nil
}

type Client struct {
	ZoneLabels map[string]string
	Token      string
	HTTP       *http.Client
}

const eventQuery = `query SecurityContext($zone: string, $filter: FirewallEventsAdaptiveFilter_InputObject) {
 viewer { zones(filter: {zoneTag: $zone}) { firewallEventsAdaptive(filter: $filter, limit: 50, orderBy: [datetime_DESC]) {
 action source clientIP clientAsn clientCountryName clientRequestPath datetime userAgent ruleId
 } } } }`

const botQuery = `query BotContext($zone: string, $filter: ZoneHttpRequestsAdaptiveGroupsFilter_InputObject) {
 viewer { zones(filter: {zoneTag: $zone}) { httpRequestsAdaptiveGroups(filter: $filter, limit: 50, orderBy: [count_DESC]) {
 count dimensions { botScore botManagementDecision }
 } } } }`

type zoneData struct {
	Events []Event    `json:"firewallEventsAdaptive"`
	Bots   []BotGroup `json:"httpRequestsAdaptiveGroups"`
}

// Lookup never accepts a provider URL or arbitrary GraphQL from the caller.
func (c *Client) Lookup(ctx context.Context, q Query, zones []string) (*Result, error) {
	if q.IP != "" && (!ValidToken(c.Token) || len(zones) == 0) {
		return nil, errors.New("Cloudflare is not configured for this server")
	}
	q, err := Normalize(q, zones)
	if err != nil {
		return nil, err
	}
	configured := ValidToken(c.Token) && len(zones) > 0
	labels := map[string]string{}
	for _, zone := range zones {
		if label := c.ZoneLabels[zone]; label != "" {
			labels[zone] = Sanitize(label, c.Token, 128)
		}
	}
	r := &Result{Configured: configured, Zones: slices.Clone(zones), ZoneLabels: labels, Notes: []string{
		"Read-only supporting evidence, not permission to block. Correlate with local findings and protected IP policy.",
		"Adaptive datasets may be sampled; event counts and empty results are not complete traffic counts or proof of safety.",
		"Bot score 0 is not computed; missing scores are unknown. Automation alone does not imply malicious activity; verified bots can be legitimate.",
	}}
	if q.IP == "" {
		return r, nil
	}
	if !configured {
		return nil, errors.New("Cloudflare is not configured for this server")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	now := time.Now().UTC()
	r.IP, r.ZoneID, r.Since, r.Until = q.IP, q.ZoneID, now.Add(-time.Duration(q.Hours)*time.Hour).Format(time.RFC3339), now.Format(time.RFC3339)
	vars := map[string]any{"zone": q.ZoneID, "filter": map[string]any{"datetime_geq": r.Since, "datetime_leq": r.Until, "clientIP": q.IP}}
	data, err := c.query(ctx, eventQuery, vars)
	if err != nil {
		return nil, err
	}
	r.Events = data.Events
	if len(r.Events) > 50 {
		r.Events = r.Events[:50]
	}
	r.Truncated = len(r.Events) == 50
	for i := range r.Events {
		e := &r.Events[i]
		// A provider response is untrusted, including returned filters.
		ip, err := netip.ParseAddr(e.ClientIP)
		if err != nil || ip.Unmap().String() != q.IP {
			return nil, errors.New("Cloudflare returned an event for a different IP")
		}
		e.Path, e.UserAgent = bound(e.Path, 256), bound(e.UserAgent, 256)
		e.Action, e.Source, e.RuleID = bound(e.Action, 64), bound(e.Source, 64), bound(e.RuleID, 128)
		e.Country, e.ClientASN, e.Time = bound(e.Country, 64), bound(e.ClientASN, 32), bound(e.Time, 64)
	}
	data, err = c.query(ctx, botQuery, vars)
	if err != nil {
		r.Notes = append(r.Notes, "Bot-score analytics unavailable: check your plan, analytics permissions and dataset availability. No bot classification inferred.")
	} else {
		r.Bots = data.Bots
		if len(r.Bots) > 50 {
			r.Bots = r.Bots[:50]
		}
		r.Truncated = r.Truncated || len(r.Bots) == 50
		for i := range r.Bots {
			b := &r.Bots[i]
			if b.Count < 0 {
				return nil, errors.New("Cloudflare returned invalid analytics")
			}
			if b.Dimensions.BotScore != nil && (*b.Dimensions.BotScore < 0 || *b.Dimensions.BotScore > 99) {
				b.Dimensions.BotScore = nil
			}
			b.Dimensions.Decision = bound(b.Dimensions.Decision, 64)
		}
	}
	return r, nil
}

func bound(s string, n int) string {
	r := []rune{}
	for _, c := range s {
		if !unicode.Is(unicode.Cf, c) && !unicode.IsControl(c) && c != 0x2028 && c != 0x2029 && !(c >= 0xfe00 && c <= 0xfe0f) && !(c >= 0xe0100 && c <= 0xe01ef) {
			r = append(r, c)
		}
	}
	if len(r) > n {
		r = r[:n]
	}
	return string(r)
}

func (c *Client) query(ctx context.Context, query string, variables map[string]any) (zoneData, error) {
	var empty zoneData
	data, _ := json.Marshal(map[string]any{"query": query, "variables": variables})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, Endpoint, bytes.NewReader(data))
	if err != nil {
		return empty, errors.New("could not construct Cloudflare query")
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{Proxy: nil}}
	if c.HTTP != nil {
		*client = *c.HTTP
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return empty, errors.New("Cloudflare request failed; check connectivity and token permissions")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return empty, &HTTPError{StatusCode: resp.StatusCode}
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, (2<<20)+1))
	if err != nil || len(raw) > 2<<20 {
		return empty, errors.New("Cloudflare response could not be read or exceeded its limit")
	}
	// Never expose the configured credential even if an upstream echoes it.
	raw, err = SanitizeJSON(raw, c.Token)
	if err != nil {
		return empty, errors.New("Cloudflare returned malformed analytics")
	}
	var result struct {
		Errors []json.RawMessage `json:"errors"`
		Data   struct {
			Viewer struct {
				Zones []zoneData `json:"zones"`
			} `json:"viewer"`
		} `json:"data"`
	}
	if json.Unmarshal(raw, &result) != nil {
		return empty, errors.New("Cloudflare returned malformed analytics")
	}
	if len(result.Errors) > 0 || len(result.Data.Viewer.Zones) != 1 {
		return empty, errors.New("Cloudflare analytics unavailable; check token permissions, zone access, retention and plan")
	}
	return result.Data.Viewer.Zones[0], nil
}

// HTTPError exposes only the status; response bodies can contain credentials.
type HTTPError struct{ StatusCode int }

func (e *HTTPError) Error() string {
	return fmt.Sprintf("Cloudflare returned HTTP %d; check analytics access, plan limits or retry later", e.StatusCode)
}
func (e *HTTPError) Retryable() bool { return e.StatusCode == 429 || e.StatusCode >= 500 }

// Sanitize removes invisible characters before redaction and truncates only at
// rune boundaries. Cleaning first prevents reassembling an echoed credential.
func Sanitize(s, secret string, limit int) string {
	s = bound(s, len([]rune(s)))
	if secret != "" {
		s = strings.ReplaceAll(s, secret, "[redacted]")
	}
	runes := []rune(s)
	if len(runes) > limit {
		runes = runes[:limit]
	}
	return string(runes)
}
func SanitizeJSON(data []byte, secret string) ([]byte, error) {
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return nil, err
	}
	var clean func(any) any
	clean = func(v any) any {
		switch v := v.(type) {
		case string:
			return Sanitize(v, secret, len([]rune(v)))
		case []any:
			for i := range v {
				v[i] = clean(v[i])
			}
		case map[string]any:
			out := map[string]any{}
			for k, x := range v {
				out[Sanitize(k, secret, len([]rune(k)))] = clean(x)
			}
			return out
		}
		return v
	}
	return json.Marshal(clean(value))
}
