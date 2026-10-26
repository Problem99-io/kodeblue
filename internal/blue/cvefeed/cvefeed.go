// Package cvefeed pulls the vulnerabilities published each day (NIST's
// National Vulnerability Database) and the ones CISA adds to its Known
// Exploited Vulnerabilities catalog, and picks out those that name software
// this server runs. It only downloads public feeds: nothing about the server
// is sent anywhere. The matches are candidates for the reviewer, who checks
// the installed version before recording a vulnerability.
package cvefeed

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	NVDURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	KEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	// KEVMirror is CISA's own copy of the catalog on GitHub, for when
	// cisa.gov refuses a server (its bot protection answers 403 to some
	// hosting networks).
	KEVMirror = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
	// MaxWindow bounds one pull; NVD refuses ranges over 120 days, and a
	// server that was off for weeks should not flood its reviewer.
	MaxWindow = 7 * 24 * time.Hour
	// maxBody bounds one response (a busy day is a few MB).
	maxBody = 64 << 20
)

// CVE is one published vulnerability, trimmed to what matching and the
// reviewer need.
type CVE struct {
	ID          string    `json:"id"`
	Published   time.Time `json:"published"`
	Description string    `json:"description"`
	Score       float64   `json:"score,omitempty"`
	Severity    string    `json:"severity,omitempty"`
	Products    []Product `json:"products,omitempty"`
}

// Product is an affected product as the CVE's publisher or NVD lists it.
type Product struct {
	Vendor   string `json:"vendor,omitempty"`
	Product  string `json:"product"`
	Versions string `json:"versions,omitempty"`
}

// KEV is an entry of CISA's Known Exploited Vulnerabilities catalog:
// attackers are using it now.
type KEV struct {
	ID          string `json:"cveID"`
	Vendor      string `json:"vendorProject"`
	Product     string `json:"product"`
	Name        string `json:"vulnerabilityName"`
	DateAdded   string `json:"dateAdded"`
	Description string `json:"shortDescription"`
	Action      string `json:"requiredAction"`
}

// Term is a name of software on this server to look for.
type Term struct {
	Name string `json:"name"`
	// From says where the name came from: "image traefik:v3.7.15",
	// "service ssh", "package openssh-server".
	From string `json:"from"`
	// Package terms come from the whole package list: they match only a
	// CVE's affected product, never free text, or "less" and "file" would
	// match every description.
	Package bool `json:"-"`
}

// Candidate is a CVE that names software on this server.
type Candidate struct {
	CVE
	KEV       bool      `json:"kev,omitempty"`
	KEVAction string    `json:"kev_action,omitempty"`
	Term      string    `json:"term"`
	From      string    `json:"from"`
	How       string    `json:"how"` // product | description | kev
	FoundAt   time.Time `json:"found_at"`
}

// Client fetches the feeds. Zero values use the public URLs.
type Client struct {
	HTTP *http.Client
	NVD  string
	KEV  string
	// KEVMirror is tried when KEV fails; with KEV unset it defaults to
	// CISA's GitHub copy.
	KEVMirror string
	APIKey    string // optional NVD API key: a higher rate limit
}

func (c Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 2 * time.Minute}
}

// Published returns the CVEs NVD published in [from, to).
func (c Client) Published(ctx context.Context, from, to time.Time) ([]CVE, error) {
	base := c.NVD
	if base == "" {
		base = NVDURL
	}
	if to.Sub(from) > MaxWindow {
		from = to.Add(-MaxWindow)
	}
	var out []CVE
	for start := 0; ; {
		q := url.Values{}
		q.Set("pubStartDate", from.UTC().Format("2006-01-02T15:04:05.000Z"))
		q.Set("pubEndDate", to.UTC().Format("2006-01-02T15:04:05.000Z"))
		q.Set("resultsPerPage", "2000")
		q.Set("startIndex", strconv.Itoa(start))
		var page nvdPage
		if err := c.get(ctx, base+"?"+q.Encode(), true, &page); err != nil {
			return out, err
		}
		for _, v := range page.Vulnerabilities {
			out = append(out, v.CVE.trim())
		}
		start += len(page.Vulnerabilities)
		if len(page.Vulnerabilities) == 0 || start >= page.TotalResults {
			return out, nil
		}
		// NVD asks clients to pause between requests (5 per 30 s without a key).
		select {
		case <-ctx.Done():
			return out, ctx.Err()
		case <-time.After(6 * time.Second):
		}
	}
}

// ExploitedSince returns the KEV entries CISA added on or after since's date.
func (c Client) ExploitedSince(ctx context.Context, since time.Time) ([]KEV, error) {
	urls := []string{c.KEV, c.KEVMirror}
	if c.KEV == "" {
		urls[0] = KEVURL
		if c.KEVMirror == "" {
			urls[1] = KEVMirror
		}
	}
	var cat struct {
		Vulnerabilities []KEV `json:"vulnerabilities"`
	}
	var err error
	for _, u := range urls {
		if u == "" {
			continue
		}
		if err = c.get(ctx, u, false, &cat); err == nil {
			break
		}
	}
	if err != nil {
		return nil, err
	}
	day := since.UTC().Format("2006-01-02")
	var out []KEV
	for _, k := range cat.Vulnerabilities {
		if k.DateAdded >= day {
			out = append(out, k)
		}
	}
	return out, nil
}

func (c Client) get(ctx context.Context, u string, nvd bool, v any) error {
	var last error
	for try := 0; try < 3; try++ {
		if try > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(try) * 30 * time.Second):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", "kodeblue-cvefeed")
		if nvd && c.APIKey != "" {
			req.Header.Set("apiKey", c.APIKey)
		}
		resp, err := c.http().Do(req)
		if err != nil {
			last = err
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		resp.Body.Close()
		switch {
		case err != nil:
			last = err
		case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
			last = fmt.Errorf("%s: HTTP %d", host(u), resp.StatusCode) // rate limit or outage: try again
		case resp.StatusCode != http.StatusOK:
			return fmt.Errorf("%s: HTTP %d", host(u), resp.StatusCode)
		default:
			if err := json.Unmarshal(body, v); err != nil {
				return fmt.Errorf("%s: %w", host(u), err)
			}
			return nil
		}
	}
	return last
}

func host(u string) string {
	if p, err := url.Parse(u); err == nil && p.Host != "" {
		return p.Host
	}
	return u
}

type nvdPage struct {
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdCVE struct {
	ID           string `json:"id"`
	Published    string `json:"published"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics map[string][]struct {
		Type     string `json:"type"`
		CVSSData struct {
			BaseScore    float64 `json:"baseScore"`
			BaseSeverity string  `json:"baseSeverity"`
		} `json:"cvssData"`
		BaseSeverity string `json:"baseSeverity"` // CVSS v2 keeps it here
	} `json:"metrics"`
	// Affected is what the CVE's publisher (its CNA) lists; new CVEs have it
	// days or weeks before NVD adds its own configurations.
	Affected []struct {
		AffectedData []struct {
			Vendor  string `json:"vendor"`
			Product string `json:"product"`
			// A CNA may name a package instead (CVE 5): "mautic/core" from
			// packagist, "openssh" from Debian.
			PackageName string   `json:"packageName"`
			CPEs        []string `json:"cpes"`
			Versions    []struct {
				Version         string `json:"version"`
				Status          string `json:"status"`
				LessThan        string `json:"lessThan"`
				LessThanOrEqual string `json:"lessThanOrEqual"`
			} `json:"versions"`
		} `json:"affectedData"`
	} `json:"affected"`
	Configurations []struct {
		Nodes []struct {
			CPEMatch []struct {
				Vulnerable            bool   `json:"vulnerable"`
				Criteria              string `json:"criteria"`
				VersionStartIncluding string `json:"versionStartIncluding"`
				VersionEndExcluding   string `json:"versionEndExcluding"`
				VersionEndIncluding   string `json:"versionEndIncluding"`
			} `json:"cpeMatch"`
		} `json:"nodes"`
	} `json:"configurations"`
}

// scoreOrder prefers the newest CVSS version, and NVD's own (Primary) score.
var scoreOrder = []string{"cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"}

func (n nvdCVE) trim() CVE {
	c := CVE{ID: n.ID}
	c.Published, _ = time.Parse("2006-01-02T15:04:05.000", n.Published)
	for _, d := range n.Descriptions {
		if d.Lang == "en" {
			c.Description = d.Value
			break
		}
	}
	for _, k := range scoreOrder {
		ms := n.Metrics[k]
		if len(ms) == 0 {
			continue
		}
		m := ms[0]
		for _, x := range ms {
			if x.Type == "Primary" {
				m = x
			}
		}
		c.Score, c.Severity = m.CVSSData.BaseScore, strings.ToLower(m.CVSSData.BaseSeverity)
		if c.Severity == "" {
			c.Severity = strings.ToLower(m.BaseSeverity)
		}
		break
	}
	seen := map[string]bool{}
	add := func(p Product) {
		k := strings.ToLower(p.Vendor + "|" + p.Product + "|" + p.Versions)
		if p.Product == "" || seen[k] {
			return
		}
		seen[k] = true
		c.Products = append(c.Products, p)
	}
	for _, a := range n.Affected {
		for _, ad := range a.AffectedData {
			var vs []string
			for _, v := range ad.Versions {
				switch {
				case v.Status != "affected":
				case v.LessThan != "":
					vs = append(vs, v.Version+" to <"+v.LessThan)
				case v.LessThanOrEqual != "":
					vs = append(vs, v.Version+" to <="+v.LessThanOrEqual)
				default:
					vs = append(vs, v.Version)
				}
			}
			name := ad.Product
			if !Usable(name) && ad.PackageName != "" {
				name = ad.PackageName
			}
			add(Product{Vendor: ad.Vendor, Product: name, Versions: clip(strings.Join(vs, ", "), 300)})
			for _, cpe := range ad.CPEs {
				if v, p, ok := cpeProduct(cpe); ok {
					add(Product{Vendor: v, Product: p})
				}
			}
		}
	}
	for _, cfg := range n.Configurations {
		for _, node := range cfg.Nodes {
			for _, m := range node.CPEMatch {
				v, p, ok := cpeProduct(m.Criteria)
				if !ok || !m.Vulnerable {
					continue
				}
				var r []string
				if m.VersionStartIncluding != "" {
					r = append(r, ">="+m.VersionStartIncluding)
				}
				if m.VersionEndExcluding != "" {
					r = append(r, "<"+m.VersionEndExcluding)
				}
				if m.VersionEndIncluding != "" {
					r = append(r, "<="+m.VersionEndIncluding)
				}
				if parts := strings.Split(m.Criteria, ":"); len(parts) > 5 && parts[5] != "*" && parts[5] != "-" {
					r = append(r, parts[5])
				}
				add(Product{Vendor: v, Product: p, Versions: strings.Join(r, " ")})
			}
		}
	}
	return c
}

// cpeProduct reads vendor and product from cpe:2.3:<part>:<vendor>:<product>:…
func cpeProduct(cpe string) (vendor, product string, ok bool) {
	p := strings.Split(cpe, ":")
	if len(p) < 5 || p[0] != "cpe" || p[4] == "*" || p[4] == "" {
		return "", "", false
	}
	return p[3], p[4], true
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// Norm folds a product name for comparison: lower case, with "_", " " and
// "." as "-". "Apache HTTP_Server" and "apache-http-server" are the same.
func Norm(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.NewReplacer("_", "-", " ", "-", ".", "-").Replace(s)
}

// generic names are too common to mean anything in a description or as a
// product: they would match most CVEs.
var generic = map[string]bool{
	"": true, "n/a": true, "unknown": true, "none": true, "multiple-products": true, "server": true, "client": true,
	"agent": true, "core": true, "app": true, "api": true, "web": true, "http": true, "proxy": true, "worker": true,
	"main": true, "service": true, "daemon": true, "init": true, "manager": true, "base": true, "common": true, "sdk": true,
	"cli": true, "master": true, "data": true,
	// The kernel gets dozens of CVEs a day; the distribution's security
	// updates (versions) are how a server learns which ones it needs.
	"linux": true, "linux-kernel": true, "kernel": true, "backend": true, "frontend": true, "admin": true, "node": true, "sh": true, "bash": true,
}

// Usable reports whether a name is specific enough to match on.
func Usable(name string) bool {
	n := Norm(name)
	return len(n) >= 3 && !generic[n]
}

// Match picks the CVEs and KEV entries that name a term. A CVE whose
// affected product equals a term matches on "product"; a service or image
// name in its description as a whole word matches on "description"; a KEV
// entry whose product or vendor equals a term matches on "kev" (attackers
// use it now). A description counts only for a CVE that lists no product.
// A CVE matched both ways is reported once, by product.
func Match(cves []CVE, kev []KEV, terms []Term, now time.Time) []Candidate {
	byName := map[string]Term{}
	var words []Term
	for _, t := range terms {
		if !Usable(t.Name) {
			continue
		}
		n := Norm(t.Name)
		if _, dup := byName[n]; !dup || !t.Package {
			byName[n] = t
		}
		if !t.Package && len(n) >= 4 {
			words = append(words, t)
		}
	}
	res := map[string]*regexp.Regexp{}
	for _, t := range words {
		res[t.Name] = regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(t.Name) + `\b`)
	}
	kevBy := map[string]KEV{}
	for _, k := range kev {
		kevBy[k.ID] = k
	}
	out := map[string]*Candidate{}
	put := func(c Candidate) {
		if old, ok := out[c.ID]; ok && Rank(*old) >= Rank(c) {
			return
		}
		c.FoundAt = now
		out[c.ID] = &c
	}
	for _, c := range cves {
		matched := false
		for _, p := range c.Products {
			if t, ok := byName[Norm(p.Product)]; ok && Usable(p.Product) {
				put(Candidate{CVE: c, Term: t.Name, From: t.From, How: "product"})
				matched = true
				break
			}
		}
		// The description counts only when the CVE names no product: one
		// that lists its product and still mentions Docker or PostgreSQL is
		// about something running on them, not about them.
		if matched || named(c.Products) {
			continue
		}
		for _, t := range words {
			if res[t.Name].MatchString(c.Description) {
				put(Candidate{CVE: c, Term: t.Name, From: t.From, How: "description"})
				break
			}
		}
	}
	for _, k := range kev {
		for _, name := range []string{k.Product, k.Vendor} {
			t, ok := byName[Norm(name)]
			if !ok || !Usable(name) {
				continue
			}
			c := Candidate{CVE: CVE{ID: k.ID, Description: k.Name + ": " + k.Description, Products: []Product{{Vendor: k.Vendor, Product: k.Product}}},
				KEV: true, KEVAction: k.Action, Term: t.Name, From: t.From, How: "kev"}
			if old, ok := out[k.ID]; ok {
				c.CVE.Score, c.CVE.Severity, c.CVE.Published = old.Score, old.Severity, old.Published
			}
			put(c)
			break
		}
	}
	// A CVE published today that CISA already lists as exploited.
	for id, c := range out {
		if k, ok := kevBy[id]; ok && !c.KEV {
			c.KEV, c.KEVAction = true, k.Action
		}
	}
	list := make([]Candidate, 0, len(out))
	for _, c := range out {
		list = append(list, *c)
	}
	Sort(list)
	return list
}

// named reports whether a CVE lists a real affected product.
func named(ps []Product) bool {
	for _, p := range ps {
		if Usable(p.Product) {
			return true
		}
	}
	return false
}

// Rank orders candidates: exploited (3), product match (2), description (1).
func Rank(c Candidate) int {
	switch {
	case c.KEV:
		return 3
	case c.How == "product":
		return 2
	}
	return 1
}

// Sort puts exploited ones first, then product matches, then by score.
func Sort(l []Candidate) {
	sort.SliceStable(l, func(i, j int) bool {
		if ri, rj := Rank(l[i]), Rank(l[j]); ri != rj {
			return ri > rj
		}
		if l[i].Score != l[j].Score {
			return l[i].Score > l[j].Score
		}
		return l[i].ID < l[j].ID
	})
}

// Urgent reports whether a candidate is worth telling people about before
// the next review: attackers use it, or it scores critical.
func (c Candidate) Urgent() bool { return c.KEV || c.Score >= 9 }
