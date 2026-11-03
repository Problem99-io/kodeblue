package research

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"
)

func validOrigin(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Host != "" && (u.Scheme == "https" || (u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1"))) && u.User == nil && u.RawQuery == "" && u.Fragment == "" && u.Path == "" && raw == u.Scheme+"://"+u.Host
}

type Coverage struct {
	Accepted       int64     `json:"accepted"`
	Rejected       int64     `json:"rejected"`
	DetailEvicted  int64     `json:"detail_evicted"`
	SummaryEvicted int64     `json:"summary_evicted"`
	LastObserved   time.Time `json:"last_observed"`
	DetailHours    int       `json:"detail_hours"`
	SummaryDays    int       `json:"summary_days"`
	Notes          []string  `json:"notes"`
}

func (s *Store) Coverage(ctx context.Context, site string) (Coverage, error) {
	c := Coverage{DetailHours: int(s.limits.DetailTTL / time.Hour), SummaryDays: int(s.limits.SummaryTTL / (24 * time.Hour)), Notes: []string{
		"Coverage describes received observations, not all website traffic. Disabled SDKs, upstream loss and privacy gates are not observable here.",
		"Browser events are client claims, not proof of JavaScript execution, a human visitor or an AI agent.",
		"Fingerprint matches are similarity evidence, not actor identity or a network connection.",
	}}
	if _, err := s.Site(ctx, site); err != nil {
		return c, err
	}
	var at int64
	err := s.db.QueryRowContext(ctx, "SELECT accepted,rejected,evicted,summary_evicted,last_at FROM coverage WHERE site=?", site).Scan(&c.Accepted, &c.Rejected, &c.DetailEvicted, &c.SummaryEvicted, &at)
	if errors.Is(err, sql.ErrNoRows) {
		err = nil
	}
	if at > 0 {
		c.LastObserved = time.Unix(at, 0).UTC()
	}
	return c, err
}

type Page struct {
	Observations []Observation `json:"observations"`
	Next         int64         `json:"next"`
	Capped       bool          `json:"capped"`
	Coverage     Coverage      `json:"coverage"`
}

// Events is keyset-paged, site-scoped and bounded to 100 rows. Sequence numbers
// are insertion order; the source event time remains separately visible.
func (s *Store) Events(ctx context.Context, site string, after int64, limit int) (Page, error) {
	return s.events(ctx, site, after, limit, false)
}

func (s *Store) Tail(ctx context.Context, site string, limit int) (Page, error) {
	return s.events(ctx, site, 0, limit, true)
}

func (s *Store) events(ctx context.Context, site string, after int64, limit int, tail bool) (Page, error) {
	result := Page{Observations: []Observation{}}
	if after < 0 {
		return result, ErrInvalid
	}
	if limit < 1 || limit > 100 {
		limit = 100
	}
	var err error
	if result.Coverage, err = s.Coverage(ctx, site); err != nil {
		return result, err
	}
	query := "SELECT seq,source,ingested,data FROM events WHERE site=? AND seq>? AND ingested>=? ORDER BY seq LIMIT ?"
	if tail {
		query = "SELECT seq,source,ingested,data FROM events WHERE site=? AND seq>? AND ingested>=? ORDER BY seq DESC LIMIT ?"
	}
	rows, err := s.db.QueryContext(ctx, query, site, after, time.Now().Add(-s.limits.DetailTTL).Unix(), limit+1)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	for rows.Next() {
		var o Observation
		var at int64
		var b string
		if err = rows.Scan(&o.Sequence, &o.Source, &at, &b); err != nil {
			return result, err
		}
		if len(result.Observations) == limit {
			result.Capped = true
			break
		}
		o.Site = site
		o.Provenance = "enrolled_source_reported"
		if o.Source == "browser" {
			o.Provenance = "browser_claimed"
		}
		o.ObservedAt = time.Unix(at, 0).UTC()
		if err = json.Unmarshal([]byte(b), &o.Event); err != nil {
			return result, err
		}
		result.Next = o.Sequence
		result.Observations = append(result.Observations, o)
	}
	if tail {
		slices.Reverse(result.Observations)
		if len(result.Observations) > 0 {
			result.Next = result.Observations[len(result.Observations)-1].Sequence
		}
	}
	return result, rows.Err()
}

type Hour struct {
	At           time.Time `json:"at"`
	Requests     int64     `json:"requests"`
	Pageviews    int64     `json:"pageviews"`
	Interactions int64     `json:"interactions"`
	Errors       int64     `json:"errors"`
}
type Finding struct {
	Rule        string `json:"rule"`
	Conclusion  string `json:"conclusion"`
	Count       int64  `json:"count"`
	Explanation string `json:"explanation"`
	Identity    string `json:"identity"`
}
type Report struct {
	Version             string    `json:"version"`
	Site                string    `json:"site"`
	Date                string    `json:"date"`
	Timezone            string    `json:"timezone"`
	Start               time.Time `json:"start"`
	End                 time.Time `json:"end"`
	Hours               []Hour    `json:"hours"`
	Requests            int64     `json:"requests"`
	Pageviews           int64     `json:"pageviews"`
	Interactions        int64     `json:"interactions"`
	Errors              int64     `json:"errors"`
	Findings            []Finding `json:"findings"`
	Coverage            Coverage  `json:"coverage"`
	Baseline            string    `json:"baseline"`
	BoundaryUncertainty bool      `json:"boundary_uncertainty"`
}

// Daily reads compact 15-minute counters, never scans raw observations. Timezone
// boundaries and 23/25-hour DST days are explicit. Unusual non-quarter-hour
// boundaries carry uncertainty rather than claiming exact counts.
func (s *Store) Daily(ctx context.Context, site, date string) (Report, error) {
	r := Report{Version: "behavioral-prototype-v1", Site: site, Date: date, Hours: []Hour{}, Findings: []Finding{}, Baseline: "unavailable: no validated comparable-day baseline"}
	config, err := s.Site(ctx, site)
	if err != nil {
		return r, err
	}
	loc, err := time.LoadLocation(config.Timezone)
	if err != nil {
		return r, err
	}
	day, err := time.ParseInLocation("2006-01-02", date, loc)
	if err != nil || day.Format("2006-01-02") != date {
		return r, ErrInvalid
	}
	r.Timezone = config.Timezone
	r.Start = day.UTC()
	r.End = day.AddDate(0, 0, 1).UTC()
	if r.Start.Before(time.Now().Add(-s.limits.SummaryTTL)) || r.End.After(time.Now().Add(48*time.Hour)) {
		return r, ErrInvalid
	}
	r.BoundaryUncertainty = r.Start.Unix()%900 != 0 || r.End.Unix()%900 != 0
	if r.Coverage, err = s.Coverage(ctx, site); err != nil {
		return r, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT (hour/3600)*3600,
SUM(CASE WHEN kind='request' THEN n ELSE 0 END),SUM(CASE WHEN kind='pageview' THEN n ELSE 0 END),
SUM(CASE WHEN kind='interaction' THEN n ELSE 0 END),SUM(CASE WHEN kind='request' AND status=5 THEN n ELSE 0 END),
SUM(CASE WHEN kind='request' AND category='sensitive' THEN n ELSE 0 END)
FROM buckets WHERE site=? AND hour>=? AND hour<? GROUP BY (hour/3600) ORDER BY (hour/3600)`, site, r.Start.Truncate(15*time.Minute).Unix(), r.End.Unix())
	if err != nil {
		return r, err
	}
	defer rows.Close()
	var sensitive int64
	for rows.Next() {
		var h Hour
		var at, n int64
		if err = rows.Scan(&at, &h.Requests, &h.Pageviews, &h.Interactions, &h.Errors, &n); err != nil {
			return r, err
		}
		h.At = time.Unix(at, 0).UTC()
		r.Hours = append(r.Hours, h)
		r.Requests += h.Requests
		r.Pageviews += h.Pageviews
		r.Interactions += h.Interactions
		r.Errors += h.Errors
		sensitive += n
	}
	if sensitive >= 20 {
		r.Findings = append(r.Findings, Finding{Rule: "sensitive-route-volume-v1", Conclusion: "needs_review", Count: sensitive, Identity: "not_established", Explanation: "At least 20 producer-reported requests targeted sensitive route categories. This is observed volume, not proof of one actor or compromise. Inspect retained evidence and authorized tests before escalating."})
	}
	return r, rows.Err()
}

type Edge struct {
	ProducerID string    `json:"producer_id"`
	SourceIP   string    `json:"source_ip,omitempty"`
	TargetIP   string    `json:"target_ip,omitempty"`
	FirstAt    time.Time `json:"first_at"`
	LastAt     time.Time `json:"last_at"`
	Source     string    `json:"source"`
	Target     string    `json:"target"`
	Relation   string    `json:"relation"`
	Evidence   []int64   `json:"evidence"`
	Count      int       `json:"count"`
}
type Graph struct {
	Edges    []Edge `json:"edges"`
	Capped   bool   `json:"capped"`
	Identity string `json:"identity"`
}

// Graph uses a bounded slice and only calls explicit connection observations
// communications. A fingerprint group is always a similarity relation.
func (s *Store) Graph(ctx context.Context, site string) (Graph, error) {
	g := Graph{Edges: []Edge{}, Identity: "not_established"}
	p, err := s.Tail(ctx, site, 100)
	if err != nil {
		return g, err
	}
	g.Capped = p.Capped
	index := map[string]int{}
	add := func(from, to, relation string, id int64, producer, sourceIP, targetIP string, at time.Time) {
		key := from + "\x00" + to + "\x00" + relation
		if i, ok := index[key]; ok {
			g.Edges[i].Count++
			if at.Before(g.Edges[i].FirstAt) {
				g.Edges[i].FirstAt = at
			}
			if at.After(g.Edges[i].LastAt) {
				g.Edges[i].LastAt = at
			}
			if len(g.Edges[i].Evidence) < 8 {
				g.Edges[i].Evidence = append(g.Edges[i].Evidence, id)
			}
			return
		}
		index[key] = len(g.Edges)
		g.Edges = append(g.Edges, Edge{Source: from, Target: to, Relation: relation, Evidence: []int64{id}, Count: 1, ProducerID: producer, SourceIP: sourceIP, TargetIP: targetIP, FirstAt: at, LastAt: at})
	}
	for _, o := range p.Observations {
		if o.Event.Kind == "connection" {
			add(o.Source+":"+o.Event.PeerIP, o.Source+":"+o.Event.DestinationIP, "producer_reported_connection", o.Sequence, o.Source, o.Event.PeerIP, o.Event.DestinationIP, o.Event.At)
		}
		if f := o.Event.Fingerprint; f != nil {
			from := "source:" + o.Source
			if o.Event.PeerIP != "" {
				from = o.Source + ":" + o.Event.PeerIP
			}
			add(from, "fingerprint:"+strings.Join([]string{f.Algorithm, f.Version, f.CapturePoint, f.Value}, ":"), "fingerprint_observed_at_source", o.Sequence, o.Source, o.Event.PeerIP, "", o.Event.At)
		}
	}
	return g, nil
}
