package research

import (
	"context"
	"encoding/json"
	"strings"
	"time"
)

func (s *Store) LastSequence(ctx context.Context, site string) (int64, error) {
	var seq int64
	err := s.db.QueryRowContext(ctx, "SELECT COALESCE(MAX(seq),0) FROM events WHERE site=?", site).Scan(&seq)
	return seq, err
}

// Window is a bounded investigation slice. The job fixes the site, source set,
// event-time interval and last accepted sequence; new ingestion cannot grow it.
func (s *Store) Window(ctx context.Context, site string, sources []string, start, end time.Time, after, through int64) (Page, error) {
	p := Page{Observations: []Observation{}}
	if after < 0 || through < 0 || len(sources) > 32 || !end.After(start) {
		return p, ErrInvalid
	}
	var err error
	if p.Coverage, err = s.Coverage(ctx, site); err != nil {
		return p, err
	}
	args := []any{site, after, through, start.Unix(), end.Unix(), time.Now().Add(-s.limits.DetailTTL).Unix(), "browser"}
	for _, source := range sources {
		args = append(args, source)
	}
	query := "SELECT seq,source,ingested,data FROM events WHERE site=? AND seq>? AND seq<=? AND at>=? AND at<? AND ingested>=? AND source IN (?" + strings.Repeat(",?", len(sources)) + ") ORDER BY seq LIMIT 26"
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return p, err
	}
	defer rows.Close()
	for rows.Next() {
		if len(p.Observations) == 25 {
			p.Capped = true
			break
		}
		var o Observation
		var at int64
		var b string
		if err = rows.Scan(&o.Sequence, &o.Source, &at, &b); err != nil {
			return p, err
		}
		if err = json.Unmarshal([]byte(b), &o.Event); err != nil {
			return p, err
		}
		o.Site = site
		o.ObservedAt = time.Unix(at, 0).UTC()
		o.Provenance = "enrolled_source_reported"
		if o.Source == "browser" {
			o.Provenance = "browser_claimed"
		}
		p.Next = o.Sequence
		p.Observations = append(p.Observations, o)
	}
	return p, rows.Err()
}
