package research

import (
	"context"
	"testing"
	"time"
)

func TestInvestigationWindowFixesDaySourcesAndSequence(t *testing.T) {
	s := testStore(t, nil)
	ctx := context.Background()
	now := time.Now().UTC()
	start := now.Truncate(24 * time.Hour)
	_, err := s.Ingest(ctx, "website", "srv_gateway", false, []Event{request("old", start.Add(-time.Hour)), request("included", now)}, now)
	if err != nil {
		t.Fatal(err)
	}
	through, err := s.LastSequence(ctx, "website")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = s.Ingest(ctx, "website", "srv_gateway", false, []Event{request("new", now)}, now)
	p, err := s.Window(ctx, "website", []string{"srv_gateway"}, start, start.Add(24*time.Hour), 0, through)
	if err != nil || len(p.Observations) != 1 || p.Observations[0].Event.ID != "included" {
		t.Fatalf("%+v %v", p, err)
	}
	p, err = s.Window(ctx, "website", nil, start, start.Add(24*time.Hour), 0, through)
	if err != nil || len(p.Observations) != 0 {
		t.Fatal("source scope bypass")
	}
}
