package provider

import (
	"context"
	"testing"
)

// reportingProvider is a Provider that answers ReportedContextWindow from a
// stand-in gateway catalog, so it satisfies reportedContextWindowResolver.
type reportingProvider struct {
	window   int64
	reported bool
}

func (reportingProvider) Name() string { return "reporting" }
func (reportingProvider) Stream(ctx context.Context, req *Request) (<-chan StreamEvent, error) {
	return nil, nil
}
func (reportingProvider) CountTokens(ctx context.Context, req *Request) (*Usage, error) {
	return nil, nil
}
func (p reportingProvider) ReportedContextWindow(ctx context.Context, model string) (int64, bool) {
	return p.window, p.reported
}

// bareProvider implements only the base Provider interface (no window reporting).
type bareProvider struct{}

func (bareProvider) Name() string { return "bare" }
func (bareProvider) Stream(ctx context.Context, req *Request) (<-chan StreamEvent, error) {
	return nil, nil
}
func (bareProvider) CountTokens(ctx context.Context, req *Request) (*Usage, error) {
	return nil, nil
}

func TestResolveContextWindowKnown(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name       string
		provider   Provider
		model      string
		wantWindow int64
		wantKnown  bool
	}{
		{
			name:       "live catalog window is authoritative",
			provider:   reportingProvider{window: 250_000, reported: true},
			model:      "some-model",
			wantWindow: 250_000,
			wantKnown:  true,
		},
		{
			name:       "catalog silent but model in registry is authoritative",
			provider:   reportingProvider{reported: false},
			model:      "claude-opus-4.8",
			wantWindow: 200_000,
			wantKnown:  true,
		},
		{
			name:       "catalog silent and model unknown is the default guess, not known",
			provider:   reportingProvider{reported: false},
			model:      "totally-unknown-model",
			wantWindow: DefaultContextWindow,
			wantKnown:  false,
		},
		{
			name:       "provider cannot report and model unknown is not known",
			provider:   bareProvider{},
			model:      "totally-unknown-model",
			wantWindow: DefaultContextWindow,
			wantKnown:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			window, known := ResolveContextWindowKnown(ctx, tc.provider, tc.model)
			if window != tc.wantWindow || known != tc.wantKnown {
				t.Fatalf("ResolveContextWindowKnown(%q) = (%d, %v), want (%d, %v)",
					tc.model, window, known, tc.wantWindow, tc.wantKnown)
			}
		})
	}
}
