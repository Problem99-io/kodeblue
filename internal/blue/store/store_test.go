package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestSpendPricing(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "k.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	since := time.Now().Add(-time.Minute)

	// A reported cost is used as is.
	st.Spend("triage", "m", 1000, 100, 0, 0.5)
	if st.Unpriced() {
		t.Fatal("a reported cost is not unpriced")
	}
	// No reported cost and no prices: recorded at $0 and flagged.
	st.Spend("triage", "m", 1000, 100, 0, 0)
	if !st.Unpriced() {
		t.Fatal("a $0 call with tokens must be flagged")
	}
	// With prices, the call is priced from its tokens.
	st.SetPricing(2, 10) // USD per million tokens
	st.Spend("triage", "m", 1_000_000, 100_000, 0, 0)
	if usd, _, _ := st.SpentSince(since); usd < 0.5+3-1e-9 || usd > 0.5+3+1e-9 {
		t.Fatalf("spent %v, want 3.5", usd)
	}
}
