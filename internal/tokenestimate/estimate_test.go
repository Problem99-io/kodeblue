package tokenestimate

import (
	"testing"

	"github.com/pkoukk/tiktoken-go"
)

// TestEmbeddedTokenizerLoadsOffline proves the embedded vocabulary yields a
// working o200k_base tokenizer with no network access.
func TestEmbeddedTokenizerLoadsOffline(t *testing.T) {
	tiktoken.SetBpeLoader(embeddedBpeLoader{})
	tok, err := tiktoken.GetEncoding(EncodingName)
	if err != nil {
		t.Fatalf("GetEncoding with embedded loader failed: %v", err)
	}
	// "hello world" is 2 tokens under o200k_base; assert an exact, known value
	// so a corrupted/truncated asset is caught rather than silently mis-sized.
	if got := len(tok.Encode("hello world", nil, nil)); got != 2 {
		t.Fatalf("token count for \"hello world\" = %d, want 2", got)
	}
}

// TestEstimateTextIsExact verifies EstimateText returns real tokenizer counts
// (no heuristic fallback) and handles the empty case.
func TestEstimateTextIsExact(t *testing.T) {
	if got := EstimateText("  "); got != 0 {
		t.Fatalf("EstimateText(blank) = %d, want 0", got)
	}

	const sample = "The quick brown fox jumps over the lazy dog."
	want := int64(len(getTokenizer().Encode(sample, nil, nil)))
	if got := EstimateText(sample); got != want {
		t.Fatalf("EstimateText(%q) = %d, want exact tokenizer count %d", sample, got, want)
	}
	if want <= 0 {
		t.Fatalf("expected a positive token count for a non-empty string, got %d", want)
	}
}
