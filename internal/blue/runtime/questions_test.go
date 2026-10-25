package runtime

import "testing"

func TestPickCheckpointOption(t *testing.T) {
	opts := []string{"Yes, keep going", "No, stop here"}
	if got := pick(opts, keepChoice); got != "Yes, keep going" {
		t.Fatalf("keep: %q", got)
	}
	if got := pick(opts, stopChoice); got != "No, stop here" {
		t.Fatalf("stop: %q", got)
	}
	if got := pick([]string{"Yes — continue", "No — end the run"}, stopChoice); got != "No — end the run" {
		t.Fatalf("relabelled stop option not matched: %q", got)
	}
}
