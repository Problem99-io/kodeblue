package provider

import (
	"strings"
	"testing"
)

// OpenRouter answers a key past its own spending cap with 403. That is not
// "access denied to this model", and retrying before the reset only fails
// again: say what it is and when it lifts, without the provider's message
// (it links the key).
func TestSpendLimitsAreNamed(t *testing.T) {
	capped := &APIStatusError{Provider: "openai", StatusCode: 403, Body: `{"error":{"message":"Key limit exceeded (daily limit). Manage it using https://openrouter.ai/workspaces/default/keys/62ebae909bc05a15 $2.01 of $2.00 used; resets 2026-10-27T00:00:00.000Z.","code":403,"metadata":{"limit_source":"openrouter_key_limit"}}}`}
	d := DiagnoseFailure(capped)
	if d.Class != "spend_limit" || d.ResetsAt != "2026-10-27T00:00:00Z" {
		t.Fatalf("diagnostic: %+v", d)
	}
	reason := FailureReason(capped)
	if !strings.Contains(reason, "spending limit") || !strings.Contains(reason, "2026-10-27 00:00 UTC") || strings.Contains(reason, "62ebae") || strings.Contains(reason, "$2") {
		t.Fatalf("reason: %q", reason)
	}
	if f := FailureFields(capped); f["resets_at"] != "2026-10-27T00:00:00Z" {
		t.Fatalf("fields: %+v", f)
	}
	if recoverableConnectionError(capped) || RestartableTurn(capped) {
		t.Fatal("a spending limit is not transient")
	}

	broke := &APIStatusError{Provider: "openai", StatusCode: 402, Body: `{"error":{"message":"This request requires more credits, or fewer max_tokens. You requested up to 32768 tokens, but can only afford 1200.","code":402}}`}
	if d := DiagnoseFailure(broke); d.Class != "quota_exceeded" || !strings.Contains(d.Cause, "credit balance") {
		t.Fatalf("402: %+v", d)
	}
	// A plain 403 is still access to the model.
	if d := DiagnoseFailure(&APIStatusError{Provider: "openai", StatusCode: 403, Body: `{"error":{"message":"not allowed"}}`}); d.Class != "permission" {
		t.Fatalf("plain 403: %+v", d)
	}
}
