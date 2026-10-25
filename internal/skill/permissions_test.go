package skill

import "testing"

func TestResolveMostSpecificPatternWins(t *testing.T) {
	rules := map[string]PermissionAction{
		"*":            PermissionDeny,
		"disk-*":       PermissionAsk,
		"disk-usage-*": PermissionAllow,
		"disk-usage":   PermissionAllow,
		"net-*":        PermissionAllow,
		"*udit":        PermissionDeny,
	}
	cases := []struct {
		name string
		want PermissionAction
	}{
		{"disk-usage", PermissionAllow},        // exact beats every glob
		{"disk-usage-report", PermissionAllow}, // longest glob beats shorter, stricter glob
		{"disk-check", PermissionAsk},          // glob beats "*"
		{"anything-else", PermissionDeny},      // only "*" matches
		{"net-audit", PermissionDeny},          // equal-length globs: more restrictive wins
	}
	// Map iteration order is random; repeat so an order-dependent result
	// would show up as a flaky failure.
	for i := 0; i < 50; i++ {
		p := NewPermissions(rules)
		for _, tc := range cases {
			if got := p.Resolve(tc.name); got != tc.want {
				t.Fatalf("Resolve(%q) = %q, want %q", tc.name, got, tc.want)
			}
		}
	}
}

func TestResolveDefaultsToAllow(t *testing.T) {
	p := NewPermissions(nil)
	if got := p.Resolve("any"); got != PermissionAllow {
		t.Fatalf("no rules: got %q, want allow", got)
	}
	p = NewPermissions(map[string]PermissionAction{"other": PermissionDeny})
	if got := p.Resolve("any"); got != PermissionAllow {
		t.Fatalf("no matching rule: got %q, want allow", got)
	}
}
