package skill

import (
	"strings"
	"testing"
)

// The frontmatter shapes below are taken verbatim from skills installed by
// `npx skills add clerk/skills`. Before multi-line scalar support, the parser
// truncated every one of them at the first line (and turned the ">-" block into
// a literal ">-"), which left the model with a useless routing description.
func TestParseMarkdownMultiLineDescriptions(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    string
		wantSub string
	}{
		{
			name: "plain multi-line scalar",
			raw: `---
name: clerk-nextjs-patterns
description: Advanced Next.js patterns - middleware, Server Actions, caching with
  Clerk.
license: MIT
---

# body
`,
			want: "Advanced Next.js patterns - middleware, Server Actions, caching with Clerk.",
		},
		{
			name: "single-quoted multi-line scalar",
			raw: `---
name: clerk-astro-patterns
description: 'Astro patterns with Clerk — middleware, SSR pages, island components,
  API routes, static vs SSR rendering. Triggers on: astro clerk, clerk astro middleware,
  astro protected page.'
license: MIT
---

# body
`,
			want: "Astro patterns with Clerk — middleware, SSR pages, island components, API routes, static vs SSR rendering. Triggers on: astro clerk, clerk astro middleware, astro protected page.",
		},
		{
			name: "folded block scalar",
			raw: `---
name: clerk-cli
description: >-
  Operate the Clerk CLI (` + "`clerk`" + ` binary) for authentication, user/org/session
  management, impersonation, local webhook testing.
license: MIT
---

# body
`,
			want: "Operate the Clerk CLI (`clerk` binary) for authentication, user/org/session management, impersonation, local webhook testing.",
		},
		{
			name: "single-line scalar is unchanged",
			raw: `---
name: clerk-backend-api
description: Clerk Backend REST API explorer and executor.
---

# body
`,
			want: "Clerk Backend REST API explorer and executor.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			def, err := ParseMarkdown(tt.raw)
			if err != nil {
				t.Fatalf("ParseMarkdown: %v", err)
			}
			if def.Description != tt.want {
				t.Errorf("description mismatch\n got: %q\nwant: %q", def.Description, tt.want)
			}
			if !strings.Contains(def.Content, "# body") {
				t.Errorf("body not preserved: %q", def.Content)
			}
		})
	}
}

// A literal block keeps its line breaks, unlike a folded one.
func TestParseMarkdownLiteralBlockScalar(t *testing.T) {
	def, err := ParseMarkdown(`---
name: literal-skill
description: |-
  first line
  second line
---
body
`)
	if err != nil {
		t.Fatalf("ParseMarkdown: %v", err)
	}
	if def.Description != "first line\nsecond line" {
		t.Errorf("got %q", def.Description)
	}
}

// Keys following a multi-line value must still be picked up — the continuation
// reader has to stop at the next top-level key rather than swallow it.
func TestParseMarkdownKeysAfterMultiLineValue(t *testing.T) {
	def, err := ParseMarkdown(`---
name: clerk-nextjs-patterns
description: >-
  Advanced Next.js patterns for
  middleware and Server Actions.
license: MIT
compatibility: Requires NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY and CLERK_SECRET_KEY.
metadata:
  author: clerk
  version: 2.2.0
---
body
`)
	if err != nil {
		t.Fatalf("ParseMarkdown: %v", err)
	}
	if def.License != "MIT" {
		t.Errorf("license = %q, want MIT", def.License)
	}
	if !strings.HasPrefix(def.Compatibility, "Requires NEXT_PUBLIC_CLERK") {
		t.Errorf("compatibility = %q", def.Compatibility)
	}
	if def.Metadata["author"] != "clerk" || def.Metadata["version"] != "2.2.0" {
		t.Errorf("metadata = %v", def.Metadata)
	}
	if def.Description != "Advanced Next.js patterns for middleware and Server Actions." {
		t.Errorf("description = %q", def.Description)
	}
}

// An unknown key with a nested block (e.g. `allowed-tools:` as a list) must be
// consumed whole so its children are not mistaken for top-level keys.
func TestParseMarkdownIgnoresUnknownNestedKeys(t *testing.T) {
	def, err := ParseMarkdown(`---
name: listy-skill
allowed-tools:
  - WebFetch
  - Read
description: Still parsed.
---
body
`)
	if err != nil {
		t.Fatalf("ParseMarkdown: %v", err)
	}
	if def.Description != "Still parsed." {
		t.Errorf("description = %q", def.Description)
	}
}

// A description longer than the limit is clamped, not rejected: dropping the
// skill would make it invisible to the model.
func TestParseMarkdownClampsLongDescription(t *testing.T) {
	long := strings.Repeat("a", 1500)
	def, err := ParseMarkdown("---\nname: long-skill\ndescription: " + long + "\n---\nbody\n")
	if err != nil {
		t.Fatalf("ParseMarkdown: %v", err)
	}
	if len([]rune(def.Description)) != maxDescriptionLen {
		t.Errorf("description length = %d, want %d", len([]rune(def.Description)), maxDescriptionLen)
	}
}
