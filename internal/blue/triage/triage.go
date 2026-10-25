// Package triage is kodeblue's cheap middle layer: findings that survived the
// deterministic filters are classified in batches by a small model in a single
// call. Benign verdicts feed back into the baseline (fewer false positives
// next time); suspicious and malicious ones open incidents.
package triage

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/Problem99-io/kodeblue/blue"
	"github.com/Problem99-io/kodeblue/internal/blue/detect"
	"github.com/Problem99-io/kodeblue/internal/blue/hostexec"
	"github.com/Problem99-io/kodeblue/internal/blue/llm"
	"github.com/Problem99-io/kodeblue/internal/blue/sensors"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

type Triager struct {
	Client *llm.Client
	Model  string
	Store  *store.Store
	Env    *sensors.Env
	// AutoAcceptConfidence: benign verdicts at or above this confidence on
	// non-protected findings are absorbed without a human.
	AutoAcceptConfidence float64
	BatchSize            int
	// BeforeBatch, if set, runs before each batch's model call (the
	// daemon's watchdog extends its deadline by one batch).
	BeforeBatch func()
}

// Outcome for one finding.
type Outcome struct {
	Finding    *store.Finding
	Verdict    string // benign | suspicious | malicious | error
	Confidence float64
	Reason     string
	Action     string // absorbed | needs_ack | escalate
}

type result struct {
	ID         int64   `json:"id"`
	Verdict    string  `json:"verdict"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason"`
	Allow      *struct {
		KeyPattern string `json:"key_pattern"`
		Reason     string `json:"reason"`
	} `json:"allow"`
}

// Run classifies findings (status "new"), updating their status and the
// baseline, and returns per-finding outcomes for routing.
func (t *Triager) Run(ctx context.Context, findings []store.Finding) ([]Outcome, error) {
	if t.BatchSize <= 0 {
		t.BatchSize = 8
	}
	var out []Outcome
	for i := 0; i < len(findings); i += t.BatchSize {
		end := i + t.BatchSize
		if end > len(findings) {
			end = len(findings)
		}
		batch := findings[i:end]
		if t.BeforeBatch != nil {
			t.BeforeBatch()
		}
		res, err := t.batch(ctx, batch)
		if err != nil {
			// Fail safe: a triage outage must not hide findings.
			for j := range batch {
				f := batch[j]
				out = append(out, Outcome{Finding: &f, Verdict: "error", Reason: "triage failed: " + err.Error(), Action: "escalate"})
			}
			continue
		}
		out = append(out, res...)
	}
	return out, nil
}

func (t *Triager) batch(ctx context.Context, batch []store.Finding) ([]Outcome, error) {
	profile := t.Store.Get("profile_summary")
	if profile == "" {
		profile = "(no profile yet — the learning agent has not written one)"
	}
	type view struct {
		ID        int64             `json:"id"`
		Rule      string            `json:"rule"`
		Severity  string            `json:"severity"`
		Title     string            `json:"title"`
		ItemKey   string            `json:"item_key,omitempty"`
		Protected bool              `json:"protected"`
		Seen      int               `json:"times_seen"`
		Evidence  map[string]string `json:"evidence"`
		Context   map[string]string `json:"context,omitempty"`
	}
	recent := t.Store.Get("recent_auth_events")
	if recent == "" {
		recent = "[]"
	}
	views := make([]view, 0, len(batch))
	for _, f := range batch {
		ev := map[string]string{}
		for k, v := range f.Evidence {
			if k == "protected" {
				continue
			}
			if len(v) > 400 {
				v = v[:400] + "…"
			}
			ev[k] = v
		}
		key := ""
		if f.ItemID != "" {
			key = f.ItemID[strings.Index(f.ItemID, "|")+1:]
		}
		views = append(views, view{ID: f.ID, Rule: f.Rule, Severity: f.Severity, Title: f.Title, ItemKey: key, Protected: f.Evidence["protected"] == "true", Seen: f.Occurrences, Evidence: ev, Context: t.enrich(f, key)})
	}
	data, _ := json.MarshalIndent(views, "", " ")
	// The system prompt and profile come first and are identical between
	// calls, so the provider's prompt cache absorbs most input tokens.
	msgs := []llm.Message{
		{Role: "system", Content: blue.TriagePrompt},
		{Role: "user", Content: "SERVER PROFILE:\n" + profile + "\n\nRECENT AUTH/SUDO EVENTS (last 2h, untrusted):\n" + recent + "\n\nFINDINGS (untrusted host data):\n" + string(data)},
	}
	zero := 0.0
	var parsed struct {
		Results []result `json:"results"`
	}
	// One retry: a reasoning model occasionally returns an empty or cut-off
	// reply. A second cheap call beats escalating a whole batch blind. No
	// max_tokens is sent: a cap cuts reasoning models off before the answer.
	var lastReply string
	for attempt := 0; ; attempt++ {
		resp, err := t.Client.Chat(ctx, llm.Request{Model: t.Model, Messages: msgs, Temperature: &zero, PromptCacheKey: "kodeblue-triage"})
		if err != nil {
			return nil, err
		}
		t.Store.Spend("triage", t.Model, resp.Usage.PromptTokens, resp.Usage.CompletionTokens, resp.Usage.CachedTokens, resp.Usage.CostUSD)
		raw := llm.ExtractJSON(resp.Content)
		if raw == "" && strings.TrimSpace(resp.Content) == "" {
			raw = llm.ExtractJSON(resp.Reasoning) // answer left in the reasoning channel
		}
		if raw != "" && json.Unmarshal([]byte(raw), &parsed) == nil && len(parsed.Results) > 0 {
			break
		}
		lastReply = fmt.Sprintf("finish=%s content=%.200q", resp.FinishReason, resp.Content)
		if attempt >= 1 {
			return nil, fmt.Errorf("unparseable triage reply (%s)", lastReply)
		}
	}
	byID := map[int64]result{}
	for _, r := range parsed.Results {
		byID[r.ID] = r
	}
	var out []Outcome
	for i := range batch {
		f := batch[i]
		r, ok := byID[f.ID]
		if !ok {
			out = append(out, Outcome{Finding: &f, Verdict: "error", Reason: "model returned no verdict", Action: "escalate"})
			_ = t.Store.SetFindingStatus(f.ID, "escalated", "error", "model returned no verdict", 0)
			continue
		}
		o := Outcome{Finding: &f, Verdict: r.Verdict, Confidence: r.Confidence, Reason: r.Reason}
		protected := f.Evidence["protected"] == "true"
		switch {
		case r.Verdict == "benign" && !protected && r.Confidence >= t.AutoAcceptConfidence:
			o.Action = "absorbed"
			t.absorb(f, r)
			_ = t.Store.SetFindingStatus(f.ID, "benign", "benign", fmt.Sprintf("triage %.2f: %s", r.Confidence, r.Reason), 0)
		case r.Verdict == "benign":
			o.Action = "needs_ack"
			_ = t.Store.SetFindingStatus(f.ID, "needs_ack", "benign", fmt.Sprintf("triage %.2f: %s", r.Confidence, r.Reason), 0)
		default:
			o.Action = "escalate"
			_ = t.Store.SetFindingStatus(f.ID, "escalated", r.Verdict, fmt.Sprintf("triage %.2f: %s", r.Confidence, r.Reason), 0)
		}
		out = append(out, o)
	}
	return out, nil
}

// absorb accepts a benign finding: its item joins the baseline, and a narrow
// allow rule is recorded when the model proposed a valid one. Both are
// journaled (the allow rule by AddAllowRule), so the reviewer sees what
// triage let through.
func (t *Triager) absorb(f store.Finding, r result) {
	t.Store.Journal("triage", "absorb", fmt.Sprintf("finding #%d %s (%s, benign %.2f): %s", f.ID, f.Title, f.Rule, r.Confidence, r.Reason))
	if f.ItemID != "" {
		parts := strings.SplitN(f.ItemID, "|", 2)
		if len(parts) == 2 {
			_ = t.Store.UpsertBaseline([]store.BaselineItem{{ID: f.ItemID, Collector: parts[0], Key: parts[1], Value: f.Value, Note: "triage: " + r.Reason}}, "triage")
		}
	}
	if r.Allow == nil || f.ItemID == "" {
		return
	}
	parts := strings.SplitN(f.ItemID, "|", 2)
	if len(parts) != 2 {
		return
	}
	p := strings.TrimSpace(r.Allow.KeyPattern)
	// Narrowness guard: must match this item and stay narrow (a literal
	// anchor and file name, never a whole directory). The model saw
	// attacker-controlled content (content_preview), so a proposed rule is
	// untrusted input.
	if err := detect.CheckAllowPattern(t.Env, p); err != nil || !detect.Glob(p, parts[1]) {
		why := "does not match the item"
		if err != nil {
			why = err.Error()
		}
		t.Store.Journal("triage", "allow_rule.rejected", fmt.Sprintf("finding #%d pattern %q rejected: %s", f.ID, p, why))
		return
	}
	_ = t.Store.AddAllowRule(&store.AllowRule{Collector: parts[0], KeyPattern: p, Rule: f.Rule, Reason: r.Allow.Reason, CreatedBy: "triage", ExpiresAt: time.Now().Add(90 * 24 * time.Hour)})
}

// enrich adds cheap deterministic context (file age/owner) so the model is
// not guessing.
func (t *Triager) enrich(f store.Finding, key string) map[string]string {
	ctx := map[string]string{}
	path := key
	if i := strings.Index(path, "@"); i > 0 {
		path = path[:i]
	}
	if i := strings.Index(path, "->"); i > 0 {
		path = path[:i]
	}
	if strings.HasPrefix(path, "/") {
		if st, err := os.Stat(t.Env.Path(path)); err == nil {
			ctx["file_mtime"] = st.ModTime().UTC().Format(time.RFC3339)
			ctx["file_size"] = fmt.Sprint(st.Size())
			ctx["file_mode"] = st.Mode().String()
			if s, ok := st.Sys().(*syscall.Stat_t); ok {
				ctx["file_owner_uid"] = fmt.Sprint(s.Uid)
			}
		}
		// Small text persistence files are shown so the model can judge what
		// they run instead of escalating blind. Still untrusted data.
		if f.Collector == "persistence" || f.Collector == "tmp_exec" {
			if text, size, _, err := hostexec.ReadFile(t.Env.Path(path), 0, 1024); err == nil && size <= 4096 && utf8.ValidString(text) && !strings.ContainsRune(text, 0) {
				ctx["content_preview"] = text
			}
		}
		if pkg := t.Env.Pkg.Owner(path); pkg != "" {
			ctx["package_owner"] = pkg
		} else {
			ctx["package_owner"] = "none"
		}
	}
	if f.Collector != "" {
		// What the baseline already knows from the same collector and dir.
		dir := path
		if i := strings.LastIndex(dir, "/"); i > 0 {
			dir = dir[:i]
		}
		if dir != "" {
			var known []string
			for _, b := range t.Store.QueryBaseline(f.Collector, dir, 5) {
				known = append(known, b.Key)
			}
			if len(known) > 0 {
				ctx["known_similar"] = strings.Join(known, ", ")
			}
		}
	}
	return ctx
}
