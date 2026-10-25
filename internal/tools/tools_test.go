package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	internal "github.com/Problem99-io/kodeblue/internal"
)

func testConfig(t *testing.T) ToolConfig {
	t.Helper()
	return ToolConfig{
		ProjectRoot:    t.TempDir(),
		MaxOutputBytes: 65536,
	}
}

type registryTestTool struct {
	name internal.ToolName
}

func (t registryTestTool) Name() internal.ToolName { return t.name }

func (t registryTestTool) Description() string { return string(t.name) + " description" }

func (t registryTestTool) Parameters() json.RawMessage { return json.RawMessage(`{"type":"object"}`) }

func (t registryTestTool) Execute(context.Context, json.RawMessage) (*Result, error) {
	return &Result{Content: "ok"}, nil
}

func TestRegistryListReturnsSortedDefinitions(t *testing.T) {
	registry := NewRegistry()
	registry.Register(registryTestTool{name: "zeta"})
	registry.Register(registryTestTool{name: "alpha"})
	registry.Register(registryTestTool{name: "beta"})

	defs := registry.List()
	if len(defs) != 3 {
		t.Fatalf("expected 3 tool definitions, got %d", len(defs))
	}

	got := []internal.ToolName{defs[0].Name, defs[1].Name, defs[2].Name}
	want := []internal.ToolName{"alpha", "beta", "zeta"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("tool order = %v, want %v", got, want)
		}
	}
}

func TestReadFile(t *testing.T) {
	cfg := testConfig(t)
	tool := NewReadFile(cfg)

	content := "line1\nline2\nline3\n"
	testFile := filepath.Join(cfg.ProjectRoot, "test.txt")
	if err := os.WriteFile(testFile, []byte(content), 0o644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	args, _ := json.Marshal(map[string]string{"path": "test.txt"})
	result, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error result: %s", result.Content)
	}
	if !strings.Contains(result.Content, `<file path=`) {
		t.Fatalf("expected file wrapper, got %q", result.Content)
	}
	if !strings.Contains(result.Content, `total_lines=3`) {
		t.Fatalf("expected total_lines metadata in content, got %q", result.Content)
	}
	if !strings.Contains(result.Content, "line1\nline2\nline3\n") {
		t.Errorf("content missing raw file body: %q", result.Content)
	}
}

func TestDefinitionToolsCreatePatch(t *testing.T) {
	cfg := testConfig(t)
	if err := os.MkdirAll(filepath.Join(cfg.ProjectRoot, ".kodeblue"), 0o755); err != nil {
		t.Fatalf("ensure project kodeblue dir: %v", err)
	}

	create := NewCreateDefinition(cfg)
	patch := NewPatchDefinition(cfg)

	created, err := create.Execute(context.Background(), mustJSON(t, map[string]any{
		"title":     "Billing",
		"snippet":   "Handles billing flows and invoice constraints.",
		"content":   "Defines the billing flow and related constraints.",
		"important": true,
		"scope":     []string{"backend/src/routes/billing.ts", "backend/src/services/billing.ts"},
		"notes": []map[string]string{{
			"id":      "overview",
			"title":   "Overview",
			"content": "The route delegates to the billing service.",
		}},
		"rules": []map[string]string{{
			"id":      "currency",
			"title":   "Currency",
			"content": "Amounts must stay in cents.",
		}},
	}))
	if err != nil {
		t.Fatalf("create definition: %v", err)
	}
	if created.IsError {
		t.Fatalf("create definition returned error: %s", created.Content)
	}
	createdID, ok := created.Metadata["definition_id"].(string)
	if !ok || createdID == "" {
		t.Fatal("expected created definition id")
	}

	patched, err := patch.Execute(context.Background(), mustJSON(t, map[string]any{
		"definition_id": createdID,
		"patchText": strings.Join([]string{
			"content: Defines billing routes, services, and invoice edge cases.",
			"add_scope: backend/src/lib/money.ts",
			"*** Add Note: edge-cases",
			"Title: Edge Cases",
			"Content: Refunds must preserve the original currency.",
			"*** Update Rule: currency",
			"Title: Currency",
			"Content: Store amounts in cents and never mix currencies in one invoice.",
		}, "\n"),
	}))
	if err != nil {
		t.Fatalf("patch definition: %v", err)
	}
	if patched.IsError {
		t.Fatalf("patch definition returned error: %s", patched.Content)
	}
	if !strings.Contains(patched.Content, "invoice edge cases") {
		t.Fatalf("expected patched definition to include updated content, got %s", patched.Content)
	}
	if !strings.Contains(created.Content, "- Important: yes") {
		t.Fatalf("expected created definition markdown to include important flag, got %s", created.Content)
	}
	if !strings.Contains(patched.Content, "backend/src/lib/money.ts") {
		t.Fatalf("expected patched definition to include added scope, got %s", patched.Content)
	}
	if !strings.Contains(patched.Content, "edge-cases") {
		t.Fatalf("expected patched definition to include new note, got %s", patched.Content)
	}
}

func TestReadDefinitionsReturnsMarkdown(t *testing.T) {
	cfg := testConfig(t)
	if err := os.MkdirAll(filepath.Join(cfg.ProjectRoot, ".kodeblue"), 0o755); err != nil {
		t.Fatalf("ensure project kodeblue dir: %v", err)
	}

	create := NewCreateDefinition(cfg)
	readTool := NewReadDefinitions(cfg)

	created, err := create.Execute(context.Background(), mustJSON(t, map[string]any{
		"title":     "Search",
		"snippet":   "File and content search helpers.",
		"content":   "Defines repository search helpers.",
		"important": true,
		"scope":     []string{"app/internal/tools/read_file.go", "app/internal/tools/grep_search.go"},
		"notes": []map[string]string{{
			"id":      "limits",
			"title":   "Limits",
			"content": "Reads should stay small to save tokens.",
		}},
	}))
	if err != nil {
		t.Fatalf("create definition: %v", err)
	}
	if created.IsError {
		t.Fatalf("create definition returned error: %s", created.Content)
	}

	result, err := readTool.Execute(context.Background(), mustJSON(t, map[string]any{}))
	if err != nil {
		t.Fatalf("read definitions: %v", err)
	}
	if result.IsError {
		t.Fatalf("read definitions returned error: %s", result.Content)
	}
	if !strings.Contains(result.Content, "# Definitions") {
		t.Fatalf("expected markdown heading, got %s", result.Content)
	}
	if !strings.Contains(result.Content, "## Search") {
		t.Fatalf("expected markdown definition heading, got %s", result.Content)
	}
	if !strings.Contains(result.Content, "- Important: yes") {
		t.Fatalf("expected markdown important marker, got %s", result.Content)
	}
	if !strings.Contains(result.Content, "### Notes") {
		t.Fatalf("expected markdown notes section, got %s", result.Content)
	}
	if strings.Contains(result.Content, `"title":`) {
		t.Fatalf("expected markdown instead of json, got %s", result.Content)
	}
}

func TestDefinitionToolsUseDefinitionsRootInsteadOfSessionCWD(t *testing.T) {
	projectRoot := t.TempDir()
	worktreeRoot := t.TempDir()
	cfg := testConfig(t)
	cfg.ProjectRoot = worktreeRoot
	cfg.DefinitionsRoot = projectRoot

	create := NewCreateDefinition(cfg)
	ctx := WithSessionCWD(context.Background(), worktreeRoot)
	created, err := create.Execute(ctx, mustJSON(t, map[string]any{
		"title":   "Shared Memory",
		"snippet": "Definitions are shared across task worktrees.",
		"content": "Definitions should persist at the owning project root, not inside isolated task worktrees.",
		"scope":   []string{"etc/nginx/sites-enabled/app.conf"},
	}))
	if err != nil {
		t.Fatalf("create definition: %v", err)
	}
	if created.IsError {
		t.Fatalf("create definition returned error: %s", created.Content)
	}

	definitionID, ok := created.Metadata["definition_id"].(string)
	if !ok || definitionID == "" {
		t.Fatal("expected created definition id")
	}
	if _, err := os.Stat(filepath.Join(projectRoot, ".kodeblue", "definitions", definitionID+".json")); err != nil {
		t.Fatalf("expected definition under project root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(worktreeRoot, ".kodeblue", "definitions", definitionID+".json")); !os.IsNotExist(err) {
		t.Fatalf("expected no definition under worktree root, stat err=%v", err)
	}
}

func TestReadFileLineRange(t *testing.T) {
	cfg := testConfig(t)
	tool := NewReadFile(cfg)

	content := "line1\nline2\nline3\nline4\nline5\n"
	testFile := filepath.Join(cfg.ProjectRoot, "test.txt")
	if err := os.WriteFile(testFile, []byte(content), 0o644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	args, _ := json.Marshal(map[string]any{
		"path":      "test.txt",
		"startLine": 2,
		"endLine":   4,
	})
	result, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error result: %s", result.Content)
	}

	lines := strings.Split(strings.TrimSpace(result.Content), "\n")
	if len(lines) != 5 {
		t.Fatalf("got %d lines, want 5", len(lines))
	}
	if !strings.Contains(lines[0], `start_line=2`) || !strings.Contains(lines[0], `end_line=4`) || !strings.Contains(lines[0], `total_lines=5`) || !strings.Contains(lines[0], `more_after="true"`) {
		t.Fatalf("unexpected header line %q", lines[0])
	}
	if !strings.HasPrefix(lines[1], "2:") {
		t.Errorf("first content line should start with '2:', got %q", lines[1])
	}
	if strings.TrimSpace(lines[len(lines)-1]) != "</file>" {
		t.Fatalf("expected closing file tag, got %q", lines[len(lines)-1])
	}
}

func TestReadFileRejectsOversizedExactRead(t *testing.T) {
	cfg := testConfig(t)
	cfg.MaxOutputBytes = 64
	tool := NewReadFile(cfg)

	testFile := filepath.Join(cfg.ProjectRoot, "large.txt")
	if err := os.WriteFile(testFile, []byte("line1\nline2\nline3\nline4\n"), 0o644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	args, _ := json.Marshal(map[string]string{"path": "large.txt"})
	result, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !result.IsError {
		t.Fatalf("expected oversized read to fail, got %#v", result)
	}
	if !strings.Contains(result.Content, "request a smaller line range") {
		t.Fatalf("expected exact-read guidance, got %q", result.Content)
	}
}

func TestReadFileRejectsMoreThan500Lines(t *testing.T) {
	cfg := testConfig(t)
	tool := NewReadFile(cfg)

	lines := make([]string, 501)
	for i := range lines {
		lines[i] = fmt.Sprintf("line%d", i+1)
	}
	testFile := filepath.Join(cfg.ProjectRoot, "large-lines.txt")
	if err := os.WriteFile(testFile, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	args, _ := json.Marshal(map[string]string{"path": "large-lines.txt"})
	result, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !result.IsError {
		t.Fatalf("expected line-limit read to fail, got %#v", result)
	}
	if !strings.Contains(result.Content, "maximum of 500 lines per call") {
		t.Fatalf("expected line-limit guidance, got %q", result.Content)
	}
}

func TestReadFileRejectsRangeOver500Lines(t *testing.T) {
	cfg := testConfig(t)
	tool := NewReadFile(cfg)

	lines := make([]string, 600)
	for i := range lines {
		lines[i] = fmt.Sprintf("line%d", i+1)
	}
	testFile := filepath.Join(cfg.ProjectRoot, "range-lines.txt")
	if err := os.WriteFile(testFile, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	args, _ := json.Marshal(map[string]any{"path": "range-lines.txt", "startLine": 1, "endLine": 501})
	result, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !result.IsError {
		t.Fatalf("expected oversized range to fail, got %#v", result)
	}
	if !strings.Contains(result.Content, "maximum of 500 lines per call") {
		t.Fatalf("expected line-limit guidance, got %q", result.Content)
	}
}

func TestReadFileRejectsStartLineBeyondEOF(t *testing.T) {
	cfg := testConfig(t)
	tool := NewReadFile(cfg)

	testFile := filepath.Join(cfg.ProjectRoot, "range.txt")
	if err := os.WriteFile(testFile, []byte("a\nb\n"), 0o644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	args, _ := json.Marshal(map[string]any{"path": "range.txt", "startLine": 10, "endLine": 12})
	result, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !result.IsError {
		t.Fatalf("expected out-of-range read to fail, got %#v", result)
	}
	if !strings.Contains(result.Content, "exceeds file length") {
		t.Fatalf("expected EOF guidance, got %q", result.Content)
	}
}

func TestReadFilePathTraversal(t *testing.T) {
	cfg := testConfig(t)
	tool := NewReadFile(cfg)

	args, _ := json.Marshal(map[string]string{"path": "../../etc/passwd"})
	result, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !result.IsError {
		t.Error("path traversal should result in error")
	}
}

func TestWriteFile(t *testing.T) {
	cfg := testConfig(t)
	tool := NewWriteFile(cfg)

	args, _ := json.Marshal(map[string]string{
		"path":    "new.txt",
		"content": "hello world",
	})
	result, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error: %s", result.Content)
	}

	data, err := os.ReadFile(filepath.Join(cfg.ProjectRoot, "new.txt"))
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(data) != "hello world" {
		t.Errorf("content = %q, want %q", string(data), "hello world")
	}
}

func TestWriteFileCreatesParentDirs(t *testing.T) {
	cfg := testConfig(t)
	tool := NewWriteFile(cfg)

	args, _ := json.Marshal(map[string]string{
		"path":    "sub/dir/file.txt",
		"content": "deep",
	})
	result, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error: %s", result.Content)
	}

	data, err := os.ReadFile(filepath.Join(cfg.ProjectRoot, "sub", "dir", "file.txt"))
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(data) != "deep" {
		t.Errorf("content = %q, want %q", string(data), "deep")
	}
}

func TestWriteFileRefusesOverwriteByDefault(t *testing.T) {
	cfg := testConfig(t)
	tool := NewWriteFile(cfg)

	target := filepath.Join(cfg.ProjectRoot, "existing.txt")
	if err := os.WriteFile(target, []byte("old"), 0o644); err != nil {
		t.Fatalf("write seed file: %v", err)
	}

	args, _ := json.Marshal(map[string]string{"path": "existing.txt", "content": "new"})
	result, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !result.IsError {
		t.Fatalf("expected overwrite refusal, got %#v", result)
	}
	if !strings.Contains(result.Content, "refusing to overwrite existing file") {
		t.Fatalf("expected overwrite refusal message, got %q", result.Content)
	}
}

func TestWriteFileAllowsExplicitOverwrite(t *testing.T) {
	cfg := testConfig(t)
	tool := NewWriteFile(cfg)

	target := filepath.Join(cfg.ProjectRoot, "existing.txt")
	if err := os.WriteFile(target, []byte("old"), 0o644); err != nil {
		t.Fatalf("write seed file: %v", err)
	}

	args, _ := json.Marshal(map[string]any{"path": "existing.txt", "content": "new", "overwrite": true})
	result, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error: %s", result.Content)
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(data) != "new" {
		t.Fatalf("content = %q, want %q", string(data), "new")
	}
}

func TestWriteFileOutsideRoot(t *testing.T) {
	cfg := testConfig(t)
	tool := NewWriteFile(cfg)

	args, _ := json.Marshal(map[string]string{
		"path":    "../../escape.txt",
		"content": "bad",
	})
	result, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !result.IsError {
		t.Error("write outside root should result in error")
	}
}

func TestListDir(t *testing.T) {
	cfg := testConfig(t)
	tool := NewListDir(cfg)

	os.WriteFile(filepath.Join(cfg.ProjectRoot, "file1.txt"), []byte("a"), 0o644)
	os.WriteFile(filepath.Join(cfg.ProjectRoot, "file2.go"), []byte("b"), 0o644)
	os.MkdirAll(filepath.Join(cfg.ProjectRoot, "subdir"), 0o755)

	args, _ := json.Marshal(map[string]string{"path": "."})
	result, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error: %s", result.Content)
	}

	if !strings.Contains(result.Content, "file1.txt") {
		t.Error("should contain file1.txt")
	}
	if !strings.Contains(result.Content, "file2.go") {
		t.Error("should contain file2.go")
	}
	if !strings.Contains(result.Content, "subdir/") {
		t.Error("should contain subdir/")
	}
}

func mustJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal json: %v", err)
	}
	return data
}

func TestAskUserSingleAndBatch(t *testing.T) {
	var seenPrompts []AskUserPrompt
	handler := func(_ context.Context, prompts []AskUserPrompt) ([]internal.QuestionAnswer, error) {
		seenPrompts = append(seenPrompts, prompts...)
		answers := make([]internal.QuestionAnswer, 0, len(prompts))
		for i := range prompts {
			prompt := prompts[i]
			ans := internal.QuestionAnswer{
				Mode:       prompt.Mode,
				AnsweredAt: time.Now(),
			}
			switch prompt.Mode {
			case QuestionModeSingle:
				if len(prompt.Options) > 0 {
					ans.Choices = []string{prompt.Options[0]}
				}
			case QuestionModeMulti:
				ans.Choices = prompt.Options
			}
			answers = append(answers, ans)
		}
		return answers, nil
	}

	tool := NewAskUser(handler)
	ctx := WithExecutionContext(context.Background(), "sess_test", "run_test")

	// Backward-compatible single-question payload.
	singleArgs, _ := json.Marshal(map[string]any{
		"question": "Pick one",
		"mode":     "single_select",
		"options":  []string{"A", "B", "C"},
	})
	singleResult, err := tool.Execute(ctx, singleArgs)
	if err != nil {
		t.Fatalf("Execute(single): %v", err)
	}
	if singleResult.IsError {
		t.Fatalf("single result unexpected error: %s", singleResult.Content)
	}
	var singleAnswer internal.QuestionAnswer
	if err := json.Unmarshal([]byte(singleResult.Content), &singleAnswer); err != nil {
		t.Fatalf("unmarshal single answer: %v", err)
	}
	if len(singleAnswer.Choices) != 1 || singleAnswer.Choices[0] != "A" {
		t.Fatalf("unexpected single answer: %+v", singleAnswer)
	}
	if len(seenPrompts) == 0 || !seenPrompts[0].Custom {
		t.Fatalf("expected single ask_user prompt to enable custom answers, got %+v", seenPrompts)
	}

	// Batch questions payload.
	batchArgs, _ := json.Marshal(map[string]any{
		"questions": []map[string]any{
			{"question": "Pick one", "mode": "single_select", "options": []string{"X", "Y", "Z"}},
			{"question": "Pick many", "mode": "multi_select", "options": []string{"m1", "m2", "m3"}},
		},
	})
	batchResult, err := tool.Execute(ctx, batchArgs)
	if err != nil {
		t.Fatalf("Execute(batch): %v", err)
	}
	if batchResult.IsError {
		t.Fatalf("batch result unexpected error: %s", batchResult.Content)
	}
	var batchOut struct {
		Answers []internal.QuestionAnswer `json:"answers"`
	}
	if err := json.Unmarshal([]byte(batchResult.Content), &batchOut); err != nil {
		t.Fatalf("unmarshal batch answers: %v", err)
	}
	if len(batchOut.Answers) != 2 {
		t.Fatalf("expected 2 answers, got %d", len(batchOut.Answers))
	}
	if batchOut.Answers[0].Mode != QuestionModeSingle {
		t.Fatalf("unexpected mode for answer 0: %s", batchOut.Answers[0].Mode)
	}
	if batchOut.Answers[1].Mode != QuestionModeMulti {
		t.Fatalf("unexpected mode for answer 1: %s", batchOut.Answers[1].Mode)
	}
	if len(seenPrompts) < 3 || !seenPrompts[1].Custom || !seenPrompts[2].Custom {
		t.Fatalf("expected batch ask_user prompts to enable custom answers, got %+v", seenPrompts)
	}
}

func TestAskUserRejectsTooFewOptions(t *testing.T) {
	tool := NewAskUser(func(_ context.Context, prompts []AskUserPrompt) ([]internal.QuestionAnswer, error) {
		return make([]internal.QuestionAnswer, len(prompts)), nil
	})
	ctx := WithExecutionContext(context.Background(), "sess_test", "run_test")

	args, _ := json.Marshal(map[string]any{
		"question": "Pick one",
		"mode":     "single_select",
		"options":  []string{"Only one"},
	})
	result, err := tool.Execute(ctx, args)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !result.IsError {
		t.Fatalf("expected too-few-options error, got %#v", result)
	}
	if !strings.Contains(result.Content, "at least 2 options") {
		t.Fatalf("unexpected error: %s", result.Content)
	}
}

func TestAskUserAcceptsTwoOptions(t *testing.T) {
	tool := NewAskUser(func(_ context.Context, prompts []AskUserPrompt) ([]internal.QuestionAnswer, error) {
		return make([]internal.QuestionAnswer, len(prompts)), nil
	})
	ctx := WithExecutionContext(context.Background(), "sess_test", "run_test")

	args, _ := json.Marshal(map[string]any{
		"question": "Hash passwords?",
		"mode":     "single_select",
		"options":  []string{"bcrypt hashed", "plain text"},
	})
	result, err := tool.Execute(ctx, args)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected two options to be accepted, got error: %s", result.Content)
	}
}

func TestAskUserAcceptsLabelAsKeyOptions(t *testing.T) {
	var seen []AskUserPrompt
	tool := NewAskUser(func(_ context.Context, prompts []AskUserPrompt) ([]internal.QuestionAnswer, error) {
		seen = prompts
		return make([]internal.QuestionAnswer, len(prompts)), nil
	})
	ctx := WithExecutionContext(context.Background(), "sess_test", "run_test")

	// The {"<label>": ""} shape models frequently emit must be accepted.
	args := []byte(`{"question":"Which DB?","mode":"single_select","options":[{"SQLite":""},{"Postgres":""},{"MySQL":""}]}`)
	result, err := tool.Execute(ctx, args)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected label-as-key options to be accepted, got error: %s", result.Content)
	}
	if len(seen) != 1 || len(seen[0].Options) != 3 || seen[0].Options[0] != "SQLite" || seen[0].Options[2] != "MySQL" {
		t.Fatalf("unexpected parsed options: %#v", seen)
	}
}

func TestAskUserReportsNestedQuestionOptionsClearly(t *testing.T) {
	tool := NewAskUser(func(_ context.Context, prompts []AskUserPrompt) ([]internal.QuestionAnswer, error) {
		return make([]internal.QuestionAnswer, len(prompts)), nil
	})
	ctx := WithExecutionContext(context.Background(), "sess_test", "run_test")

	args, _ := json.Marshal(map[string]any{
		"question": "Pick one",
		"mode":     "single_select",
		"options": []map[string]any{
			{"value": "stub-then-wire"},
			{"mode": "single_select", "options": []string{"A", "B", "C"}},
		},
	})
	result, err := tool.Execute(ctx, args)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !result.IsError {
		t.Fatalf("expected nested-options error, got %#v", result)
	}
	if !strings.Contains(result.Content, "options[1] must be a plain string label") || !strings.Contains(result.Content, "top-level questions array") {
		t.Fatalf("unexpected error: %s", result.Content)
	}
}

func TestReadFileBatch(t *testing.T) {
	cfg := testConfig(t)
	tool := NewReadFile(cfg)

	if err := os.WriteFile(filepath.Join(cfg.ProjectRoot, "a.txt"), []byte("alpha\n"), 0o644); err != nil {
		t.Fatalf("seed a: %v", err)
	}
	if err := os.WriteFile(filepath.Join(cfg.ProjectRoot, "b.txt"), []byte("beta\n"), 0o644); err != nil {
		t.Fatalf("seed b: %v", err)
	}

	args, _ := json.Marshal(map[string]any{
		"reads": []map[string]any{
			{"path": "a.txt"},
			{"path": "missing.txt"},
			{"path": "b.txt"},
		},
	})
	result, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !result.IsError {
		t.Fatalf("expected IsError because one read failed")
	}
	if !strings.Contains(result.Content, "alpha") || !strings.Contains(result.Content, "beta") {
		t.Fatalf("expected both successful reads in output, got: %s", result.Content)
	}
	if !strings.Contains(result.Content, "missing.txt") {
		t.Fatalf("expected the failing read to be reported, got: %s", result.Content)
	}
	if got := result.Metadata["parallelism"]; got != 3 {
		t.Fatalf("batch parallelism = %#v, want 3", got)
	}
	if got := result.Metadata["parallelized_reads"]; got != 2 {
		t.Fatalf("parallelized reads = %#v, want 2", got)
	}
	// Output must remain in request order even when reads complete concurrently.
	alpha := strings.Index(result.Content, "alpha")
	missing := strings.Index(result.Content, "missing.txt")
	beta := strings.Index(result.Content, "beta")
	if alpha < 0 || missing < alpha || beta < missing {
		t.Fatalf("batch output order is not deterministic: %s", result.Content)
	}
}

func TestReadFileBatchConcurrencyIsBounded(t *testing.T) {
	cfg := testConfig(t)
	tool := NewReadFile(cfg)
	reads := make([]map[string]any, 0, readFileBatchConcurrency+3)
	for i := 0; i < readFileBatchConcurrency+3; i++ {
		name := fmt.Sprintf("batch-%d.txt", i)
		if err := os.WriteFile(filepath.Join(cfg.ProjectRoot, name), []byte(name+"\n"), 0o644); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
		reads = append(reads, map[string]any{"path": name})
	}

	args, _ := json.Marshal(map[string]any{"reads": reads})
	result, err := tool.Execute(context.Background(), args)
	if err != nil || result.IsError {
		t.Fatalf("Execute = %#v, %v", result, err)
	}
	if got := result.Metadata["parallelism"]; got != readFileBatchConcurrency {
		t.Fatalf("batch parallelism = %#v, want cap %d", got, readFileBatchConcurrency)
	}
	if got := result.Metadata["parallelized_reads"]; got != len(reads)-1 {
		t.Fatalf("parallelized reads = %#v, want %d", got, len(reads)-1)
	}
	for i := 0; i < len(reads)-1; i++ {
		left := strings.Index(result.Content, fmt.Sprintf("batch-%d.txt", i))
		right := strings.Index(result.Content, fmt.Sprintf("batch-%d.txt", i+1))
		if left < 0 || right < left {
			t.Fatalf("expected read %d before read %d in deterministic output: %s", i, i+1, result.Content)
		}
	}
}

func TestWriteFileBatchPartialSuccess(t *testing.T) {
	cfg := testConfig(t)
	tool := NewWriteFile(cfg)

	// b.txt already exists and is written without overwrite -> must fail,
	// while a.txt and c.txt should still be created.
	if err := os.WriteFile(filepath.Join(cfg.ProjectRoot, "b.txt"), []byte("old"), 0o644); err != nil {
		t.Fatalf("seed b: %v", err)
	}

	args, _ := json.Marshal(map[string]any{
		"writes": []map[string]any{
			{"path": "a.txt", "content": "A"},
			{"path": "b.txt", "content": "B"},
			{"path": "c.txt", "content": "C"},
		},
	})
	result, err := tool.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !result.IsError {
		t.Fatalf("expected IsError because one write failed")
	}

	if data, _ := os.ReadFile(filepath.Join(cfg.ProjectRoot, "a.txt")); string(data) != "A" {
		t.Fatalf("a.txt should have been written, got %q", string(data))
	}
	if data, _ := os.ReadFile(filepath.Join(cfg.ProjectRoot, "c.txt")); string(data) != "C" {
		t.Fatalf("c.txt should have been written, got %q", string(data))
	}
	if data, _ := os.ReadFile(filepath.Join(cfg.ProjectRoot, "b.txt")); string(data) != "old" {
		t.Fatalf("b.txt should be untouched, got %q", string(data))
	}

	if !strings.Contains(result.Content, "2 of 3 succeeded, 1 failed") {
		t.Fatalf("expected partial-success summary, got: %s", result.Content)
	}
	if result.Metadata["succeeded"] != 2 || result.Metadata["failed"] != 1 {
		t.Fatalf("unexpected counts: %#v", result.Metadata)
	}
}
