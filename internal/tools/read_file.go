package tools

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	internal "github.com/Problem99-io/kodeblue/internal"
)

type readFileTool struct {
	cfg ToolConfig
}

const readFileMaxLinesPerCall = 500

// readFileBatchConcurrency is intentionally small. A batch contains independent,
// read-only filesystem operations, so parallel reads reduce wall-clock time without
// changing the workspace. Keeping the bound low avoids turning one model tool call
// into an unbounded file-descriptor or disk-I/O fan-out.
const readFileBatchConcurrency = 4

// NewReadFile creates a read_file tool.
func NewReadFile(cfg ToolConfig) Tool {
	return &readFileTool{cfg: cfg}
}

func (t *readFileTool) Name() internal.ToolName { return "read_file" }

func (t *readFileTool) Description() string {
	return "Read the exact contents of a file. Hard limit: this tool reads at most 500 lines per call. Optionally specify startLine and endLine (1-based) to read an exact line range; if you omit them, the whole file is only returned when it is 500 lines or fewer. If the requested file or range exceeds the line or output limit, the tool returns an error instead of truncating; request a smaller range rather than using partial output as a source of truth for edits. To read several files, or several ranges of the same file, in one call, pass a reads array; each entry is read independently and the results are returned together in order."
}

// readRequest is a single read operation, usable on its own (path/startLine/endLine
// at the top level) or as one element of the batch reads array.
type readRequest struct {
	Path      string `json:"path"`
	StartLine int    `json:"startLine"`
	EndLine   int    `json:"endLine"`
}

func (t *readFileTool) Parameters() json.RawMessage {
	return makeSchema(map[string]any{
		"path":      map[string]any{"type": "string", "description": "File path relative to the active workspace/session root or an allowed absolute path. Omit when using reads."},
		"startLine": map[string]any{"type": "integer", "description": "Start line (1-based, inclusive)"},
		"endLine":   map[string]any{"type": "integer", "description": "End line (1-based, inclusive)"},
		"reads": map[string]any{
			"type":        "array",
			"description": "Optional batch mode: a list of independent read operations executed in one call. Use this to read multiple files, or multiple ranges of the same file, at once. When provided, the top-level path/startLine/endLine are ignored. Each read is reported separately so one failing read does not discard the others.",
			"items": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path":      map[string]any{"type": "string", "description": "File path relative to the active workspace/session root or an allowed absolute path"},
					"startLine": map[string]any{"type": "integer", "description": "Start line (1-based, inclusive)"},
					"endLine":   map[string]any{"type": "integer", "description": "End line (1-based, inclusive)"},
				},
				"required": []string{"path"},
			},
		},
	}, nil)
}

func (t *readFileTool) Execute(ctx context.Context, args json.RawMessage) (*Result, error) {
	var params struct {
		readRequest
		Reads []readRequest `json:"reads"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return &Result{Content: "invalid arguments: " + err.Error(), IsError: true}, nil
	}

	if len(params.Reads) > 0 {
		return t.executeBatch(ctx, params.Reads), nil
	}
	if params.Path == "" {
		return &Result{Content: "path is required (or provide a non-empty reads array)", IsError: true}, nil
	}
	return t.readOne(ctx, params.readRequest), nil
}

// executeBatch runs independent reads with bounded concurrency and concatenates the
// results in request order. A failing read is reported inline and does not stop the
// remaining reads. Result ordering is deliberately deterministic even though the
// filesystem operations may complete in a different order.
func (t *readFileTool) executeBatch(ctx context.Context, reads []readRequest) *Result {
	results := make([]*Result, len(reads))
	parallelism := min(readFileBatchConcurrency, len(reads))
	if parallelism > 0 {
		jobs := make(chan int)
		var workers sync.WaitGroup
		for range parallelism {
			workers.Add(1)
			go func() {
				defer workers.Done()
				for index := range jobs {
					results[index] = t.readOne(ctx, reads[index])
				}
			}()
		}
		for index := range reads {
			jobs <- index
		}
		close(jobs)
		workers.Wait()
	}

	var builder strings.Builder
	entries := make([]map[string]any, 0, len(reads))
	anyError := false
	for i, r := range reads {
		res := results[i]
		if i > 0 {
			builder.WriteString("\n\n")
		}
		if res.IsError {
			anyError = true
			builder.WriteString(fmt.Sprintf("<read index=%d path=%q error=\"true\">\n%s\n</read>", i+1, r.Path, res.Content))
		} else {
			builder.WriteString(res.Content)
		}
		entry := map[string]any{"path": r.Path, "ok": !res.IsError}
		if res.IsError {
			entry["error"] = res.Content
		}
		if res.Metadata != nil {
			entry["detail"] = res.Metadata
		}
		entries = append(entries, entry)
	}
	return &Result{
		Content: builder.String(),
		IsError: anyError,
		Metadata: map[string]any{
			"tool":               "read_file",
			"batch":              true,
			"reads":              entries,
			"requested_reads":    len(reads),
			"parallelism":        parallelism,
			"parallelized_reads": max(0, len(reads)-1),
		},
	}
}

// readOne performs a single read (full file or line range) and returns its result.
func (t *readFileTool) readOne(ctx context.Context, r readRequest) *Result {
	absPath, err := validatePath(effectiveRoot(ctx, t.cfg), r.Path)
	if err != nil {
		return &Result{Content: err.Error(), IsError: true}
	}

	if r.StartLine > 0 || r.EndLine > 0 {
		res, _ := t.readRange(absPath, r.StartLine, r.EndLine)
		return res
	}

	data, err := os.ReadFile(absPath)
	if err != nil {
		return &Result{Content: "failed to read file: " + err.Error(), IsError: true}
	}

	totalLines := countFileLines(data)
	if totalLines > readFileMaxLinesPerCall {
		return &Result{Content: fmt.Sprintf("requested read for %s is %d lines, which exceeds the maximum of %d lines per call; request a smaller line range", absPath, totalLines, readFileMaxLinesPerCall), IsError: true}
	}
	content, err := formatExactReadContent(absPath, 1, totalLines, totalLines, false, false, string(data), t.cfg.MaxOutputBytes)
	if err != nil {
		return &Result{Content: err.Error(), IsError: true}
	}
	return &Result{
		Content: content,
		Metadata: map[string]any{
			"tool":       "read_file",
			"file":       absPath,
			"startLine":  1,
			"endLine":    totalLines,
			"totalLines": totalLines,
			"bytes":      len(data),
			"moreBefore": false,
			"moreAfter":  false,
		},
	}
}

func (t *readFileTool) readRange(path string, start, end int) (*Result, error) {
	if start <= 0 {
		start = 1
	}
	if end > 0 && end < start {
		return &Result{Content: "endLine must be >= startLine", IsError: true}, nil
	}
	if end > 0 && end-start+1 > readFileMaxLinesPerCall {
		return &Result{Content: fmt.Sprintf("requested line range %d-%d exceeds the maximum of %d lines per call; request a smaller range", start, end, readFileMaxLinesPerCall), IsError: true}, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return &Result{Content: "failed to open file: " + err.Error(), IsError: true}, nil
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	var lines []string
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		if lineNum < start {
			continue
		}
		if end > 0 && lineNum > end {
			continue
		}
		if len(lines) >= readFileMaxLinesPerCall {
			return &Result{Content: fmt.Sprintf("requested read for %s exceeds the maximum of %d lines per call; request a smaller line range", path, readFileMaxLinesPerCall), IsError: true}, nil
		}
		lines = append(lines, fmt.Sprintf("%d: %s", lineNum, scanner.Text()))
	}
	if err := scanner.Err(); err != nil {
		return &Result{Content: "error reading file: " + err.Error(), IsError: true}, nil
	}
	if lineNum == 0 {
		return &Result{Content: formatReadFileContent(path, 1, 0, 0, false, false, ""), Metadata: map[string]any{
			"tool":       "read_file",
			"file":       path,
			"startLine":  1,
			"endLine":    0,
			"totalLines": 0,
			"lines":      0,
			"moreBefore": false,
			"moreAfter":  false,
		}}, nil
	}
	if start > lineNum {
		return &Result{Content: fmt.Sprintf("startLine %d exceeds file length %d for %s; request a valid range", start, lineNum, path), IsError: true}, nil
	}

	actualEnd := 0
	if len(lines) > 0 {
		actualEnd = start + len(lines) - 1
	} else if lineNum > 0 && start <= lineNum {
		actualEnd = start - 1
	}
	moreBefore := start > 1
	moreAfter := actualEnd > 0 && actualEnd < lineNum
	content, err := formatExactReadContent(path, start, actualEnd, lineNum, moreBefore, moreAfter, strings.Join(lines, "\n"), t.cfg.MaxOutputBytes)
	if err != nil {
		return &Result{Content: err.Error(), IsError: true}, nil
	}
	return &Result{
		Content: content,
		Metadata: map[string]any{
			"tool":       "read_file",
			"file":       path,
			"startLine":  start,
			"endLine":    actualEnd,
			"totalLines": lineNum,
			"lines":      len(lines),
			"moreBefore": moreBefore,
			"moreAfter":  moreAfter,
		},
	}, nil
}

func countFileLines(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	count := bytes.Count(data, []byte{'\n'})
	if data[len(data)-1] != '\n' {
		count++
	}
	return count
}

func formatReadFileContent(path string, start, end, totalLines int, moreBefore, moreAfter bool, body string) string {
	if start <= 0 {
		start = 1
	}
	if end < 0 {
		end = 0
	}

	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("<file path=%q start_line=%d end_line=%d total_lines=%d more_before=%q more_after=%q>\n", path, start, end, totalLines, boolString(moreBefore), boolString(moreAfter)))
	builder.WriteString(body)
	if body != "" && !strings.HasSuffix(body, "\n") {
		builder.WriteString("\n")
	}
	builder.WriteString("</file>")
	return builder.String()
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func formatExactReadContent(path string, start, end, totalLines int, moreBefore, moreAfter bool, body string, maxBytes int64) (string, error) {
	content := formatReadFileContent(path, start, end, totalLines, moreBefore, moreAfter, body)
	if maxBytes > 0 && int64(len(content)) > maxBytes {
		return "", fmt.Errorf("requested read for %s is %d bytes, which exceeds the tool output limit of %d bytes; request a smaller line range", path, len(content), maxBytes)
	}
	return content, nil
}
