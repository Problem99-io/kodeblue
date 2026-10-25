package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/hostexec"
	"github.com/Problem99-io/kodeblue/internal/blue/sensors"
)

func (s *Server) hostExec(ctx context.Context, args json.RawMessage) (string, error) {
	var a struct {
		Argv   []string `json:"argv"`
		Reason string   `json:"reason"`
	}
	if err := decode(args, &a); err != nil {
		return "", err
	}
	res, err := hostexec.Run(ctx, a.Argv, 30*time.Second, 24*1024)
	if err != nil {
		return "", err
	}
	out := fmt.Sprintf("exit=%d%s\n%s", res.ExitCode, map[bool]string{true: " (output truncated)", false: ""}[res.Truncated], res.Stdout)
	if res.Stderr != "" {
		out += "\n[stderr]\n" + res.Stderr
	}
	if res.TimedOut {
		out += "\n[timed out]"
	}
	return out + untrusted, nil
}

func (s *Server) hostRead(ctx context.Context, args json.RawMessage) (string, error) {
	var a struct {
		Path     string `json:"path"`
		Offset   int64  `json:"offset"`
		MaxBytes int    `json:"max_bytes"`
	}
	if err := decode(args, &a); err != nil {
		return "", err
	}
	if a.MaxBytes == 0 {
		a.MaxBytes = 16384
	}
	text, size, more, err := hostexec.ReadFile(s.env.Path(a.Path), a.Offset, a.MaxBytes)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("[%s: %d bytes total, more=%v]\n%s%s", a.Path, size, more, text, untrusted), nil
}

func (s *Server) hostList(ctx context.Context, args json.RawMessage) (string, error) {
	var a struct {
		Path string `json:"path"`
	}
	if err := decode(args, &a); err != nil {
		return "", err
	}
	if !filepath.IsAbs(a.Path) {
		return "", errors.New("path must be absolute")
	}
	entries, err := os.ReadDir(s.env.Path(a.Path))
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for i, e := range entries {
		if i >= 500 {
			fmt.Fprintf(&b, "… %d more\n", len(entries)-500)
			break
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		uid := ""
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			uid = fmt.Sprint(st.Uid)
		}
		fmt.Fprintf(&b, "%s uid=%s %9d %s %s\n", info.Mode(), uid, info.Size(), info.ModTime().UTC().Format("2006-01-02T15:04"), e.Name())
	}
	return b.String() + untrusted, nil
}

func (s *Server) snapshot(ctx context.Context, args json.RawMessage) (string, error) {
	var a struct {
		Collector string `json:"collector"`
		Contains  string `json:"contains"`
		Limit     int    `json:"limit"`
	}
	if err := decode(args, &a); err != nil {
		return "", err
	}
	if a.Limit <= 0 {
		a.Limit = 100
	}
	if a.Collector == "auth" {
		return "", errors.New("auth is an event stream; use host_exec journalctl or host_read on the auth log")
	}
	extra := s.extraIntegrity()
	reg := sensors.NewRegistry([]string{a.Collector}, extra)
	if len(reg.Names()) == 0 {
		return "", fmt.Errorf("unknown collector %q", a.Collector)
	}
	snap := reg.Sweep(ctx, s.env, true)
	if e := snap.Errors[a.Collector]; e != "" {
		return "", errors.New(e)
	}
	var items []sensors.Item
	for _, it := range snap.Items {
		if a.Contains == "" || strings.Contains(it.Key, a.Contains) {
			items = append(items, it)
		}
	}
	total := len(items)
	if len(items) > a.Limit {
		items = items[:a.Limit]
	}
	return fmt.Sprintf("%d items (showing %d)\n%s%s", total, len(items), jsonOut(items), untrusted), nil
}

func (s *Server) extraIntegrity() []string {
	var learned []string
	_ = json.Unmarshal([]byte(s.st.Get("extra_integrity_paths")), &learned)
	return s.cfg.IntegrityPaths(learned) // the same list the daemon watches
}

func (s *Server) baselineQuery(ctx context.Context, args json.RawMessage) (string, error) {
	var a struct {
		Collector string `json:"collector"`
		Contains  string `json:"contains"`
		Limit     int    `json:"limit"`
	}
	if err := decode(args, &a); err != nil {
		return "", err
	}
	if a.Limit <= 0 {
		a.Limit = 100
	}
	items := s.st.QueryBaseline(a.Collector, a.Contains, a.Limit)
	return fmt.Sprintf("counts per collector: %s\n%s%s", jsonOut(s.st.BaselineCounts()), jsonOut(items), untrusted), nil
}
