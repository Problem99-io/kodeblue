package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/Problem99-io/kodeblue/blue"
	internal "github.com/Problem99-io/kodeblue/internal"
	"github.com/Problem99-io/kodeblue/internal/logging"
	"github.com/Problem99-io/kodeblue/internal/policy"
)

// Every built-in tool the engine registers is one a kodeblue agent can call,
// and every built-in tool an agent names exists. ask_user is the exception:
// the engine answers it on the operator's behalf and no agent lists it.
func TestBuiltinToolsMatchAgentAllowlists(t *testing.T) {
	cfg := policy.DefaultConfig()
	cfg.Skills.Enabled = true
	root := t.TempDir()
	registry, _ := buildToolRegistry(cfg, root, root, nil, logging.NewLogger(slog.LevelError, false))
	registered := map[string]bool{}
	for _, def := range registry.List() {
		registered[string(def.Name)] = true
	}

	agents, err := blue.Agents()
	if err != nil {
		t.Fatal(err)
	}
	used := map[string]bool{"ask_user": true}
	for _, a := range agents {
		for _, name := range a.Tools {
			if strings.HasPrefix(name, "mcp__") {
				continue
			}
			used[name] = true
			if !registered[name] {
				t.Errorf("agent %s names %q, which the engine does not register", a.Name, name)
			}
		}
	}
	var unused []string
	for name := range registered {
		if !used[name] {
			unused = append(unused, name)
		}
	}
	sort.Strings(unused)
	if len(unused) > 0 {
		t.Errorf("registered tools no agent can call: %v", unused)
	}
	for _, removed := range []string{"edit_file", "grep", "grep_search", "delete_definition"} {
		if registered[removed] {
			t.Errorf("%s is still registered", removed)
		}
	}
}

// The patch that once slipped past the path guard (a lone \r hid the second
// target from its line scanner) reaches no tool at all now.
func TestRemovedPatchToolCannotWrite(t *testing.T) {
	cfg := policy.DefaultConfig()
	root := t.TempDir()
	registry, _ := buildToolRegistry(cfg, root, root, nil, logging.NewLogger(slog.LevelError, false))
	args, _ := json.Marshal(map[string]string{
		"patchText": "*** Begin Patch\n*** Add File: a.txt\r*** Add File: denied/x.txt\n+x\n*** End Patch",
	})
	res, err := registry.Execute(context.Background(), internal.ToolName("edit_file"), args)
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(res.Content, "unknown tool") {
		t.Fatalf("edit_file result = %#v, want unknown tool", res)
	}
	for _, p := range []string{"a.txt", "denied/x.txt"} {
		if _, err := os.Stat(filepath.Join(root, p)); !os.IsNotExist(err) {
			t.Fatalf("%s exists after the call (err=%v)", p, err)
		}
	}
}
