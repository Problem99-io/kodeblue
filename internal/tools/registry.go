package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"

	internal "github.com/Problem99-io/kodeblue/internal"
)

// Tool is the interface all tools implement.
type Tool interface {
	Name() internal.ToolName
	Description() string
	Parameters() json.RawMessage
	Execute(ctx context.Context, args json.RawMessage) (*Result, error)
}

// Result is returned by tool execution.
type Result struct {
	Content     string
	IsError     bool
	Metadata    map[string]any        // Structured data for UI consumption (optional)
	Attachments []internal.Attachment // Transient images for model inspection.
}

// Registry manages available tools.
type Registry struct {
	mu    sync.RWMutex
	tools map[internal.ToolName]Tool
}

// NewRegistry creates an empty tool registry.
func NewRegistry() *Registry {
	return &Registry{tools: make(map[internal.ToolName]Tool)}
}

// Register adds a tool to the registry.
func (r *Registry) Register(t Tool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tools[internal.CanonicalToolName(t.Name())] = t
}

// Get retrieves a tool by name.
func (r *Registry) Get(name internal.ToolName) (Tool, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tools[internal.CanonicalToolName(name)]
	return t, ok
}

// List returns definitions for all registered tools.
func (r *Registry) List() []internal.ToolDefinition {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.tools))
	for name := range r.tools {
		names = append(names, string(name))
	}
	sort.Strings(names)

	defs := make([]internal.ToolDefinition, 0, len(names))
	for _, name := range names {
		t := r.tools[internal.ToolName(name)]
		defs = append(defs, internal.ToolDefinition{
			Name:        t.Name(),
			Description: t.Description(),
			Parameters:  t.Parameters(),
		})
	}
	return defs
}

// Execute runs a tool by name with the given arguments.
func (r *Registry) Execute(ctx context.Context, name internal.ToolName, args json.RawMessage) (result *Result, err error) {
	defer func() {
		if value := recover(); value != nil {
			result = &Result{Content: "tool execution panicked", IsError: true, Metadata: map[string]any{"category": "panic"}}
			err = errors.New("tool execution panicked")
		}
		if err == nil && result == nil {
			err = errors.New("tool returned no result")
			result = &Result{Content: err.Error(), IsError: true}
		}
	}()
	if allowed, ok := AllowedToolsFromContext(ctx); ok && !allowed[internal.CanonicalToolNameString(string(name))] {
		return &Result{Content: "tool not allowed for this run", IsError: true, Metadata: map[string]any{"category": "guard_denied"}}, nil
	}
	t, ok := r.Get(name)
	if !ok {
		return &Result{Content: fmt.Sprintf("unknown tool: %s", name), IsError: true}, nil
	}
	return t.Execute(ctx, args)
}
