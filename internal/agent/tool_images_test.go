package agent

import (
	"context"
	"encoding/json"
	internal "github.com/Problem99-io/kodeblue/internal"
	"github.com/Problem99-io/kodeblue/internal/policy"
	"github.com/Problem99-io/kodeblue/internal/provider"
	"github.com/Problem99-io/kodeblue/internal/tools"
	"testing"
)

type imageTool struct{}

func (imageTool) Name() internal.ToolName     { return "capture_image" }
func (imageTool) Description() string         { return "image result test" }
func (imageTool) Parameters() json.RawMessage { return json.RawMessage(`{"type":"object"}`) }
func (imageTool) Execute(context.Context, json.RawMessage) (*tools.Result, error) {
	return &tools.Result{Content: "screenshot saved", Attachments: []internal.Attachment{{MediaType: "image/png", FileName: "capture.png", Data: "aW1n"}}}, nil
}

func TestLoopSendsToolImageToNextModelTurn(t *testing.T) {
	registry := tools.NewRegistry()
	registry.Register(imageTool{})
	am, err := policy.NewToolGuard(policy.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	mp := newMockProvider([][]provider.StreamEvent{toolCallResponse("call-image", "capture_image", `{}`), simpleTextResponse("I inspected the image.")})
	loop := NewLoop(registry, am, nil, nil)
	_, err = loop.Run(context.Background(), buildRunConfig(mp, registry.List()), "Inspect the image", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(mp.requests) != 2 {
		t.Fatalf("requests=%d", len(mp.requests))
	}
	for _, m := range mp.requests[1].Messages {
		if len(m.ToolResults) > 0 && len(m.Attachments) == 1 && m.Attachments[0].Data == "aW1n" {
			return
		}
	}
	t.Fatal("tool image did not reach model continuation")
}
