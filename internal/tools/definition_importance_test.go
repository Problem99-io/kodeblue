package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Problem99-io/kodeblue/internal/definitions"
)

func TestDefinitionImportanceWriteBoundaries(t *testing.T) {
	cfg := testConfig(t)
	create := NewCreateDefinition(cfg)
	for _, tool := range []Tool{create, NewPatchDefinition(cfg)} {
		if !strings.Contains(tool.Description(), "every task") {
			t.Errorf("%s does not explain the every-task importance criterion", tool.Name())
		}
	}
	var schema map[string]any
	if err := json.Unmarshal(create.Parameters(), &schema); err != nil {
		t.Fatal(err)
	}
	properties := schema["properties"].(map[string]any)
	important := properties["important"].(map[string]any)
	if important["default"] != false || !strings.Contains(important["description"].(string), "including unrelated tasks") {
		t.Errorf("%s does not default to ordinary searchable knowledge or explain universal relevance", create.Name())
	}
	if !strings.Contains(string(create.Parameters()), "every task") {
		t.Errorf("%s schema omits the importance criterion", create.Name())
	}
}

func TestDefinitionImportanceDefaultsAndExplicitDemotion(t *testing.T) {
	cfg := testConfig(t)
	result, err := NewCreateDefinition(cfg).Execute(context.Background(), json.RawMessage(`{"title":"Auth reference","snippet":"Login flow","content":"Detailed module reference","scope":["auth"]}`))
	if err != nil || result.IsError {
		t.Fatal(result, err)
	}
	store := definitions.NewStore(cfg.ProjectRoot)
	items, err := store.List()
	if err != nil || len(items) != 1 || items[0].Important {
		t.Fatal("ordinary knowledge must remain non-important by default", items, err)
	}
	def := items[0]
	def.Important = true
	if _, err := store.Update(def); err != nil {
		t.Fatal(err)
	}
	args, _ := json.Marshal(map[string]string{"definition_id": def.ID, "patchText": "important: false"})
	result, err = NewPatchDefinition(cfg).Execute(context.Background(), args)
	if err != nil || result.IsError {
		t.Fatal(result, err)
	}
	updated, err := store.Get(def.ID)
	if err != nil || updated.Important || updated.Content != def.Content || updated.Snippet != def.Snippet {
		t.Fatal("demotion must preserve searchable reference content", updated, err)
	}
}
