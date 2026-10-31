package config

import (
	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
	"testing"
)

func TestInvestigatorUsesNormalModelSelection(t *testing.T) {
	c := Default()
	c.Inference.AgentModel = "default-agent"
	if c.ModelFor(hubproto.RoleInvestigator) != "default-agent" {
		t.Fatal("default model not inherited")
	}
	c.Inference.AgentModels = map[string]string{hubproto.RoleInvestigator: "research-model"}
	if c.ModelFor(hubproto.RoleInvestigator) != "research-model" || c.EffectiveModels()[hubproto.RoleInvestigator] != "research-model" {
		t.Fatal("role override/status missing")
	}
	c.Inference.Refs = map[string]hubproto.ModelRef{hubproto.RoleInvestigator: {Connection: "fleet", Model: "scoped-model"}}
	if c.EffectiveModels()[hubproto.RoleInvestigator] != "fleet/scoped-model" {
		t.Fatal("hub model reference not inherited")
	}
}
