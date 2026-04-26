package config

import (
	"strings"
	"testing"
)

func TestValidate_NormalizesConntrackCapacity(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Conntrack.MaxEntries = 54321
	cfg.Capacity.Conntrack = 0

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if cfg.Capacity.Conntrack != 54321 {
		t.Fatalf("expected Capacity.Conntrack to be normalized, got %d", cfg.Capacity.Conntrack)
	}
}

func TestValidateConfigErr_UsesStructuredValidator(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Port.IPPortRules = []IPPortRule{{IP: "192.0.2.1", Port: 0, Action: IPPortRuleActionAllow}}

	err := ValidateConfigErr(&cfg)
	if err == nil {
		t.Fatalf("expected validation error")
	}
	if !strings.Contains(err.Error(), "port.ip_port_rules[0].port") {
		t.Fatalf("expected structured field path in error, got %v", err)
	}
}

func TestValidate_RuntimeServicesWarnAsNonPersistent(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Runtime.AI.Enabled = true
	cfg.Runtime.MCP.Enabled = true

	result := ValidateConfigStruct(&cfg)
	if len(result.Warnings) < 2 {
		t.Fatalf("expected runtime warnings, got %+v", result.Warnings)
	}

	foundAI := false
	foundMCP := false
	for _, warning := range result.Warnings {
		switch warning.Field {
		case "runtime.ai":
			foundAI = true
		case "runtime.mcp":
			foundMCP = true
		}
	}

	if !foundAI || !foundMCP {
		t.Fatalf("expected runtime ai/mcp warnings, got %+v", result.Warnings)
	}
}

func TestValidate_ModuleNameRequired(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Modules = []ModuleConfig{{Enabled: true}}

	result := ValidateConfigStruct(&cfg)
	if result.Valid {
		t.Fatalf("expected invalid result")
	}
	if len(result.Errors) == 0 || result.Errors[0].Field != "modules[0].name" {
		t.Fatalf("expected module name error, got %+v", result.Errors)
	}
}
