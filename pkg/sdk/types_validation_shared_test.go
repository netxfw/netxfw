package sdk

import (
	"strings"
	"testing"
)

func TestGlobalConfigValidate_UsesSharedValidators(t *testing.T) {
	cfg := GlobalConfig{
		Base: BaseConfig{LockListV4Mask: 33},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatalf("expected validation error")
	}
	if !strings.Contains(err.Error(), "lock_list_v4_mask") {
		t.Fatalf("expected shared validator message, got %v", err)
	}
}

func TestLogEngineConfigValidate_UsesSharedActionValidator(t *testing.T) {
	cfg := LogEngineConfig{
		Rules: []LogEngineRule{{ID: "r1", Action: "invalid_action"}},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatalf("expected validation error")
	}
	if !strings.Contains(err.Error(), "invalid action") {
		t.Fatalf("expected shared action validator message, got %v", err)
	}
}
