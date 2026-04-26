package config

import "testing"

func TestConfigValidator_IPPortRuleActionCompatibility(t *testing.T) {
	validator := NewConfigValidator()

	t.Run("ActionTwoAcceptedAsLegacyDeny", func(t *testing.T) {
		cfg := &Config{
			Port: PortConfig{
				IPPortRules: []IPPortRule{{IP: "192.0.2.0/24", Port: 80, Action: IPPortRuleActionDenyCompat}},
			},
		}

		result := validator.Validate(cfg)
		if !result.Valid {
			t.Fatalf("expected valid config, got errors: %+v", result.Errors)
		}
	})

	t.Run("InvalidActionUsesCanonicalMessage", func(t *testing.T) {
		cfg := &Config{
			Port: PortConfig{
				IPPortRules: []IPPortRule{{IP: "192.0.2.0/24", Port: 80, Action: 3}},
			},
		}

		result := validator.Validate(cfg)
		if result.Valid {
			t.Fatalf("expected invalid result")
		}
		if len(result.Errors) == 0 || result.Errors[0].Field != "port.ip_port_rules[0].action" {
			t.Fatalf("expected action error, got %+v", result.Errors)
		}
		if result.Errors[0].Message != "action must be 0/2 (deny) or 1 (allow)" {
			t.Fatalf("unexpected error message: %s", result.Errors[0].Message)
		}
	})
}

func TestConfigValidator_ConflictChecksTreatActionTwoAsDeny(t *testing.T) {
	validator := NewConfigValidator()
	cfg := &Config{
		Base: BaseConfig{Whitelist: []string{"192.0.2.0/24"}},
		Port: PortConfig{
			AllowedPorts: []uint16{443},
			IPPortRules:  []IPPortRule{{IP: "192.0.2.128/25", Port: 443, Action: IPPortRuleActionDenyCompat}},
		},
	}

	result := validator.Validate(cfg)
	if result.Valid {
		t.Fatalf("expected conflict result to be invalid due to overlap error")
	}

	foundOverlap := false
	foundPortWarning := false
	for _, err := range result.Errors {
		if err.Field == "port.ip_port_rules[0].ip" {
			foundOverlap = true
			break
		}
	}
	for _, warning := range result.Warnings {
		if warning.Field == "port.ip_port_rules[0]" {
			foundPortWarning = true
			break
		}
	}

	if !foundOverlap {
		t.Fatalf("expected overlap error for legacy deny action, got errors: %+v", result.Errors)
	}
	if !foundPortWarning {
		t.Fatalf("expected allowed-port conflict warning for legacy deny action, got warnings: %+v", result.Warnings)
	}
}
