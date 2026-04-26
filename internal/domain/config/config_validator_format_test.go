package config

import "testing"

func TestValidateConfig_MergesSyntaxAndStructureResults(t *testing.T) {
	configData := []byte(`
[web]
enabled = true
port = 0
`)

	result, err := ValidateConfig(configData)
	if err != nil {
		t.Fatalf("ValidateConfig returned unexpected error: %v", err)
	}
	if result.Valid {
		t.Fatalf("expected invalid result")
	}
	if len(result.Errors) == 0 {
		t.Fatalf("expected validation errors")
	}
	if result.Errors[0].Field != "web.port" {
		t.Fatalf("expected web.port field, got %+v", result.Errors)
	}
}

func TestValidateSyntax_UsesStructuredFieldName(t *testing.T) {
	validator := NewConfigValidator()
	result := validator.ValidateSyntax([]byte("[base\nwhitelist=[\"bad-ip\"]"))
	if result.Valid {
		t.Fatalf("expected syntax error")
	}
	if len(result.Errors) == 0 || result.Errors[0].Field != "config.syntax" {
		t.Fatalf("expected config.syntax field, got %+v", result.Errors)
	}
}
