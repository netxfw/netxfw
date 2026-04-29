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

func TestValidateServiceBindAddresses(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Web.Enabled = true
	cfg.Web.Bind = "not-an-ip"
	cfg.Web.Token = "secret"
	cfg.Metrics.Enabled = true
	cfg.Metrics.ServerEnabled = true
	cfg.Metrics.Bind = "0.0.0.0"
	cfg.Base.EnablePprof = true
	cfg.Base.PprofBind = "127.0.0.1"

	result := NewConfigValidator().Validate(&cfg)
	if result.Valid {
		t.Fatalf("expected invalid bind address")
	}
	if len(result.Errors) == 0 || result.Errors[0].Field != "web.bind" {
		t.Fatalf("expected web.bind error, got %+v", result.Errors)
	}
	if len(result.Warnings) == 0 {
		t.Fatalf("expected exposure warning for unauthenticated metrics")
	}
}
