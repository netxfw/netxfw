package config

import "testing"

func TestConfigValidator_ValidateBPFPluginConfig(t *testing.T) {
	validator := NewConfigValidator()

	t.Run("ValidConfiguredPlugins", func(t *testing.T) {
		cfg := &Config{
			BPFPlugin: BPFPluginSettings{
				Enabled: true,
				Plugins: []BPFPluginConfig{
					{Path: "/tmp/plugin-a.o", Index: 2, Enabled: true},
					{Path: "/tmp/plugin-b.o", Index: 3, Enabled: true},
				},
			},
		}

		result := validator.Validate(cfg)
		if !result.Valid {
			t.Fatalf("expected valid config, got errors: %+v", result.Errors)
		}
	})

	t.Run("EnabledWithoutPluginsWarns", func(t *testing.T) {
		cfg := &Config{
			BPFPlugin: BPFPluginSettings{
				Enabled: true,
			},
		}

		result := validator.Validate(cfg)
		if !result.Valid {
			t.Fatalf("expected warning-only result, got errors: %+v", result.Errors)
		}
		if len(result.Warnings) == 0 || result.Warnings[0].Field != "bpf_plugin.plugins" {
			t.Fatalf("expected bpf_plugin.plugins warning, got %+v", result.Warnings)
		}
	})

	t.Run("MissingPathIsInvalid", func(t *testing.T) {
		cfg := &Config{
			BPFPlugin: BPFPluginSettings{
				Enabled: true,
				Plugins: []BPFPluginConfig{
					{Index: 2, Enabled: true},
				},
			},
		}

		result := validator.Validate(cfg)
		if result.Valid {
			t.Fatalf("expected invalid result")
		}
		if len(result.Errors) == 0 || result.Errors[0].Field != "bpf_plugin.plugins[0].path" {
			t.Fatalf("expected path error, got %+v", result.Errors)
		}
	})

	t.Run("InvalidSlotIsRejected", func(t *testing.T) {
		cfg := &Config{
			BPFPlugin: BPFPluginSettings{
				Enabled: true,
				Plugins: []BPFPluginConfig{
					{Path: "/tmp/plugin-a.o", Index: 1, Enabled: true},
				},
			},
		}

		result := validator.Validate(cfg)
		if result.Valid {
			t.Fatalf("expected invalid result")
		}
		if len(result.Errors) == 0 || result.Errors[0].Field != "bpf_plugin.plugins[0].index" {
			t.Fatalf("expected index error, got %+v", result.Errors)
		}
	})

	t.Run("DuplicateSlotsAreRejected", func(t *testing.T) {
		cfg := &Config{
			BPFPlugin: BPFPluginSettings{
				Enabled: true,
				Plugins: []BPFPluginConfig{
					{Path: "/tmp/plugin-a.o", Index: 2, Enabled: true},
					{Path: "/tmp/plugin-b.o", Index: 2, Enabled: true},
				},
			},
		}

		result := validator.Validate(cfg)
		if result.Valid {
			t.Fatalf("expected invalid result")
		}
		if len(result.Errors) == 0 || result.Errors[0].Field != "bpf_plugin.plugins[1].index" {
			t.Fatalf("expected duplicate index error, got %+v", result.Errors)
		}
	})
}
