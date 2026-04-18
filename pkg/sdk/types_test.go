package sdk

import "testing"

func TestBPFPluginSettingsValidate(t *testing.T) {
	t.Run("disabled settings skip validation", func(t *testing.T) {
		cfg := BPFPluginSettings{
			Enabled: false,
			Plugins: []BPFPluginConfig{
				{Path: "", Index: 0, Enabled: true},
			},
		}

		if err := cfg.Validate(); err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	})

	t.Run("enabled plugin requires path and valid slot", func(t *testing.T) {
		cfg := BPFPluginSettings{
			Enabled: true,
			Plugins: []BPFPluginConfig{
				{Path: "", Index: BPFPluginSlotStart, Enabled: true},
			},
		}

		if err := cfg.Validate(); err == nil {
			t.Fatalf("expected validation error")
		}
	})

	t.Run("duplicate enabled slots are rejected", func(t *testing.T) {
		cfg := BPFPluginSettings{
			Enabled: true,
			Plugins: []BPFPluginConfig{
				{Path: "/tmp/a.o", Index: BPFPluginSlotStart, Enabled: true},
				{Path: "/tmp/b.o", Index: BPFPluginSlotStart, Enabled: true},
			},
		}

		if err := cfg.Validate(); err == nil {
			t.Fatalf("expected duplicate slot error")
		}
	})
}
