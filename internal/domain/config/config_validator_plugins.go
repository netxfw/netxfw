package config

import "fmt"

func (v *ConfigValidator) validateBPFPluginConfig(cfg *BPFPluginSettings, result *ValidationResult) {
	if !cfg.Enabled {
		return
	}

	if len(cfg.Plugins) == 0 {
		result.AddWarning("bpf_plugin.plugins", "BPF plugins are enabled but no plugins are configured", nil)
		return
	}

	seen := make(map[int]int, len(cfg.Plugins))
	for i := range cfg.Plugins {
		plugin := &cfg.Plugins[i]
		if !plugin.Enabled {
			continue
		}

		fieldPrefix := fmt.Sprintf("bpf_plugin.plugins[%d]", i)
		if plugin.Path == "" {
			result.AddError(fieldPrefix+".path", "Plugin path is required", nil)
		}
		if plugin.Index < BPFPluginSlotStart || plugin.Index > BPFPluginSlotEnd {
			result.AddError(
				fieldPrefix+".index",
				fmt.Sprintf("Plugin index must be between %d and %d", BPFPluginSlotStart, BPFPluginSlotEnd),
				plugin.Index,
			)
			continue
		}
		if prev, ok := seen[plugin.Index]; ok {
			result.AddError(
				fieldPrefix+".index",
				fmt.Sprintf("Duplicate plugin index %d already used by bpf_plugin.plugins[%d]", plugin.Index, prev),
				plugin.Index,
			)
			continue
		}
		seen[plugin.Index] = i
	}
}
