package plugins

import (
	"fmt"
	"strings"

	domainconfig "github.com/netxfw/netxfw/internal/domain/config"
	"go.uber.org/zap"
)

type pluginManager interface {
	LoadPlugin(path string, index int) error
	RemovePlugin(index int) error
}

// Load inserts a datapath plugin program into the configured jump-table slot.
func Load(manager pluginManager, path string, index int) error {
	if manager == nil {
		return fmt.Errorf("manager is nil")
	}
	if path == "" {
		return fmt.Errorf("plugin path is required")
	}
	if err := ValidateSlot(index); err != nil {
		return err
	}
	return manager.LoadPlugin(path, index)
}

// Remove detaches a datapath plugin program from the configured jump-table slot.
func Remove(manager pluginManager, index int) error {
	if manager == nil {
		return fmt.Errorf("manager is nil")
	}
	if err := ValidateSlot(index); err != nil {
		return err
	}
	return manager.RemovePlugin(index)
}

// LoadConfigured loads all enabled datapath plugins declared in config.
func LoadConfigured(manager pluginManager, globalCfg *domainconfig.Config, log *zap.SugaredLogger) error {
	if globalCfg == nil {
		return fmt.Errorf("config is nil")
	}
	if !globalCfg.BPFPlugin.Enabled {
		log.Infof("[INFO]  BPF plugin auto-loading is disabled")
		return nil
	}

	plugins := globalCfg.BPFPlugin.Plugins
	if len(plugins) == 0 {
		log.Infof("[INFO]  No BPF plugins configured")
		return nil
	}

	log.Infof("[INFO]  Loading %d BPF plugin(s)...", len(plugins))

	var loadErrors []string
	loadedCount := 0
	for _, plugin := range plugins {
		if !plugin.Enabled {
			log.Infof("[INFO]  Skipping disabled plugin: %s (index %d)", plugin.Path, plugin.Index)
			continue
		}
		if err := ValidateSlot(plugin.Index); err != nil {
			log.Warnf("[WARN]  Invalid plugin index %d for %s (must be %d-%d)",
				plugin.Index, plugin.Path, SlotStart, SlotEnd)
			loadErrors = append(loadErrors, fmt.Sprintf("%s: %v", plugin.Path, err))
			continue
		}
		if err := Load(manager, plugin.Path, plugin.Index); err != nil {
			log.Warnf("[WARN]  Failed to load BPF plugin %s: %v", plugin.Path, err)
			loadErrors = append(loadErrors, fmt.Sprintf("%s: %v", plugin.Path, err))
			continue
		}

		loadedCount++
		desc := plugin.Description
		if desc == "" {
			desc = "no description"
		}
		log.Infof("[OK] BPF plugin loaded: %s at index %d (%s)", plugin.Path, plugin.Index, desc)
	}

	if len(loadErrors) > 0 {
		return fmt.Errorf("failed to load %d plugin(s): %s", len(loadErrors), strings.Join(loadErrors, "; "))
	}

	log.Infof("[OK] Successfully loaded %d/%d BPF plugin(s)", loadedCount, len(plugins))
	return nil
}
