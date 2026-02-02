package main

import (
	"fmt"
	"log"
	"os"

	"github.com/livp123/netxfw/internal/plugins"
	"github.com/livp123/netxfw/internal/plugins/types"
	"gopkg.in/yaml.v3"
)

func initConfiguration() {
	configDir := "/etc/netxfw"
	configPath := configDir + "/config.yaml"

	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		if err := os.MkdirAll(configDir, 0755); err != nil {
			log.Fatalf("❌ Failed to create config directory %s: %v", configDir, err)
		}
		log.Printf("📂 Created config directory: %s", configDir)
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		globalCfg := types.GlobalConfig{}
		// Get default configs from plugins
		for _, p := range plugins.GetPlugins() {
			switch p.Name() {
			case "base":
				globalCfg.Base = p.DefaultConfig().(types.BaseConfig)
			case "port":
				globalCfg.Port = p.DefaultConfig().(types.PortConfig)
			case "metrics":
				globalCfg.Metrics = p.DefaultConfig().(types.MetricsConfig)
			case "conntrack":
				globalCfg.Conntrack = p.DefaultConfig().(types.ConntrackConfig)
			}
		}

		// Set default capacities
		globalCfg.Capacity = types.CapacityConfig{
			Conntrack:    100000,
			LockList:     2000000,
			Whitelist:    65536,
			IPPortRules:  65536,
			AllowedPorts: 1024,
		}

		data, _ := yaml.Marshal(globalCfg)
		if err := os.WriteFile(configPath, data, 0644); err != nil {
			log.Fatalf("❌ Failed to create config.yaml: %v", err)
		}
		log.Printf("📄 Created default global config: %s", configPath)
	} else {
		log.Printf("ℹ️  Config file already exists: %s", configPath)
	}
}

/**
 * testConfiguration validates the syntax and values of configuration files.
 */
func testConfiguration() {
	configPath := "/etc/netxfw/config.yaml"
	fmt.Printf("🔍 Testing global configuration in %s...\n", configPath)

	cfg, err := types.LoadGlobalConfig(configPath)
	if err != nil {
		log.Fatalf("❌ Error loading config.yaml: %v", err)
	}

	allValid := true
	for _, p := range plugins.GetPlugins() {
		if err := p.Validate(cfg); err != nil {
			fmt.Printf("❌ Validation failed for plugin %s: %v\n", p.Name(), err)
			allValid = false
			continue
		}
		fmt.Printf("✅ Plugin %s configuration is valid\n", p.Name())
	}

	if allValid {
		fmt.Println("🎉 All configurations are valid!")
	} else {
		os.Exit(1)
	}
}
