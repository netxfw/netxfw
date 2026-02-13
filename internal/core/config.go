package core

import (
	"fmt"
	"log"
	"os"

	"github.com/livp123/netxfw/internal/plugins"
	"github.com/livp123/netxfw/internal/plugins/types"
)

// InitConfiguration initializes the default configuration files if they don't exist.
// InitConfiguration 如果默认配置文件不存在，则初始化它们。
func InitConfiguration() {
	configDir := "/etc/netxfw"
	configPath := configDir + "/config.yaml"

	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		if err := os.MkdirAll(configDir, 0755); err != nil {
			log.Fatalf("❌ Failed to create config directory %s: %v", configDir, err)
		}
		log.Printf("📂 Created config directory: %s", configDir)
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Define default config with bilingual comments
		// 定义带有双语注释的默认配置
		defaultConfig := types.DefaultConfigTemplate

		if err := os.WriteFile(configPath, []byte(defaultConfig), 0644); err != nil {
			log.Fatalf("❌ Failed to create config.yaml: %v", err)
		}
		log.Printf("📄 Created default global config with comments: %s", configPath)
	} else {
		log.Printf("ℹ️  Config file already exists: %s", configPath)
	}
}

/**
 * TestConfiguration validates the syntax and values of configuration files.
 * TestConfiguration 验证配置文件的语法和值。
 */
func TestConfiguration() {
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
