package core

import (
	"context"
	"os"
	"path/filepath"
	"sync"

	"github.com/livp123/netxfw/internal/config"
	"github.com/livp123/netxfw/internal/plugins"
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/utils/logger"
)

// ConfigMu protects concurrent access to the configuration file.
// ConfigMu 保护对配置文件的并发访问。
var ConfigMu sync.RWMutex

// InitConfiguration initializes the default configuration files if they don't exist.
// InitConfiguration 如果默认配置文件不存在，则初始化它们。
func InitConfiguration(ctx context.Context) {
	log := logger.Get(ctx)
	configPath := config.GetConfigPath()
	configDir := filepath.Dir(configPath)

	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		if err := os.MkdirAll(configDir, 0755); err != nil {
			log.Fatalf("❌ Failed to create config directory %s: %v", configDir, err)
		}
		log.Infof("📂 Created config directory: %s", configDir)
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Define default config with bilingual comments
		// 定义带有双语注释的默认配置
		defaultConfig := types.DefaultConfigTemplate

		if err := os.WriteFile(configPath, []byte(defaultConfig), 0644); err != nil {
			log.Fatalf("❌ Failed to create config.yaml: %v", err)
		}
		log.Infof("📄 Created default global config with comments: %s", configPath)
	} else {
		log.Infof("ℹ️  Config file already exists: %s", configPath)
	}
}

/**
 * TestConfiguration validates the syntax and values of configuration files.
 * TestConfiguration 验证配置文件的语法和值。
 */
func TestConfiguration(ctx context.Context) {
	log := logger.Get(ctx)
	configPath := config.GetConfigPath()
	log.Infof("🔍 Testing global configuration in %s...", configPath)

	cfg, err := types.LoadGlobalConfig(configPath)
	if err != nil {
		log.Fatalf("❌ Error loading config.yaml: %v", err)
	}

	allValid := true
	for _, p := range plugins.GetPlugins() {
		if err := p.Validate(cfg); err != nil {
			log.Errorf("❌ Validation failed for plugin %s: %v", p.Name(), err)
			allValid = false
			continue
		}
		log.Infof("✅ Plugin %s configuration is valid", p.Name())
	}

	if allValid {
		log.Infof("🎉 All configurations are valid!")
	} else {
		os.Exit(1)
	}
}
