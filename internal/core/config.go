package core

import (
	"context"
	"os"
	"path/filepath"

	"github.com/livp123/netxfw/internal/config"
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/utils/logger"
)

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
