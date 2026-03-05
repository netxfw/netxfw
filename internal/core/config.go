package core

import (
	"context"
	"os"
	"path/filepath"

	"github.com/netxfw/netxfw/internal/config"
	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/netxfw/netxfw/internal/utils/logger"
)

// InitConfiguration initializes the default configuration files if they don't exist.
// InitConfiguration 如果默认配置文件不存在，则初始化它们。
func InitConfiguration(ctx context.Context) {
	log := logger.Get(ctx)
	configPath := config.GetConfigPath()
	configDir := filepath.Dir(configPath)

	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		if err := os.MkdirAll(configDir, 0755); err != nil {
			log.Fatalf("[ERROR] Failed to create config directory %s: %v", configDir, err)
		}
		log.Infof("[DIR] Created config directory: %s", configDir)
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Define default config with bilingual comments
		// 定义带有双语注释的默认配置
		defaultConfig := types.DefaultConfigTemplate

		if err := os.WriteFile(configPath, []byte(defaultConfig), 0600); err != nil {
			log.Fatalf("[ERROR] Failed to create config.yaml: %v", err)
		}
		log.Infof("[FILE] Created default global config with comments: %s", configPath)
	} else {
		log.Infof("[INFO]  Config file already exists: %s", configPath)
	}

	// Initialize LockListFile if configured in the newly created or existing config
	// 如果在新建或现有的配置中配置了 LockListFile，则初始化它
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err == nil && globalCfg.Base.LockListFile != "" {
		lockListFile := globalCfg.Base.LockListFile
		if _, err := os.Stat(lockListFile); os.IsNotExist(err) {
			// Create directory for lock list file if needed
			// 如果需要，为锁定列表文件创建目录
			lockListDir := filepath.Dir(lockListFile)
			if _, err := os.Stat(lockListDir); os.IsNotExist(err) {
				if err := os.MkdirAll(lockListDir, 0755); err != nil {
					log.Warnf("[WARN]  Failed to create lock list directory %s: %v", lockListDir, err)
				}
			}
			
			// Create empty lock list file
			// 创建空的锁定列表文件
			if err := os.WriteFile(lockListFile, []byte(""), 0644); err != nil {
				log.Warnf("[WARN]  Failed to create lock list file %s: %v", lockListFile, err)
			} else {
				log.Infof("[FILE] Created lock list file: %s", lockListFile)
			}
		}
	}
}
