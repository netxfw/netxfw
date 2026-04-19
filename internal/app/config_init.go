package app

import (
	"context"
	"os"
	"path/filepath"

	"github.com/netxfw/netxfw/internal/utils/logger"
)

// InitConfiguration initializes the default configuration files if they don't exist.
func InitConfiguration(ctx context.Context) {
	log := logger.Get(ctx)
	configPath := GetConfigPath()
	configDir := filepath.Dir(configPath)

	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		if err := os.MkdirAll(configDir, 0755); err != nil {
			log.Fatalf("[ERROR] Failed to create config directory %s: %v", configDir, err)
		}
		log.Infof("[DIR] Created config directory: %s", configDir)
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		if err := os.WriteFile(configPath, []byte(DefaultConfigTemplate()), 0600); err != nil {
			log.Fatalf("[ERROR] Failed to create config file: %v", err)
		}
		log.Infof("[FILE] Created default global config with comments: %s", configPath)
	} else {
		log.Infof("[INFO]  Config file already exists: %s", configPath)
	}

	globalCfg, err := LoadConfig()
	if err == nil && globalCfg.Base.LockListFile != "" {
		lockListFile := globalCfg.Base.LockListFile
		if _, statErr := os.Stat(lockListFile); os.IsNotExist(statErr) {
			lockListDir := filepath.Dir(lockListFile)
			if _, dirErr := os.Stat(lockListDir); os.IsNotExist(dirErr) {
				if mkErr := os.MkdirAll(lockListDir, 0755); mkErr != nil {
					log.Warnf("[WARN]  Failed to create lock list directory %s: %v", lockListDir, mkErr)
				}
			}

			if writeErr := os.WriteFile(lockListFile, []byte(""), 0644); writeErr != nil {
				log.Warnf("[WARN]  Failed to create lock list file %s: %v", lockListFile, writeErr)
			} else {
				log.Infof("[FILE] Created lock list file: %s", lockListFile)
			}
		}
	}
}
