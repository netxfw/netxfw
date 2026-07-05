// Package app provides app functionality.
package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/netxfw/netxfw/internal/utils/logger"
)

// InitConfiguration initializes the default configuration files if they don't exist.
func InitConfiguration(ctx context.Context) error {
	log := logger.Get(ctx)
	configPath := GetConfigPath()
	configDir := filepath.Dir(configPath)

	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		if err := os.MkdirAll(configDir, 0750); err != nil {
			return fmt.Errorf("failed to create config directory %s: %w", configDir, err)
		}
		log.Infof("[DIR] Created config directory: %s", configDir)
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		if err := os.WriteFile(configPath, []byte(DefaultConfigTemplate()), 0600); err != nil {
			return fmt.Errorf("failed to create config file: %w", err)
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
				if mkErr := os.MkdirAll(lockListDir, 0750); mkErr != nil {
					log.Warnf("[WARN]  Failed to create lock list directory %s: %v", lockListDir, mkErr)
				}
			}

			if writeErr := os.WriteFile(lockListFile, []byte(""), 0600); writeErr != nil {
				log.Warnf("[WARN]  Failed to create lock list file %s: %v", lockListFile, writeErr)
			} else {
				log.Infof("[FILE] Created lock list file: %s", lockListFile)
			}
		}
	}
	return nil
}
