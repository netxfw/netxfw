package configfile

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"

	domainconfig "github.com/netxfw/netxfw/internal/domain/config"
	"github.com/netxfw/netxfw/internal/utils/fileutil"
	"github.com/netxfw/netxfw/internal/utils/logger"
)

func Save(path string, cfg *domainconfig.Config) error {
	data, err := Encode(cfg)
	if err != nil {
		return err
	}
	return fileutil.AtomicWriteFile(path, data, 0600)
}

func SaveWithBackup(path string, cfg *domainconfig.Config, keepBackups int) error {
	log := logger.Get(nil)
	safePath := filepath.Clean(path)
	oldData, readErr := os.ReadFile(safePath)

	newData, err := Encode(cfg)
	if err != nil {
		return err
	}

	if readErr == nil && bytes.Equal(oldData, newData) {
		return nil
	}

	if readErr == nil && keepBackups > 0 {
		backupPath := safePath + ".bak." + nowStamp()
		if err := os.WriteFile(backupPath, oldData, 0600); err != nil {
			log.Warnf("[WARN] Failed to backup config file: %v", err)
		} else {
			log.Infof("[BACKUP] Created config backup: %s", backupPath)
			if cleanupErr := CleanupOldBackups(path, keepBackups); cleanupErr != nil {
				log.Warnf("[WARN] Failed to cleanup old backups: %v", cleanupErr)
			}
		}
	}

	return fileutil.AtomicWriteFile(path, newData, 0600)
}

func CleanupOldBackups(originalPath string, keep int) error {
	log := logger.Get(nil)
	dir := filepath.Dir(originalPath)
	baseName := filepath.Base(originalPath)
	pattern := baseName + ".bak.*"

	matches, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil {
		return err
	}
	if len(matches) <= keep {
		return nil
	}

	sort.Strings(matches)
	toRemove := matches[:len(matches)-keep]
	for _, f := range toRemove {
		if err := os.Remove(f); err == nil {
			log.Infof("[DELETE] Removed old backup: %s", f)
		}
	}
	return nil
}
