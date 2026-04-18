package configfile

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/BurntSushi/toml"
	"github.com/netxfw/netxfw/internal/utils/fileutil"
)

func Backup(path string) (string, error) {
	safePath := filepath.Clean(path)
	data, err := os.ReadFile(safePath)
	if err != nil {
		return "", fmt.Errorf("failed to read config file: %w", err)
	}

	backupPath := safePath + ".bak." + nowStamp()
	if err := os.WriteFile(backupPath, data, 0600); err != nil {
		return "", fmt.Errorf("failed to create backup: %w", err)
	}
	return backupPath, nil
}

func Restore(backupPath, configPath string) error {
	safeBackupPath := filepath.Clean(backupPath)
	safeConfigPath := filepath.Clean(configPath)

	data, err := os.ReadFile(safeBackupPath)
	if err != nil {
		return fmt.Errorf("failed to read backup file: %w", err)
	}

	var testCfg map[string]any
	if _, err := toml.Decode(string(data), &testCfg); err != nil {
		return fmt.Errorf("backup file contains invalid TOML: %w", err)
	}

	return fileutil.AtomicWriteFile(safeConfigPath, data, 0600)
}

func ListBackups(path string) ([]string, error) {
	dir := filepath.Dir(path)
	baseName := filepath.Base(path)
	pattern := baseName + ".bak.*"

	matches, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil {
		return nil, err
	}

	sort.Sort(sort.Reverse(sort.StringSlice(matches)))
	return matches, nil
}
