package types

import (
	"sync"

	"github.com/netxfw/netxfw/internal/adapters/configfile"
	"github.com/netxfw/netxfw/pkg/sdk"
)

// ConfigMu protects concurrent access to the configuration file.
var ConfigMu sync.RWMutex

type BPFPluginConfig = sdk.BPFPluginConfig
type BPFPluginSettings = sdk.BPFPluginSettings
type GlobalConfig = sdk.GlobalConfig
type ModuleConfig = sdk.ModuleConfig
type LogEngineConfig = sdk.LogEngineConfig
type LogEngineRule = sdk.LogEngineRule
type RateLimitConfig = sdk.RateLimitConfig
type RateLimitRule = sdk.RateLimitRule
type WebConfig = sdk.WebConfig
type AIConfig = sdk.AIConfig
type MCPConfig = sdk.MCPConfig
type CloudConfig = sdk.CloudConfig
type ProxyProtocolConfig = sdk.ProxyProtocolConfig
type ClusterConfig = sdk.ClusterConfig
type CapacityConfig = sdk.CapacityConfig
type BaseConfig = sdk.BaseConfig
type ConntrackConfig = sdk.ConntrackConfig
type MetricsConfig = sdk.MetricsConfig
type PortConfig = sdk.PortConfig
type IPPortRule = sdk.IPPortRule

// LoadGlobalConfig loads the configuration from a TOML file.
func LoadGlobalConfig(path string) (*GlobalConfig, error) {
	cfg, err := configfile.Load(path)
	if err != nil {
		return nil, err
	}
	out := GlobalConfig(*cfg)
	return &out, nil
}

// SaveGlobalConfig saves the configuration to a TOML file.
func SaveGlobalConfig(path string, cfg *GlobalConfig) error {
	return configfile.Save(path, cfg)
}

// SaveGlobalConfigWithBackup saves the configuration to a TOML file with backup.
func SaveGlobalConfigWithBackup(path string, cfg *GlobalConfig, keepBackups int) error {
	return configfile.SaveWithBackup(path, cfg, keepBackups)
}

// CleanupOldBackups removes old backup files, keeping only the latest N.
func CleanupOldBackups(originalPath string, keep int) error {
	return configfile.CleanupOldBackups(originalPath, keep)
}

// BackupConfig creates a backup of the configuration file.
func BackupConfig(path string) (string, error) {
	return configfile.Backup(path)
}

// RestoreConfigFromBackup restores configuration from a backup file.
func RestoreConfigFromBackup(backupPath, configPath string) error {
	return configfile.Restore(backupPath, configPath)
}

// ListBackups lists all backup files for a configuration.
func ListBackups(path string) ([]string, error) {
	return configfile.ListBackups(path)
}
