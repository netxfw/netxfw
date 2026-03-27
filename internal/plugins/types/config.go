package types

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/netxfw/netxfw/internal/utils/fileutil"
	"github.com/netxfw/netxfw/internal/utils/logger"
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
	safePath := filepath.Clean(path)
	data, err := os.ReadFile(safePath)
	if err != nil {
		return nil, err
	}

	cfg := GlobalConfig{
		Cluster: ClusterConfig{
			Enabled:    false,
			ConfigPath: "cluster.toml",
		},
		Base: BaseConfig{
			DefaultDeny:        true,
			AllowReturnTraffic: false,
			AllowICMP:          true,
			PersistRules:       true,
			CleanupInterval:    "1m",
			ICMPRate:           10,
			ICMPBurst:          50,
			LockListV4Mask:     24,
			LockListV6Mask:     64,
			EnablePprof:        false,
			PprofPort:          6060,
		},
		Conntrack: ConntrackConfig{
			Enabled:    true,
			MaxEntries: 100000,
			TCPTimeout: "1h",
			UDPTimeout: "5m",
		},
		RateLimit: RateLimitConfig{
			Enabled:         true,
			AutoBlock:       true,
			AutoBlockExpiry: "10m",
		},
		LogEngine: LogEngineConfig{
			Enabled: false,
			Workers: 4,
		},
		Capacity: CapacityConfig{
			Conntrack:       100000,
			LockList:        2000000,
			DynLockList:     2000000,
			Whitelist:       65536,
			IPPortRules:     65536,
			AllowedPorts:    1024,
			RateLimits:      1000,
			DropReasonStats: 1000000,
			PassReasonStats: 1000000,
		},
		Logging: logger.LoggingConfig{
			Enabled:    false,
			Path:       "/var/log/netxfw/agent.log",
			MaxSize:    10,
			MaxBackups: 3,
			MaxAge:     30,
			Compress:   true,
		},
		Web: WebConfig{
			Port: 11811,
		},
		Metrics: MetricsConfig{
			Enabled:           false,
			ServerEnabled:     false,
			Port:              11812,
			TopN:              10,
			ThresholdCritical: 90,
			ThresholdHigh:     75,
			ThresholdMedium:   50,
			StatsInterval:     "1s",
			AvgPacketSize:     500,
		},
		AI: AIConfig{
			Enabled: false,
			Port:    11813,
		},
		MCP: MCPConfig{
			Enabled: false,
			Port:    11814,
			Mode:    "sse",
		},
	}

	if _, err = toml.Decode(string(data), &cfg); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}
	return &cfg, nil
}

// SaveGlobalConfig saves the configuration to a TOML file.
func SaveGlobalConfig(path string, cfg *GlobalConfig) error {
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(cfg); err != nil {
		return err
	}
	return fileutil.AtomicWriteFile(path, buf.Bytes(), 0600)
}

// SaveGlobalConfigWithBackup saves the configuration to a TOML file with backup.
func SaveGlobalConfigWithBackup(path string, cfg *GlobalConfig, keepBackups int) error {
	log := logger.Get(nil)
	safePath := filepath.Clean(path)
	oldData, readErr := os.ReadFile(safePath)

	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(cfg); err != nil {
		return err
	}
	newData := buf.Bytes()

	if readErr == nil && bytes.Equal(oldData, newData) {
		return nil
	}

	if readErr == nil && keepBackups > 0 {
		backupPath := safePath + ".bak." + time.Now().Format("20060102-150405")
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

// CleanupOldBackups removes old backup files, keeping only the latest N.
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

// BackupConfig creates a backup of the configuration file.
func BackupConfig(path string) (string, error) {
	safePath := filepath.Clean(path)
	data, err := os.ReadFile(safePath)
	if err != nil {
		return "", fmt.Errorf("failed to read config file: %w", err)
	}

	backupPath := safePath + ".bak." + time.Now().Format("20060102-150405")
	if err := os.WriteFile(backupPath, data, 0600); err != nil {
		return "", fmt.Errorf("failed to create backup: %w", err)
	}
	return backupPath, nil
}

// RestoreConfigFromBackup restores configuration from a backup file.
func RestoreConfigFromBackup(backupPath, configPath string) error {
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

// ListBackups lists all backup files for a configuration.
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
