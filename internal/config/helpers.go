package config

import (
	"os"
	"path/filepath"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/netxfw/netxfw/internal/adapters/configfile"
	"github.com/netxfw/netxfw/pkg/sdk"
)

/**
 * LoadMap loads a pinned BPF map by its name.
 * It automatically resolves the pin path.
 * LoadMap 通过名称加载固定的 BPF Map。
 * 它会自动解析固定路径。
 */
func LoadMap(mapName string) (*ebpf.Map, error) {
	return ebpf.LoadPinnedMap(filepath.Join(GetPinPath(), mapName), nil)
}

/**
 * ClearMap loads and clears a BPF map by name.
 * ClearMap 通过名称加载并清除 BPF Map。
 */
// func ClearMap(mapName string) error {
// 	m, err := LoadMap(mapName)
// 	if err != nil {
// 		return err
// 	}
// 	defer m.Close()
// 	return m.Iterate().Close()
// }

// ConfigManagerInstance holds the singleton instance of the config manager
// ConfigManagerInstance 保存配置管理器的单例实例
var ConfigManagerInstance *ConfigManager
var once sync.Once
var configFileMu sync.RWMutex

// GetDefaultConfigPath returns the default config path, preferring TOML over YAML.
// GetDefaultConfigPath 返回默认配置路径，优先使用 TOML 格式。
// Priority: TOML > YAML (to support older installs)
// 优先级：TOML > YAML（用于支持旧安装）
func GetDefaultConfigPath() string {
	// Check if TOML config exists / 检查 TOML 配置是否存在
	if _, err := os.Stat(DefaultConfigPath); err == nil {
		return DefaultConfigPath
	}
	// Fall back to YAML for older installs / 回退到 YAML 以支持旧安装
	if _, err := os.Stat(YAMLConfigPath); err == nil {
		return YAMLConfigPath
	}
	// Return TOML as default for new installations / 新安装默认返回 TOML
	return DefaultConfigPath
}

// GetConfigPath returns the current config path from the manager or default.
// GetConfigPath 返回管理器中的当前配置路径或默认路径。
// If runtime.ConfigPath is set (e.g., via CLI flag or test), it takes precedence.
// 如果 runtime.ConfigPath 已设置（例如通过 CLI 标志或测试），则优先使用它。
func GetConfigPath() string {
	if ConfigManagerInstance != nil {
		return ConfigManagerInstance.GetConfigPath()
	}
	return resolveConfigPath()
}

// GetConfigManager returns the singleton instance of the config manager
// GetConfigManager 返回配置管理器的单例实例
func GetConfigManager() *ConfigManager {
	once.Do(func() {
		ConfigManagerInstance = NewConfigManager(GetDefaultConfigPath())
	})
	return ConfigManagerInstance
}

// LoadGlobalConfig loads the configuration using the config manager
// LoadGlobalConfig 使用配置管理器加载配置
func LoadGlobalConfig() error {
	return GetConfigManager().LoadConfig()
}

// SaveGlobalConfig saves the configuration using the config manager
// SaveGlobalConfig 使用配置管理器保存配置
func SaveGlobalConfig() error {
	return GetConfigManager().SaveConfig()
}

// GetCurrentConfig returns the current configuration
// GetCurrentConfig 返回当前配置
func GetCurrentConfig() *sdk.GlobalConfig {
	return GetConfigManager().GetConfig()
}

// DefaultConfigTemplate returns the default TOML config template text.
func DefaultConfigTemplate() string {
	return configfile.DefaultTemplate()
}

func lockConfigRead() {
	configFileMu.RLock()
}

func unlockConfigRead() {
	configFileMu.RUnlock()
}

func lockConfigWrite() {
	configFileMu.Lock()
}

func unlockConfigWrite() {
	configFileMu.Unlock()
}

// MutateConfig applies fn to the current in-memory config and persists it.
// MutateConfig 对当前内存配置执行 fn 并持久化。
func MutateConfig(fn func(*sdk.GlobalConfig) error) error {
	return GetConfigManager().MutateConfig(fn)
}

// MutateLoadedConfig reloads config from disk, applies fn, and persists it.
// MutateLoadedConfig 从磁盘重新加载配置，执行 fn 后持久化。
func MutateLoadedConfig(fn func(*sdk.GlobalConfig) error) error {
	return GetConfigManager().MutateLoadedConfig(fn)
}

// ReloadCurrentConfig reloads and returns the current config snapshot.
// ReloadCurrentConfig 重新加载并返回当前配置快照。
func ReloadCurrentConfig() (*sdk.GlobalConfig, error) {
	return GetConfigManager().ReloadConfig()
}

// GetBackupKeep returns the number of backups to keep from config.
// GetBackupKeep 从配置中获取保留的备份数量。
func GetBackupKeep() int {
	cfg := GetCurrentConfig()
	if cfg != nil && cfg.Base.BackupKeep > 0 {
		return cfg.Base.BackupKeep
	}
	return DefaultBackupKeep
}

// CloneConfig returns a deep copy of cfg.
func CloneConfig(cfg *sdk.GlobalConfig) *sdk.GlobalConfig {
	if cfg == nil {
		return nil
	}
	return configfile.Clone(cfg)
}
