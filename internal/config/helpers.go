package config

import (
	"path/filepath"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/netxfw/netxfw/internal/plugins/types"
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
func GetCurrentConfig() *types.GlobalConfig {
	return GetConfigManager().GetConfig()
}
