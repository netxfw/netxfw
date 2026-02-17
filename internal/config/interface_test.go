package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/stretchr/testify/assert"
)

// TestGetDefaultConfigPath tests GetDefaultConfigPath function
// TestGetDefaultConfigPath 测试 GetDefaultConfigPath 函数
func TestGetDefaultConfigPath(t *testing.T) {
	path := GetDefaultConfigPath()
	assert.NotEmpty(t, path)
	assert.Contains(t, path, "config.yaml")
}

// TestGetConfigPath tests GetConfigPath function
// TestGetConfigPath 测试 GetConfigPath 函数
func TestGetConfigPath(t *testing.T) {
	// When runtime.ConfigPath is not set, should return default
	// 当 runtime.ConfigPath 未设置时，应返回默认值
	path := GetConfigPath()
	assert.NotEmpty(t, path)
}

// TestGetPinPath tests GetPinPath function
// TestGetPinPath 测试 GetPinPath 函数
func TestGetPinPath(t *testing.T) {
	path := GetPinPath()
	assert.NotEmpty(t, path)
	assert.Contains(t, path, "bpf")
}

// TestGetConfigManager tests GetConfigManager singleton
// TestGetConfigManager 测试 GetConfigManager 单例
func TestGetConfigManager(t *testing.T) {
	manager1 := GetConfigManager()
	manager2 := GetConfigManager()

	// Should return the same instance
	// 应该返回相同的实例
	assert.Equal(t, manager1, manager2)
}

// TestConfigManager_GetConfigPath tests ConfigManager GetConfigPath
// TestConfigManager_GetConfigPath 测试 ConfigManager GetConfigPath
func TestConfigManager_GetConfigPath(t *testing.T) {
	manager := NewConfigManager("/test/path/config.yaml")
	assert.Equal(t, "/test/path/config.yaml", manager.GetConfigPath())
}

// TestConfigManager_GetConfig tests ConfigManager GetConfig
// TestConfigManager_GetConfig 测试 ConfigManager GetConfig
func TestConfigManager_GetConfig(t *testing.T) {
	manager := NewConfigManager("/test/path/config.yaml")
	cfg := manager.GetConfig()

	// Should return nil initially
	// 初始应返回 nil
	assert.Nil(t, cfg)
}

// TestConfigManager_UpdateConfig tests ConfigManager UpdateConfig
// TestConfigManager_UpdateConfig 测试 ConfigManager UpdateConfig
func TestConfigManager_UpdateConfig(t *testing.T) {
	manager := NewConfigManager("/test/path/config.yaml")

	// Update config with nil
	// 用 nil 更新配置
	manager.UpdateConfig(nil)
}

// TestConfigurable tests the Configurable interface
// TestConfigurable 测试 Configurable 接口
func TestConfigurable(t *testing.T) {
	// Verify ConfigManager implements Configurable
	// 验证 ConfigManager 实现了 Configurable
	var _ Configurable = (*ConfigManager)(nil)
}

// TestConstants tests the package constants
// TestConstants 测试包常量
func TestConstants(t *testing.T) {
	assert.NotEmpty(t, DefaultConfigPath)
	assert.NotEmpty(t, BPFPinPath)
}

// TestConfigManager_GetBaseConfig tests ConfigManager GetBaseConfig
// TestConfigManager_GetBaseConfig 测试 ConfigManager GetBaseConfig
func TestConfigManager_GetBaseConfig(t *testing.T) {
	manager := NewConfigManager("/test/path/config.yaml")
	cfg := manager.GetBaseConfig()
	assert.Nil(t, cfg)
}

// TestConfigManager_GetWebConfig tests ConfigManager GetWebConfig
// TestConfigManager_GetWebConfig 测试 ConfigManager GetWebConfig
func TestConfigManager_GetWebConfig(t *testing.T) {
	manager := NewConfigManager("/test/path/config.yaml")
	cfg := manager.GetWebConfig()
	assert.Nil(t, cfg)
}

// TestConfigManager_GetMetricsConfig tests ConfigManager GetMetricsConfig
// TestConfigManager_GetMetricsConfig 测试 ConfigManager GetMetricsConfig
func TestConfigManager_GetMetricsConfig(t *testing.T) {
	manager := NewConfigManager("/test/path/config.yaml")
	cfg := manager.GetMetricsConfig()
	assert.Nil(t, cfg)
}

// TestConfigManager_GetLoggingConfig tests ConfigManager GetLoggingConfig
// TestConfigManager_GetLoggingConfig 测试 ConfigManager GetLoggingConfig
func TestConfigManager_GetLoggingConfig(t *testing.T) {
	manager := NewConfigManager("/test/path/config.yaml")
	cfg := manager.GetLoggingConfig()
	assert.Nil(t, cfg)
}

// TestConfigManager_GetConntrackConfig tests ConfigManager GetConntrackConfig
// TestConfigManager_GetConntrackConfig 测试 ConfigManager GetConntrackConfig
func TestConfigManager_GetConntrackConfig(t *testing.T) {
	manager := NewConfigManager("/test/path/config.yaml")
	cfg := manager.GetConntrackConfig()
	assert.Nil(t, cfg)
}

// TestConfigManager_GetRateLimitConfig tests ConfigManager GetRateLimitConfig
// TestConfigManager_GetRateLimitConfig 测试 ConfigManager GetRateLimitConfig
func TestConfigManager_GetRateLimitConfig(t *testing.T) {
	manager := NewConfigManager("/test/path/config.yaml")
	cfg := manager.GetRateLimitConfig()
	assert.Nil(t, cfg)
}

// TestConfigManager_GetPortConfig tests ConfigManager GetPortConfig
// TestConfigManager_GetPortConfig 测试 ConfigManager GetPortConfig
func TestConfigManager_GetPortConfig(t *testing.T) {
	manager := NewConfigManager("/test/path/config.yaml")
	cfg := manager.GetPortConfig()
	assert.Nil(t, cfg)
}

// TestConfigManager_GetCapacityConfig tests ConfigManager GetCapacityConfig
// TestConfigManager_GetCapacityConfig 测试 ConfigManager GetCapacityConfig
func TestConfigManager_GetCapacityConfig(t *testing.T) {
	manager := NewConfigManager("/test/path/config.yaml")
	cfg := manager.GetCapacityConfig()
	assert.Nil(t, cfg)
}

// TestConfigManager_GetLogEngineConfig tests ConfigManager GetLogEngineConfig
// TestConfigManager_GetLogEngineConfig 测试 ConfigManager GetLogEngineConfig
func TestConfigManager_GetLogEngineConfig(t *testing.T) {
	manager := NewConfigManager("/test/path/config.yaml")
	cfg := manager.GetLogEngineConfig()
	assert.Nil(t, cfg)
}

// TestConfigManager_GetAIConfig tests ConfigManager GetAIConfig
// TestConfigManager_GetAIConfig 测试 ConfigManager GetAIConfig
func TestConfigManager_GetAIConfig(t *testing.T) {
	manager := NewConfigManager("/test/path/config.yaml")
	cfg := manager.GetAIConfig()
	assert.Nil(t, cfg)
}

// TestConfigManager_GetMCPConfig tests ConfigManager GetMCPConfig
// TestConfigManager_GetMCPConfig 测试 ConfigManager GetMCPConfig
func TestConfigManager_GetMCPConfig(t *testing.T) {
	manager := NewConfigManager("/test/path/config.yaml")
	cfg := manager.GetMCPConfig()
	assert.Nil(t, cfg)
}

// TestConfigManager_GetClusterConfig tests ConfigManager GetClusterConfig
// TestConfigManager_GetClusterConfig 测试 ConfigManager GetClusterConfig
func TestConfigManager_GetClusterConfig(t *testing.T) {
	manager := NewConfigManager("/test/path/config.yaml")
	cfg := manager.GetClusterConfig()
	assert.Nil(t, cfg)
}

// TestConfigManager_SetBaseConfig tests ConfigManager SetBaseConfig
// TestConfigManager_SetBaseConfig 测试 ConfigManager SetBaseConfig
func TestConfigManager_SetBaseConfig(t *testing.T) {
	manager := NewConfigManager("/test/path/config.yaml")
	manager.SetBaseConfig(types.BaseConfig{})
}

// TestConfigManager_SetWebConfig tests ConfigManager SetWebConfig
// TestConfigManager_SetWebConfig 测试 ConfigManager SetWebConfig
func TestConfigManager_SetWebConfig(t *testing.T) {
	manager := NewConfigManager("/test/path/config.yaml")
	manager.SetWebConfig(types.WebConfig{})
}

// TestConfigManager_SetMetricsConfig tests ConfigManager SetMetricsConfig
// TestConfigManager_SetMetricsConfig 测试 ConfigManager SetMetricsConfig
func TestConfigManager_SetMetricsConfig(t *testing.T) {
	manager := NewConfigManager("/test/path/config.yaml")
	manager.SetMetricsConfig(types.MetricsConfig{})
}

// TestConfigManager_SetLoggingConfig tests ConfigManager SetLoggingConfig
// TestConfigManager_SetLoggingConfig 测试 ConfigManager SetLoggingConfig
func TestConfigManager_SetLoggingConfig(t *testing.T) {
	manager := NewConfigManager("/test/path/config.yaml")
	manager.SetLoggingConfig(types.LoggingConfig{})
}

// TestConfigManager_SetConntrackConfig tests ConfigManager SetConntrackConfig
// TestConfigManager_SetConntrackConfig 测试 ConfigManager SetConntrackConfig
func TestConfigManager_SetConntrackConfig(t *testing.T) {
	manager := NewConfigManager("/test/path/config.yaml")
	manager.SetConntrackConfig(types.ConntrackConfig{})
}

// TestConfigManager_SetRateLimitConfig tests ConfigManager SetRateLimitConfig
// TestConfigManager_SetRateLimitConfig 测试 ConfigManager SetRateLimitConfig
func TestConfigManager_SetRateLimitConfig(t *testing.T) {
	manager := NewConfigManager("/test/path/config.yaml")
	manager.SetRateLimitConfig(types.RateLimitConfig{})
}

// TestConfigManager_SetPortConfig tests ConfigManager SetPortConfig
// TestConfigManager_SetPortConfig 测试 ConfigManager SetPortConfig
func TestConfigManager_SetPortConfig(t *testing.T) {
	manager := NewConfigManager("/test/path/config.yaml")
	manager.SetPortConfig(types.PortConfig{})
}

// TestConfigManager_SetCapacityConfig tests ConfigManager SetCapacityConfig
// TestConfigManager_SetCapacityConfig 测试 ConfigManager SetCapacityConfig
func TestConfigManager_SetCapacityConfig(t *testing.T) {
	manager := NewConfigManager("/test/path/config.yaml")
	manager.SetCapacityConfig(types.CapacityConfig{})
}

// TestConfigManager_SetLogEngineConfig tests ConfigManager SetLogEngineConfig
// TestConfigManager_SetLogEngineConfig 测试 ConfigManager SetLogEngineConfig
func TestConfigManager_SetLogEngineConfig(t *testing.T) {
	manager := NewConfigManager("/test/path/config.yaml")
	manager.SetLogEngineConfig(types.LogEngineConfig{})
}

// TestConfigManager_SetAIConfig tests ConfigManager SetAIConfig
// TestConfigManager_SetAIConfig 测试 ConfigManager SetAIConfig
func TestConfigManager_SetAIConfig(t *testing.T) {
	manager := NewConfigManager("/test/path/config.yaml")
	manager.SetAIConfig(types.AIConfig{})
}

// TestConfigManager_SetMCPConfig tests ConfigManager SetMCPConfig
// TestConfigManager_SetMCPConfig 测试 ConfigManager SetMCPConfig
func TestConfigManager_SetMCPConfig(t *testing.T) {
	manager := NewConfigManager("/test/path/config.yaml")
	manager.SetMCPConfig(types.MCPConfig{})
}

// TestConfigManager_SetClusterConfig tests ConfigManager SetClusterConfig
// TestConfigManager_SetClusterConfig 测试 ConfigManager SetClusterConfig
func TestConfigManager_SetClusterConfig(t *testing.T) {
	manager := NewConfigManager("/test/path/config.yaml")
	manager.SetClusterConfig(types.ClusterConfig{})
}

// TestLoadGlobalConfig tests LoadGlobalConfig function
// TestLoadGlobalConfig 测试 LoadGlobalConfig 函数
func TestLoadGlobalConfig(t *testing.T) {
	// Reset the singleton for testing
	// 重置单例以进行测试
	ConfigManagerInstance = nil

	// Create a temp config file
	// 创建临时配置文件
	tmpDir, err := os.MkdirTemp("", "config_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "config.yaml")
	configContent := `
base:
  default_deny: true
web:
  enabled: true
  port: 8080
`
	err = os.WriteFile(configPath, []byte(configContent), 0644)
	assert.NoError(t, err)

	// Create new manager
	// 创建新管理器
	ConfigManagerInstance = NewConfigManager(configPath)

	err = LoadGlobalConfig()
	assert.NoError(t, err)
}

// TestSaveGlobalConfig tests SaveGlobalConfig function
// TestSaveGlobalConfig 测试 SaveGlobalConfig 函数
func TestSaveGlobalConfig(t *testing.T) {
	// Reset the singleton
	// 重置单例
	ConfigManagerInstance = nil

	tmpDir, err := os.MkdirTemp("", "config_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "config.yaml")

	// Create manager with test config
	// 使用测试配置创建管理器
	ConfigManagerInstance = NewConfigManager(configPath)

	// Set some config
	// 设置一些配置
	cfg := &types.GlobalConfig{
		Base: types.BaseConfig{
			DefaultDeny: true,
		},
		Web: types.WebConfig{
			Enabled: true,
			Port:    9090,
		},
	}
	ConfigManagerInstance.UpdateConfig(cfg)

	err = SaveGlobalConfig()
	assert.NoError(t, err)

	// Verify file was created
	// 验证文件已创建
	_, err = os.Stat(configPath)
	assert.NoError(t, err)
}

// TestGetCurrentConfig tests GetCurrentConfig function
// TestGetCurrentConfig 测试 GetCurrentConfig 函数
func TestGetCurrentConfig(t *testing.T) {
	// Reset the singleton
	// 重置单例
	ConfigManagerInstance = nil

	tmpDir, err := os.MkdirTemp("", "config_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "config.yaml")
	ConfigManagerInstance = NewConfigManager(configPath)

	// Load config first
	// 先加载配置
	_ = ConfigManagerInstance.LoadConfig()

	cfg := GetCurrentConfig()
	// Config may be nil if file doesn't exist
	// 如果文件不存在，配置可能为 nil
	_ = cfg
}

// TestConfigManager_LoadConfig tests ConfigManager LoadConfig
// TestConfigManager_LoadConfig 测试 ConfigManager LoadConfig
func TestConfigManager_LoadConfig(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "config_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "config.yaml")
	configContent := `
base:
  default_deny: false
  whitelist:
    - 192.168.1.0/24
web:
  enabled: true
  port: 11811
`
	err = os.WriteFile(configPath, []byte(configContent), 0644)
	assert.NoError(t, err)

	manager := NewConfigManager(configPath)
	err = manager.LoadConfig()
	assert.NoError(t, err)

	cfg := manager.GetConfig()
	assert.NotNil(t, cfg)
	assert.False(t, cfg.Base.DefaultDeny)
}

// TestConfigManager_SaveConfig tests ConfigManager SaveConfig
// TestConfigManager_SaveConfig 测试 ConfigManager SaveConfig
func TestConfigManager_SaveConfig(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "config_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "config.yaml")
	manager := NewConfigManager(configPath)

	cfg := &types.GlobalConfig{
		Base: types.BaseConfig{
			DefaultDeny: true,
		},
	}
	manager.UpdateConfig(cfg)

	err = manager.SaveConfig()
	assert.NoError(t, err)

	// Verify file exists
	// 验证文件存在
	_, err = os.Stat(configPath)
	assert.NoError(t, err)
}

// TestLoadMap_NonExistent tests loading a non-existent map
// TestLoadMap_NonExistent 测试加载不存在的 Map
func TestLoadMap_NonExistent(t *testing.T) {
	_, err := LoadMap("non_existent_map")
	assert.Error(t, err)
}

// TestConfigManager_Validate tests ConfigManager Validate method
// TestConfigManager_Validate 测试 ConfigManager Validate 方法
func TestConfigManager_Validate(t *testing.T) {
	t.Run("Nil config", func(t *testing.T) {
		manager := NewConfigManager("/test/path/config.yaml")
		err := manager.Validate()
		assert.NoError(t, err)
	})

	t.Run("Valid config", func(t *testing.T) {
		manager := NewConfigManager("/test/path/config.yaml")
		cfg := &types.GlobalConfig{
			Base: types.BaseConfig{
				DefaultDeny: true,
			},
			Web: types.WebConfig{
				Enabled: true,
				Port:    8080,
			},
		}
		manager.UpdateConfig(cfg)

		err := manager.Validate()
		assert.NoError(t, err)
	})

	t.Run("Invalid config", func(t *testing.T) {
		manager := NewConfigManager("/test/path/config.yaml")
		cfg := &types.GlobalConfig{
			Base: types.BaseConfig{
				LockListV4Mask: -1, // Invalid mask
			},
		}
		manager.UpdateConfig(cfg)

		err := manager.Validate()
		assert.Error(t, err)
	})
}
