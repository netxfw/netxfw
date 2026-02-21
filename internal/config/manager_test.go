package config

import (
	"os"
	"testing"

	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/stretchr/testify/assert"
)

// TestConfigManager tests the configuration manager functionality
// TestConfigManager 测试配置管理器功能
func TestConfigManager(t *testing.T) {
	// Create a temporary config file for testing
	// 为测试创建临时配置文件
	tempConfigFile := "/tmp/test_yaml"

	// Create default config
	// 创建默认配置
	defaultCfg := &types.GlobalConfig{
		Base: types.BaseConfig{
			DefaultDeny:        true,
			AllowReturnTraffic: true,
			AllowICMP:          true,
			Interfaces:         []string{"lo"},
			EnableAFXDP:        false,
		},
		Web: types.WebConfig{
			Enabled: true,
			Port:    8080,
			Token:   "test-token",
		},
		Metrics: types.MetricsConfig{
			Enabled: true,
			Port:    9090,
		},
	}

	// Save the config using the new manager
	// 使用新的管理器保存配置
	cfgManager := NewConfigManager(tempConfigFile)
	cfgManager.UpdateConfig(defaultCfg)

	// Save to file
	// 保存到文件
	err := cfgManager.SaveConfig()
	assert.NoError(t, err)

	// Load from file
	// 从文件加载
	err = cfgManager.LoadConfig()
	assert.NoError(t, err)

	// Get the loaded config
	// 获取加载的配置
	loadedCfg := cfgManager.GetConfig()
	assert.NotNil(t, loadedCfg)
	assert.Equal(t, defaultCfg.Base.DefaultDeny, loadedCfg.Base.DefaultDeny)
	assert.Equal(t, defaultCfg.Web.Port, loadedCfg.Web.Port)
	assert.Equal(t, defaultCfg.Metrics.Port, loadedCfg.Metrics.Port)

	// Test individual getters
	// 测试单独的 getter 方法
	baseCfg := cfgManager.GetBaseConfig()
	assert.Equal(t, defaultCfg.Base.DefaultDeny, baseCfg.DefaultDeny)

	webCfg := cfgManager.GetWebConfig()
	assert.Equal(t, defaultCfg.Web.Port, webCfg.Port)

	metricsCfg := cfgManager.GetMetricsConfig()
	assert.Equal(t, defaultCfg.Metrics.Port, metricsCfg.Port)

	// Test individual setters
	// 测试单独的 setter 方法
	newBaseCfg := types.BaseConfig{
		DefaultDeny:        false,
		AllowReturnTraffic: false,
		AllowICMP:          false,
		Interfaces:         []string{"eth0"},
		EnableAFXDP:        true,
	}
	cfgManager.SetBaseConfig(newBaseCfg)

	updatedBaseCfg := cfgManager.GetBaseConfig()
	assert.Equal(t, newBaseCfg.DefaultDeny, updatedBaseCfg.DefaultDeny)
	assert.Equal(t, newBaseCfg.EnableAFXDP, updatedBaseCfg.EnableAFXDP)

	// Clean up
	// 清理
	os.Remove(tempConfigFile)
	os.Remove(tempConfigFile + ".bak." + "*") // Remove any backup files
}

// TestConfigManagerSingleton tests the singleton instance
// TestConfigManagerSingleton 测试单例实例
func TestConfigManagerSingleton(t *testing.T) {
	// Test that the singleton instance works correctly
	// 测试单例实例正常工作
	instance1 := GetConfigManager()
	instance2 := GetConfigManager()

	assert.Equal(t, instance1, instance2)
	assert.NotNil(t, instance1)
}

// TestConfigManagerConcurrentAccess tests concurrent read/write access
// TestConfigManagerConcurrentAccess 测试并发读写访问
func TestConfigManagerConcurrentAccess(t *testing.T) {
	cfgManager := NewConfigManager("/tmp/concurrent_test.yaml")

	// Test concurrent read/write access
	// 测试并发读写访问
	done := make(chan bool)

	// Writer goroutine
	// 写入协程
	go func() {
		for i := 0; i < 10; i++ {
			newCfg := &types.GlobalConfig{
				Base: types.BaseConfig{
					DefaultDeny: i%2 == 0,
				},
			}
			cfgManager.UpdateConfig(newCfg)
		}
		done <- true
	}()

	// Reader goroutine
	// 读取协程
	go func() {
		for i := 0; i < 10; i++ {
			cfg := cfgManager.GetConfig()
			if cfg != nil {
				_ = cfg.Base.DefaultDeny // Access the value
			}
		}
		done <- true
	}()

	<-done
	<-done
}
