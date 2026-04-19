package config_test

import (
	"path/filepath"
	"sync"
	"testing"

	"github.com/netxfw/netxfw/internal/adapters/configfile"
	appconfig "github.com/netxfw/netxfw/internal/app/config"
	domainconfig "github.com/netxfw/netxfw/internal/domain/config"
	"github.com/stretchr/testify/assert"
)

// TestConfigPersistence tests saving/loading config via app/domain config APIs.
// TestConfigPersistence 测试通过 app/domain 配置 API 保存和加载配置。
func TestConfigPersistence(t *testing.T) {
	tmpDir := t.TempDir()
	tempConfigFile := filepath.Join(tmpDir, "config.toml")

	defaultCfg := &domainconfig.Config{
		Base: domainconfig.BaseConfig{
			DefaultDeny:        true,
			AllowReturnTraffic: true,
			AllowICMP:          true,
			Interfaces:         []string{"lo"},
			EnableAFXDP:        false,
		},
		Web: domainconfig.WebConfig{
			Enabled: true,
			Port:    8080,
			Token:   "test-token",
		},
		Metrics: domainconfig.MetricsConfig{
			Enabled: true,
			Port:    9090,
		},
	}

	originalPath := appconfig.GetConfigPath()
	appconfig.SetConfigPath(tempConfigFile)
	defer appconfig.SetConfigPath(originalPath)

	err := appconfig.DefaultWriteGateway().SaveConfig(tempConfigFile, defaultCfg, 3, "test/unit/config.TestConfigPersistence")
	assert.NoError(t, err)

	loadedCfg, err := appconfig.LoadConfig()
	assert.NoError(t, err)
	assert.NotNil(t, loadedCfg)
	assert.Equal(t, defaultCfg.Base.DefaultDeny, loadedCfg.Base.DefaultDeny)
	assert.Equal(t, defaultCfg.Web.Port, loadedCfg.Web.Port)
	assert.Equal(t, defaultCfg.Metrics.Port, loadedCfg.Metrics.Port)

	baseCfg := loadedCfg.Base
	assert.Equal(t, defaultCfg.Base.DefaultDeny, baseCfg.DefaultDeny)

	webCfg := loadedCfg.Web
	assert.Equal(t, defaultCfg.Web.Port, webCfg.Port)

	metricsCfg := loadedCfg.Metrics
	assert.Equal(t, defaultCfg.Metrics.Port, metricsCfg.Port)

	loadedCfg.Base = domainconfig.BaseConfig{
		DefaultDeny:        false,
		AllowReturnTraffic: false,
		AllowICMP:          false,
		Interfaces:         []string{"eth0"},
		EnableAFXDP:        true,
	}
	assert.NoError(t, appconfig.DefaultWriteGateway().SaveConfig(tempConfigFile, loadedCfg, 3, "test/unit/config.TestConfigPersistence.update"))

	reloadedCfg, err := configfile.Load(tempConfigFile)
	assert.NoError(t, err)
	assert.Equal(t, loadedCfg.Base.DefaultDeny, reloadedCfg.Base.DefaultDeny)
	assert.Equal(t, loadedCfg.Base.EnableAFXDP, reloadedCfg.Base.EnableAFXDP)
}

// TestConfigPathSingletonBehavior tests the shared config path behavior.
// TestConfigPathSingletonBehavior 测试共享配置路径行为。
func TestConfigPathSingletonBehavior(t *testing.T) {
	originalPath := appconfig.GetConfigPath()
	appconfig.SetConfigPath("/tmp/test_singleton_config.toml")
	defer appconfig.SetConfigPath(originalPath)

	instance1 := appconfig.GetConfigPath()
	instance2 := appconfig.GetConfigPath()

	assert.Equal(t, instance1, instance2)
	assert.NotEmpty(t, instance1)
}

// TestConfigConcurrentAccess tests concurrent read/write access through clone/load helpers.
// TestConfigConcurrentAccess 测试通过 clone/load 辅助方法进行并发读写访问。
func TestConfigConcurrentAccess(t *testing.T) {
	cfg := &domainconfig.Config{}
	var wg sync.WaitGroup

	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			newCfg := &domainconfig.Config{
				Base: domainconfig.BaseConfig{
					DefaultDeny: i%2 == 0,
				},
			}
			cfg = configfile.Clone(newCfg)
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			current := configfile.Clone(cfg)
			if current != nil {
				_ = current.Base.DefaultDeny
			}
		}
	}()

	wg.Wait()
}
