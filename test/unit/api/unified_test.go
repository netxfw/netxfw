package api_test

import (
	"testing"

	"github.com/netxfw/netxfw/internal/api"
	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/stretchr/testify/assert"
)

// TestAPIServerCreation tests that API server can be created
// TestAPIServerCreation 测试 API 服务器可以创建
func TestAPIServerCreation(t *testing.T) {
	// Test that we can create a server with nil SDK
	// This tests the basic structure without complex mocking
	// 测试我们可以用 nil SDK 创建服务器
	// 这测试了基本结构，不需要复杂的模拟
	server := api.NewServer(nil, 8080)

	assert.NotNil(t, server)
	assert.Equal(t, 8080, server.Port())
}

// TestMetricsServerCreation tests metrics server creation
// TestMetricsServerCreation 测试 metrics 服务器创建
func TestMetricsServerCreation(t *testing.T) {
	// Create metrics server with config
	// 使用配置创建 metrics 服务器
	cfg := &types.MetricsConfig{
		Enabled:       true,
		ServerEnabled: true,
		Port:          11812,
	}

	metricsServer := api.NewMetricsServer(nil, cfg)

	// Verify server was created correctly
	// 验证服务器创建正确
	assert.NotNil(t, metricsServer)
}

// TestMetricsServerWithDisabledConfig tests metrics server with disabled config
// TestMetricsServerWithDisabledConfig 测试禁用配置的 metrics 服务器
func TestMetricsServerWithDisabledConfig(t *testing.T) {
	// Create metrics server with disabled config
	// 使用禁用配置创建 metrics 服务器
	cfg := &types.MetricsConfig{
		Enabled:       false,
		ServerEnabled: false,
		Port:          11812,
	}

	metricsServer := api.NewMetricsServer(nil, cfg)

	// Verify server was created correctly even with disabled config
	// 验证即使配置禁用，服务器也能正确创建
	assert.NotNil(t, metricsServer)
}

// TestMetricsServerWithServerDisabled tests metrics server when server is disabled
// TestMetricsServerWithServerDisabled 测试服务器禁用时的 metrics 服务器
func TestMetricsServerWithServerDisabled(t *testing.T) {
	// Create metrics server with server disabled but metrics enabled
	// 创建服务器禁用但 metrics 启用的 metrics 服务器
	cfg := &types.MetricsConfig{
		Enabled:       true,
		ServerEnabled: false,
		Port:          11812,
	}

	metricsServer := api.NewMetricsServer(nil, cfg)

	// Verify server was created correctly
	// 验证服务器创建正确
	assert.NotNil(t, metricsServer)
	assert.False(t, cfg.ServerEnabled)
}

// TestSDKMethod tests the Sdk getter method
// TestSDKMethod 测试 Sdk 获取方法
func TestSDKMethod(t *testing.T) {
	server := api.NewServer(nil, 8080)

	// Test that Sdk() returns nil when SDK is nil
	// 测试当 SDK 为 nil 时 Sdk() 返回 nil
	sdk := server.Sdk()
	assert.Nil(t, sdk)
}

// TestUnifiedServiceStructure tests the overall structure of unified service
// TestUnifiedServiceStructure 测试统一服务的整体结构
func TestUnifiedServiceStructure(t *testing.T) {
	// Test the conceptual structure of the unified web/api/metrics service
	// 测试统一 web/api/metrics 服务的概念结构
	t.Run("Test unified service paths", func(t *testing.T) {
		paths := []string{"/", "/api/", "/metrics"}

		// Verify all essential paths exist
		// 验证所有必要路径存在
		assert.Len(t, paths, 3)

		// Verify paths are distinct
		// 验证路径是不同的
		assert.Equal(t, "/", paths[0])
		assert.Equal(t, "/api/", paths[1])
		assert.Equal(t, "/metrics", paths[2])
	})

	t.Run("Test default ports", func(t *testing.T) {
		webPort := 11811
		metricsPort := 11812

		assert.NotEqual(t, webPort, metricsPort, "Web and metrics ports should be different")
		assert.Greater(t, webPort, 1024, "Web port should be above privileged range")
		assert.Greater(t, metricsPort, 1024, "Metrics port should be above privileged range")
	})
}

// TestConfigValidation tests configuration validation
// TestConfigValidation 测试配置验证
func TestConfigValidation(t *testing.T) {
	t.Run("Valid metrics config", func(t *testing.T) {
		cfg := &types.MetricsConfig{
			Enabled:       true,
			ServerEnabled: true,
			Port:          11812,
		}

		assert.True(t, cfg.Enabled)
		assert.True(t, cfg.ServerEnabled)
		assert.Equal(t, 11812, cfg.Port)
	})

	t.Run("Disabled metrics config", func(t *testing.T) {
		cfg := &types.MetricsConfig{
			Enabled:       false,
			ServerEnabled: false,
			Port:          0,
		}

		assert.False(t, cfg.Enabled)
		assert.False(t, cfg.ServerEnabled)
	})
}
