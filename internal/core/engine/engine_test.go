package engine

import (
	"testing"

	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/xdp"
	"github.com/livp123/netxfw/pkg/sdk"
	"github.com/stretchr/testify/assert"
)

// TestLogger implements sdk.Logger for testing
// TestLogger 实现 sdk.Logger 用于测试
type TestLogger struct {
	t *testing.T
}

// Infof logs an info message
// Infof 记录信息消息
func (l *TestLogger) Infof(format string, args ...interface{}) {
	l.t.Logf("[INFO] "+format, args...)
}

// Warnf logs a warning message
// Warnf 记录警告消息
func (l *TestLogger) Warnf(format string, args ...interface{}) {
	l.t.Logf("[WARN] "+format, args...)
}

// Errorf logs an error message
// Errorf 记录错误消息
func (l *TestLogger) Errorf(format string, args ...interface{}) {
	l.t.Logf("[ERROR] "+format, args...)
}

// TestCoreModules tests the core engine modules
// TestCoreModules 测试核心引擎模块
func TestCoreModules(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)
	logger := &TestLogger{t: t}
	globalCfg := &types.GlobalConfig{
		Base: types.BaseConfig{
			DefaultDeny:        true,
			AllowReturnTraffic: true,
		},
		Conntrack: types.ConntrackConfig{
			Enabled:    true,
			TCPTimeout: "1h",
		},
		Port: types.PortConfig{
			AllowedPorts: []uint16{80, 443},
			IPPortRules: []types.IPPortRule{
				{IP: "192.168.1.100", Port: 22, Action: 1}, // Allow SSH
			},
		},
		RateLimit: types.RateLimitConfig{
			Enabled:   true,
			AutoBlock: true,
			Rules: []types.RateLimitRule{
				{IP: "10.0.0.1", Rate: 100, Burst: 10},
			},
		},
	}

	t.Run("BaseModule", func(t *testing.T) {
		mod := &BaseModule{}
		if err := mod.Init(globalCfg, s, logger); err != nil {
			t.Fatalf("Init failed: %v", err)
		}
		if err := mod.Start(); err != nil {
			t.Fatalf("Start failed: %v", err)
		}
		// Verify Base settings
		// Note: Since MockManager is internal, we can't easily check internal state here
		// unless we export it or add getters to MockManager.
		// For now, we rely on no error returned.
		// 验证 Base 设置
		// 注意：由于 MockManager 是内部的，我们无法轻易检查内部状态
		// 除非我们导出它或向 MockManager 添加 getter 方法
		// 目前，我们依赖没有返回错误
	})

	t.Run("ConntrackModule", func(t *testing.T) {
		mod := &ConntrackModule{}
		if err := mod.Init(globalCfg, s, logger); err != nil {
			t.Fatalf("Init failed: %v", err)
		}
		if err := mod.Start(); err != nil {
			t.Fatalf("Start failed: %v", err)
		}
	})

	t.Run("PortModule", func(t *testing.T) {
		mod := &PortModule{}
		if err := mod.Init(globalCfg, s, logger); err != nil {
			t.Fatalf("Init failed: %v", err)
		}
		if err := mod.Start(); err != nil {
			t.Fatalf("Start failed: %v", err)
		}
		// Verify Port settings via Manager
		// 通过 Manager 验证端口设置
		ports, _ := mockMgr.ListAllowedPorts()
		found80 := false
		for _, p := range ports {
			if p == 80 {
				found80 = true
				break
			}
		}
		if !found80 {
			t.Errorf("Port 80 should be allowed")
		}
	})

	t.Run("RateLimitModule", func(t *testing.T) {
		mod := &RateLimitModule{}
		if err := mod.Init(globalCfg, s, logger); err != nil {
			t.Fatalf("Init failed: %v", err)
		}
		if err := mod.Start(); err != nil {
			t.Fatalf("Start failed: %v", err)
		}
		// Verify RateLimit settings
		// 验证速率限制设置
		rules, _, _ := mockMgr.ListRateLimitRules(0, "")
		found := false
		for ip := range rules {
			if ip == "10.0.0.1" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("RateLimit rule for 10.0.0.1 not found")
		}
	})
}

// TestBaseModule_Name tests BaseModule Name method
// TestBaseModule_Name 测试 BaseModule Name 方法
func TestBaseModule_Name(t *testing.T) {
	mod := &BaseModule{}
	assert.Equal(t, "base", mod.Name())
}

// TestBaseModule_Reload tests BaseModule Reload method
// TestBaseModule_Reload 测试 BaseModule Reload 方法
func TestBaseModule_Reload(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)
	logger := &TestLogger{t: t}
	globalCfg := &types.GlobalConfig{
		Base: types.BaseConfig{
			DefaultDeny: true,
		},
	}

	mod := &BaseModule{}
	err := mod.Init(globalCfg, s, logger)
	assert.NoError(t, err)

	err = mod.Reload(globalCfg)
	assert.NoError(t, err)
}

// TestBaseModule_Stop tests BaseModule Stop method
// TestBaseModule_Stop 测试 BaseModule Stop 方法
func TestBaseModule_Stop(t *testing.T) {
	mod := &BaseModule{}
	err := mod.Stop()
	assert.NoError(t, err)
}

// TestConntrackModule_Name tests ConntrackModule Name method
// TestConntrackModule_Name 测试 ConntrackModule Name 方法
func TestConntrackModule_Name(t *testing.T) {
	mod := &ConntrackModule{}
	assert.Equal(t, "conntrack", mod.Name())
}

// TestConntrackModule_Reload tests ConntrackModule Reload method
// TestConntrackModule_Reload 测试 ConntrackModule Reload 方法
func TestConntrackModule_Reload(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)
	logger := &TestLogger{t: t}
	globalCfg := &types.GlobalConfig{
		Conntrack: types.ConntrackConfig{
			Enabled:    true,
			TCPTimeout: "1h",
		},
	}

	mod := &ConntrackModule{}
	err := mod.Init(globalCfg, s, logger)
	assert.NoError(t, err)

	err = mod.Reload(globalCfg)
	assert.NoError(t, err)
}

// TestConntrackModule_Stop tests ConntrackModule Stop method
// TestConntrackModule_Stop 测试 ConntrackModule Stop 方法
func TestConntrackModule_Stop(t *testing.T) {
	mod := &ConntrackModule{}
	err := mod.Stop()
	assert.NoError(t, err)
}

// TestPortModule_Name tests PortModule Name method
// TestPortModule_Name 测试 PortModule Name 方法
func TestPortModule_Name(t *testing.T) {
	mod := &PortModule{}
	assert.Equal(t, "port", mod.Name())
}

// TestPortModule_Reload tests PortModule Reload method
// TestPortModule_Reload 测试 PortModule Reload 方法
func TestPortModule_Reload(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)
	logger := &TestLogger{t: t}
	globalCfg := &types.GlobalConfig{
		Port: types.PortConfig{
			AllowedPorts: []uint16{80, 443},
		},
	}

	mod := &PortModule{}
	err := mod.Init(globalCfg, s, logger)
	assert.NoError(t, err)

	err = mod.Reload(globalCfg)
	assert.NoError(t, err)
}

// TestPortModule_Stop tests PortModule Stop method
// TestPortModule_Stop 测试 PortModule Stop 方法
func TestPortModule_Stop(t *testing.T) {
	mod := &PortModule{}
	err := mod.Stop()
	assert.NoError(t, err)
}

// TestRateLimitModule_Name tests RateLimitModule Name method
// TestRateLimitModule_Name 测试 RateLimitModule Name 方法
func TestRateLimitModule_Name(t *testing.T) {
	mod := &RateLimitModule{}
	assert.Equal(t, "ratelimit", mod.Name())
}

// TestRateLimitModule_Reload tests RateLimitModule Reload method
// TestRateLimitModule_Reload 测试 RateLimitModule Reload 方法
func TestRateLimitModule_Reload(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)
	logger := &TestLogger{t: t}
	globalCfg := &types.GlobalConfig{
		RateLimit: types.RateLimitConfig{
			Enabled: true,
		},
	}

	mod := &RateLimitModule{}
	err := mod.Init(globalCfg, s, logger)
	assert.NoError(t, err)

	err = mod.Reload(globalCfg)
	assert.NoError(t, err)
}

// TestRateLimitModule_Stop tests RateLimitModule Stop method
// TestRateLimitModule_Stop 测试 RateLimitModule Stop 方法
func TestRateLimitModule_Stop(t *testing.T) {
	mod := &RateLimitModule{}
	err := mod.Stop()
	assert.NoError(t, err)
}
