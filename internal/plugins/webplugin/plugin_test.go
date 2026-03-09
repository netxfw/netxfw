package web

import (
	"testing"
	"time"

	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/netxfw/netxfw/pkg/sdk"
	"github.com/stretchr/testify/assert"
)

// TestWebPlugin_DefaultConfig tests the default config
// TestWebPlugin_DefaultConfig 测试默认配置
func TestWebPlugin_DefaultConfig(t *testing.T) {
	p := &WebPlugin{}
	cfg := p.DefaultConfig()
	assert.IsType(t, types.WebConfig{}, cfg)
	webCfg := cfg.(types.WebConfig)
	assert.True(t, webCfg.Enabled)
	assert.Equal(t, 11811, webCfg.Port)
}

// TestWebPlugin_Validate tests config validation
// TestWebPlugin_Validate 测试配置验证
func TestWebPlugin_Validate(t *testing.T) {
	p := &WebPlugin{}

	tests := []struct {
		name    string
		cfg     *types.GlobalConfig
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: &types.GlobalConfig{
				Web: types.WebConfig{
					Enabled: true,
					Port:    8080,
				},
			},
			wantErr: false,
		},
		{
			name: "invalid port low",
			cfg: &types.GlobalConfig{
				Web: types.WebConfig{
					Enabled: true,
					Port:    0,
				},
			},
			wantErr: true,
		},
		{
			name: "invalid port high",
			cfg: &types.GlobalConfig{
				Web: types.WebConfig{
					Enabled: true,
					Port:    70000,
				},
			},
			wantErr: true,
		},
		{
			name: "disabled valid port",
			cfg: &types.GlobalConfig{
				Web: types.WebConfig{
					Enabled: false,
					Port:    0,
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := p.Validate(tt.cfg)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestWebPlugin_Init tests plugin initialization
// TestWebPlugin_Init 测试插件初始化
func TestWebPlugin_Init(t *testing.T) {
	p := &WebPlugin{}
	ctx := &sdk.PluginContext{
		Config: &types.GlobalConfig{
			Web: types.WebConfig{
				Enabled: true,
				Port:    11811,
			},
		},
		SDK: &sdk.SDK{}, // Mock SDK if needed
	}

	err := p.Init(ctx)
	assert.NoError(t, err)
}

// TestWebPlugin_Name tests plugin name
// TestWebPlugin_Name 测试插件名称
func TestWebPlugin_Name(t *testing.T) {
	p := &WebPlugin{}
	assert.Equal(t, "web", p.Name())
}

// TestWebPlugin_Type tests plugin type
// TestWebPlugin_Type 测试插件类型
func TestWebPlugin_Type(t *testing.T) {
	p := &WebPlugin{}
	assert.Equal(t, sdk.PluginTypeExtension, p.Type())
}

// TestWebPlugin_Stop tests plugin stop
// TestWebPlugin_Stop 测试插件停止
func TestWebPlugin_Stop(t *testing.T) {
	p := &WebPlugin{}
	err := p.Stop()
	assert.NoError(t, err)
}

// TestWebPlugin_Stop_WithServer tests plugin stop with server
// TestWebPlugin_Stop_WithServer 测试带服务器的插件停止
func TestWebPlugin_Stop_WithServer(t *testing.T) {
	p := &WebPlugin{
		config: &types.WebConfig{
			Enabled: true,
			Port:    11819,
		},
	}
	ctx := &sdk.PluginContext{
		Config: &types.GlobalConfig{
			Web: types.WebConfig{
				Enabled: true,
				Port:    11819,
			},
		},
		SDK: &sdk.SDK{},
	}

	p.Init(ctx)
	err := p.Stop()
	assert.NoError(t, err)
}

// TestWebPlugin_Reload tests plugin reload
// TestWebPlugin_Reload 测试插件重载
func TestWebPlugin_Reload(t *testing.T) {
	p := &WebPlugin{}
	ctx := &sdk.PluginContext{
		Config: &types.GlobalConfig{
			Web: types.WebConfig{
				Enabled: true,
				Port:    11820,
			},
		},
		SDK: &sdk.SDK{},
	}

	err := p.Reload(ctx)
	assert.NoError(t, err)
}

// TestWebPlugin_Start_Disabled tests plugin start when disabled
// TestWebPlugin_Start_Disabled 测试禁用时的插件启动
func TestWebPlugin_Start_Disabled(t *testing.T) {
	p := &WebPlugin{
		config: &types.WebConfig{
			Enabled: false,
			Port:    11821,
		},
	}
	ctx := &sdk.PluginContext{
		Config: &types.GlobalConfig{
			Web: types.WebConfig{
				Enabled: false,
				Port:    11821,
			},
		},
		SDK:    &sdk.SDK{},
		Logger: &MockLogger{},
	}

	err := p.Start(ctx)
	assert.NoError(t, err)
	assert.False(t, p.running)
}

// TestWebPlugin_CollectStats tests collectStats method
// TestWebPlugin_CollectStats 测试 collectStats 方法
func TestWebPlugin_CollectStats(t *testing.T) {
	p := &WebPlugin{
		config: &types.WebConfig{
			Enabled: true,
			Port:    11822,
		},
		running: true,
	}

	// Create a simple context with mock SDK
	ctx := &sdk.PluginContext{
		Config: &types.GlobalConfig{
			Web: types.WebConfig{
				Enabled: true,
				Port:    11822,
			},
		},
		SDK:    &sdk.SDK{},
		Logger: &MockLogger{},
	}

	// Run collectStats in goroutine and stop quickly
	go func() {
		time.Sleep(100 * time.Millisecond)
		p.setRunning(false)
	}()

	p.collectStats(ctx)
}

// MockLogger is a mock implementation of sdk.Logger
// MockLogger 是 sdk.Logger 的模拟实现
type MockLogger struct{}

// Infof implements sdk.Logger
func (m *MockLogger) Infof(format string, args ...interface{})  {}
func (m *MockLogger) Warnf(format string, args ...interface{})  {}
func (m *MockLogger) Errorf(format string, args ...interface{}) {}
