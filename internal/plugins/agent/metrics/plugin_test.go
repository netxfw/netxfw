package metrics

import (
	"testing"

	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/pkg/sdk"
	"github.com/stretchr/testify/assert"
)

// TestMetricsPlugin_DefaultConfig tests the default config
// TestMetricsPlugin_DefaultConfig 测试默认配置
func TestMetricsPlugin_DefaultConfig(t *testing.T) {
	p := &MetricsPlugin{}
	cfg := p.DefaultConfig()
	assert.IsType(t, types.MetricsConfig{}, cfg)
	metricsCfg := cfg.(types.MetricsConfig)
	assert.True(t, metricsCfg.Enabled)
	assert.True(t, metricsCfg.ServerEnabled)
	assert.Equal(t, 11812, metricsCfg.Port)
}

// TestMetricsPlugin_Validate tests config validation
// TestMetricsPlugin_Validate 测试配置验证
func TestMetricsPlugin_Validate(t *testing.T) {
	p := &MetricsPlugin{}

	tests := []struct {
		name    string
		cfg     *types.GlobalConfig
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: &types.GlobalConfig{
				Metrics: types.MetricsConfig{
					Enabled:       true,
					ServerEnabled: true,
					Port:          8080,
				},
			},
			wantErr: false,
		},
		{
			name: "invalid port low",
			cfg: &types.GlobalConfig{
				Metrics: types.MetricsConfig{
					Enabled:       true,
					ServerEnabled: true,
					Port:          0,
				},
			},
			wantErr: true,
		},
		{
			name: "invalid port high",
			cfg: &types.GlobalConfig{
				Metrics: types.MetricsConfig{
					Enabled:       true,
					ServerEnabled: true,
					Port:          70000,
				},
			},
			wantErr: true,
		},
		{
			name: "disabled valid port",
			cfg: &types.GlobalConfig{
				Metrics: types.MetricsConfig{
					Enabled:       false,
					ServerEnabled: false,
					Port:          0,
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

// TestMetricsPlugin_Init tests plugin initialization
// TestMetricsPlugin_Init 测试插件初始化
func TestMetricsPlugin_Init(t *testing.T) {
	p := &MetricsPlugin{}
	ctx := &sdk.PluginContext{
		Config: &types.GlobalConfig{
			Metrics: types.MetricsConfig{
				Enabled:       true,
				ServerEnabled: true,
				Port:          11812,
			},
		},
		SDK: &sdk.SDK{}, // Mock SDK if needed
	}

	err := p.Init(ctx)
	assert.NoError(t, err)
}

// TestMetricsPlugin_Name tests plugin name
// TestMetricsPlugin_Name 测试插件名称
func TestMetricsPlugin_Name(t *testing.T) {
	p := &MetricsPlugin{}
	assert.Equal(t, "metrics", p.Name())
}

// TestMetricsPlugin_Type tests plugin type
// TestMetricsPlugin_Type 测试插件类型
func TestMetricsPlugin_Type(t *testing.T) {
	p := &MetricsPlugin{}
	assert.Equal(t, sdk.PluginTypeExtension, p.Type())
}

// TestMetricsPlugin_Stop tests plugin stop
// TestMetricsPlugin_Stop 测试插件停止
func TestMetricsPlugin_Stop(t *testing.T) {
	p := &MetricsPlugin{
		config: &types.MetricsConfig{
			Enabled:       false,
			ServerEnabled: false,
		},
	}
	err := p.Stop()
	assert.NoError(t, err)
}

// TestMetricsPlugin_Stop_WithServer tests plugin stop with server
// TestMetricsPlugin_Stop_WithServer 测试带服务器的插件停止
func TestMetricsPlugin_Stop_WithServer(t *testing.T) {
	p := &MetricsPlugin{
		config: &types.MetricsConfig{
			Enabled:       true,
			ServerEnabled: true,
			Port:          11816,
		},
	}
	ctx := &sdk.PluginContext{
		Config: &types.GlobalConfig{
			Metrics: types.MetricsConfig{
				Enabled:       true,
				ServerEnabled: true,
				Port:          11816,
			},
		},
		SDK: &sdk.SDK{},
	}

	p.Init(ctx)
	err := p.Stop()
	assert.NoError(t, err)
}
