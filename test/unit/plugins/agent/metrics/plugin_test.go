package metrics_test

import (
	"testing"

	"github.com/netxfw/netxfw/internal/plugins/agent/metrics"
	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/netxfw/netxfw/pkg/sdk"
	"github.com/stretchr/testify/assert"
)

// TestMetricsPlugin_DefaultConfig tests the default config
// TestMetricsPlugin_DefaultConfig 测试默认配置
func TestMetricsPlugin_DefaultConfig(t *testing.T) {
	p := &metrics.MetricsPlugin{}
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
	p := &metrics.MetricsPlugin{}

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
	p := &metrics.MetricsPlugin{}
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
