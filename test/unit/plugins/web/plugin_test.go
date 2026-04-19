package web_test

import (
	"net/http"
	"testing"

	web "github.com/netxfw/netxfw/internal/plugins/webplugin"
	sdk "github.com/netxfw/netxfw/pkg/sdk"
	"github.com/stretchr/testify/assert"
)

type stubWebHost struct{}

func (s *stubWebHost) EnsureHandlerInitialized() error { return nil }
func (s *stubWebHost) APIHandler() http.Handler        { return http.NewServeMux() }
func (s *stubWebHost) UIHandler() http.Handler         { return http.NewServeMux() }

// TestWebPlugin_DefaultConfig tests the default config
// TestWebPlugin_DefaultConfig 测试默认配置
func TestWebPlugin_DefaultConfig(t *testing.T) {
	p := &web.WebPlugin{}
	cfg := p.DefaultConfig()
	assert.IsType(t, sdk.WebConfig{}, cfg)
	webCfg := cfg.(sdk.WebConfig)
	assert.True(t, webCfg.Enabled)
	assert.Equal(t, 11811, webCfg.Port)
}

// TestWebPlugin_Validate tests config validation
// TestWebPlugin_Validate 测试配置验证
func TestWebPlugin_Validate(t *testing.T) {
	p := &web.WebPlugin{}

	tests := []struct {
		name    string
		cfg     *sdk.GlobalConfig
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: &sdk.GlobalConfig{
				Web: sdk.WebConfig{
					Enabled: true,
					Port:    8080,
				},
			},
			wantErr: false,
		},
		{
			name: "invalid port low",
			cfg: &sdk.GlobalConfig{
				Web: sdk.WebConfig{
					Enabled: true,
					Port:    0,
				},
			},
			wantErr: true,
		},
		{
			name: "invalid port high",
			cfg: &sdk.GlobalConfig{
				Web: sdk.WebConfig{
					Enabled: true,
					Port:    70000,
				},
			},
			wantErr: true,
		},
		{
			name: "disabled valid port",
			cfg: &sdk.GlobalConfig{
				Web: sdk.WebConfig{
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
	p := &web.WebPlugin{}
	ctx := &sdk.RuntimePluginContext{
		Config: &sdk.GlobalConfig{
			Web: sdk.WebConfig{
				Enabled: true,
				Port:    11811,
			},
		},
		SDK: &sdk.SDK{}, // Mock SDK if needed
		Web: &stubWebHost{},
	}

	err := p.Init(ctx)
	assert.NoError(t, err)
}
