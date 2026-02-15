package web

import (
	"testing"

	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/pkg/sdk"
	"github.com/stretchr/testify/assert"
)

func TestWebPlugin_DefaultConfig(t *testing.T) {
	p := &WebPlugin{}
	cfg := p.DefaultConfig()
	assert.IsType(t, types.WebConfig{}, cfg)
	webCfg := cfg.(types.WebConfig)
	assert.True(t, webCfg.Enabled)
	assert.Equal(t, 11811, webCfg.Port)
}

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
					Port:    0, // Should be ignored if validation logic checks enabled first?
					// Wait, the validation logic is: if cfg.Web.Enabled { check port }
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
	assert.NotNil(t, p.api)
	assert.Equal(t, 11811, p.config.Port)
}
