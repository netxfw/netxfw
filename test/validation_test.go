package types

import (
	"github.com/livp123/netxfw/internal/plugins/types"
	"testing"
)

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  types.GlobalConfig
		wantErr bool
	}{
		{
			name: "Valid Config",
			config: types.GlobalConfig{
				Base: types.BaseConfig{
					LockListV4Mask: 24,
					LockListV6Mask: 64,
					Whitelist:      []string{"127.0.0.1/32", "192.168.1.1"},
				},
				Port: types.PortConfig{
					IPPortRules: []types.IPPortRule{
						{IP: "10.0.0.1", Port: 80, Action: 1},
					},
				},
				RateLimit: types.RateLimitConfig{
					Rules: []types.RateLimitRule{
						{IP: "10.0.0.0/24"},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Invalid V4 Mask",
			config: types.GlobalConfig{
				Base: types.BaseConfig{
					LockListV4Mask: 33,
				},
			},
			wantErr: true,
		},
		{
			name: "Invalid Whitelist CIDR",
			config: types.GlobalConfig{
				Base: types.BaseConfig{
					Whitelist: []string{"invalid-ip"},
				},
			},
			wantErr: true,
		},
		{
			name: "Invalid Port",
			config: types.GlobalConfig{
				Port: types.PortConfig{
					IPPortRules: []types.IPPortRule{
						{IP: "10.0.0.1", Port: 0, Action: 1},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "Invalid Action",
			config: types.GlobalConfig{
				Port: types.PortConfig{
					IPPortRules: []types.IPPortRule{
						{IP: "10.0.0.1", Port: 80, Action: 3},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "Invalid RateLimit CIDR",
			config: types.GlobalConfig{
				RateLimit: types.RateLimitConfig{
					Rules: []types.RateLimitRule{
						{IP: "999.999.999.999"},
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}

	t.Run("Conntrack Alignment", func(t *testing.T) {
		cfg := types.GlobalConfig{
			Conntrack: types.ConntrackConfig{
				MaxEntries: 50000,
			},
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate failed: %v", err)
		}
		if cfg.Capacity.Conntrack != 50000 {
			t.Errorf("Expected Capacity.Conntrack to be 50000, got %d", cfg.Capacity.Conntrack)
		}
	})
}
