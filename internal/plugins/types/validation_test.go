package types

import (
	"testing"
)

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  GlobalConfig
		wantErr bool
	}{
		{
			name: "Valid Config",
			config: GlobalConfig{
				Base: BaseConfig{
					LockListV4Mask: 24,
					LockListV6Mask: 64,
					Whitelist:      []string{"127.0.0.1/32", "192.168.1.1"},
				},
				Port: PortConfig{
					IPPortRules: []IPPortRule{
						{IP: "10.0.0.1", Port: 80, Action: 1},
					},
				},
				RateLimit: RateLimitConfig{
					Rules: []RateLimitRule{
						{IP: "10.0.0.0/24"},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Invalid V4 Mask",
			config: GlobalConfig{
				Base: BaseConfig{
					LockListV4Mask: 33,
				},
			},
			wantErr: true,
		},
		{
			name: "Invalid Whitelist CIDR",
			config: GlobalConfig{
				Base: BaseConfig{
					Whitelist: []string{"invalid-ip"},
				},
			},
			wantErr: true,
		},
		{
			name: "Invalid Port",
			config: GlobalConfig{
				Port: PortConfig{
					IPPortRules: []IPPortRule{
						{IP: "10.0.0.1", Port: 0, Action: 1},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "Invalid Action",
			config: GlobalConfig{
				Port: PortConfig{
					IPPortRules: []IPPortRule{
						{IP: "10.0.0.1", Port: 80, Action: 3},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "Invalid RateLimit CIDR",
			config: GlobalConfig{
				RateLimit: RateLimitConfig{
					Rules: []RateLimitRule{
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
}
