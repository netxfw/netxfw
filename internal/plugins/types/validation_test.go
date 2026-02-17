package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestGlobalConfig_Validate tests GlobalConfig validation
// TestGlobalConfig_Validate 测试 GlobalConfig 验证
func TestGlobalConfig_Validate(t *testing.T) {
	// Test valid config
	// 测试有效配置
	cfg := &GlobalConfig{
		Base: BaseConfig{
			LockListV4Mask: 24,
			LockListV6Mask: 64,
		},
		Port: PortConfig{
			IPPortRules: []IPPortRule{
				{IP: "192.168.1.1", Port: 80, Action: 1},
			},
		},
		RateLimit: RateLimitConfig{
			Rules: []RateLimitRule{
				{IP: "10.0.0.0/8", Rate: 1000, Burst: 100},
			},
		},
		LogEngine: LogEngineConfig{
			Rules: []LogEngineRule{
				{Path: "/var/log/test.log", Action: "block"},
			},
		},
	}
	err := cfg.Validate()
	assert.NoError(t, err)
}

// TestBaseConfig_Validate tests BaseConfig validation
// TestBaseConfig_Validate 测试 BaseConfig 验证
func TestBaseConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  BaseConfig
		wantErr bool
	}{
		{
			name: "Valid config",
			config: BaseConfig{
				LockListV4Mask: 24,
				LockListV6Mask: 64,
			},
			wantErr: false,
		},
		{
			name: "Invalid V4 mask - negative",
			config: BaseConfig{
				LockListV4Mask: -1,
			},
			wantErr: true,
		},
		{
			name: "Invalid V4 mask - too large",
			config: BaseConfig{
				LockListV4Mask: 33,
			},
			wantErr: true,
		},
		{
			name: "Invalid V6 mask - negative",
			config: BaseConfig{
				LockListV6Mask: -1,
			},
			wantErr: true,
		},
		{
			name: "Invalid V6 mask - too large",
			config: BaseConfig{
				LockListV6Mask: 129,
			},
			wantErr: true,
		},
		{
			name: "Valid whitelist",
			config: BaseConfig{
				Whitelist: []string{"192.168.1.0/24", "10.0.0.1"},
			},
			wantErr: false,
		},
		{
			name: "Invalid whitelist CIDR",
			config: BaseConfig{
				Whitelist: []string{"invalid"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestPortConfig_Validate tests PortConfig validation
// TestPortConfig_Validate 测试 PortConfig 验证
func TestPortConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  PortConfig
		wantErr bool
	}{
		{
			name:    "Empty config",
			config:  PortConfig{},
			wantErr: false,
		},
		{
			name: "Valid rule - allow",
			config: PortConfig{
				IPPortRules: []IPPortRule{
					{IP: "192.168.1.1", Port: 80, Action: 1},
				},
			},
			wantErr: false,
		},
		{
			name: "Valid rule - deny",
			config: PortConfig{
				IPPortRules: []IPPortRule{
					{IP: "192.168.1.1", Port: 443, Action: 2},
				},
			},
			wantErr: false,
		},
		{
			name: "Invalid port - zero",
			config: PortConfig{
				IPPortRules: []IPPortRule{
					{IP: "192.168.1.1", Port: 0, Action: 1},
				},
			},
			wantErr: true,
		},
		{
			name: "Invalid action",
			config: PortConfig{
				IPPortRules: []IPPortRule{
					{IP: "192.168.1.1", Port: 80, Action: 3},
				},
			},
			wantErr: true,
		},
		{
			name: "Invalid IP",
			config: PortConfig{
				IPPortRules: []IPPortRule{
					{IP: "invalid", Port: 80, Action: 1},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestRateLimitConfig_Validate tests RateLimitConfig validation
// TestRateLimitConfig_Validate 测试 RateLimitConfig 验证
func TestRateLimitConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  RateLimitConfig
		wantErr bool
	}{
		{
			name:    "Empty config",
			config:  RateLimitConfig{},
			wantErr: false,
		},
		{
			name: "Valid rule",
			config: RateLimitConfig{
				Rules: []RateLimitRule{
					{IP: "192.168.1.0/24", Rate: 1000, Burst: 100},
				},
			},
			wantErr: false,
		},
		{
			name: "Invalid IP",
			config: RateLimitConfig{
				Rules: []RateLimitRule{
					{IP: "invalid", Rate: 1000, Burst: 100},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestLogEngineConfig_Validate tests LogEngineConfig validation
// TestLogEngineConfig_Validate 测试 LogEngineConfig 验证
func TestLogEngineConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  LogEngineConfig
		wantErr bool
	}{
		{
			name:    "Empty config",
			config:  LogEngineConfig{},
			wantErr: false,
		},
		{
			name: "Valid rule with action",
			config: LogEngineConfig{
				Rules: []LogEngineRule{
					{Path: "/var/log/test.log", Action: "block"},
				},
			},
			wantErr: false,
		},
		{
			name: "Valid rule with numeric action",
			config: LogEngineConfig{
				Rules: []LogEngineRule{
					{Path: "/var/log/test.log", Action: "1"},
				},
			},
			wantErr: false,
		},
		{
			name: "Valid rule with block prefix",
			config: LogEngineConfig{
				Rules: []LogEngineRule{
					{Path: "/var/log/test.log", Action: "block:10m"},
				},
			},
			wantErr: false,
		},
		{
			name: "Valid rule with black prefix",
			config: LogEngineConfig{
				Rules: []LogEngineRule{
					{Path: "/var/log/test.log", Action: "black:5m"},
				},
			},
			wantErr: false,
		},
		{
			name: "Valid rule with tail position start",
			config: LogEngineConfig{
				Rules: []LogEngineRule{
					{Path: "/var/log/test.log", TailPosition: "start"},
				},
			},
			wantErr: false,
		},
		{
			name: "Valid rule with tail position end",
			config: LogEngineConfig{
				Rules: []LogEngineRule{
					{Path: "/var/log/test.log", TailPosition: "end"},
				},
			},
			wantErr: false,
		},
		{
			name: "Valid rule with tail position offset",
			config: LogEngineConfig{
				Rules: []LogEngineRule{
					{Path: "/var/log/test.log", TailPosition: "offset"},
				},
			},
			wantErr: false,
		},
		{
			name: "Invalid tail position",
			config: LogEngineConfig{
				Rules: []LogEngineRule{
					{Path: "/var/log/test.log", TailPosition: "invalid"},
				},
			},
			wantErr: true,
		},
		{
			name: "Invalid action",
			config: LogEngineConfig{
				Rules: []LogEngineRule{
					{Path: "/var/log/test.log", Action: "invalid"},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidateCIDR tests the validateCIDR helper function
// TestValidateCIDR 测试 validateCIDR 辅助函数
func TestValidateCIDR(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"Valid IPv4", "192.168.1.1", false},
		{"Valid IPv4 CIDR", "192.168.1.0/24", false},
		{"Valid IPv6", "2001:db8::1", false},
		{"Valid IPv6 CIDR", "2001:db8::/32", false},
		{"Valid IP with port", "192.168.1.1:8080", false},
		{"Invalid format", "invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCIDR(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
