package types

import (
	"net"
	"strings"
	"testing"

	"github.com/livp123/netxfw/internal/utils/logger"
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

// containsStr checks if a string contains a substring.
// containsStr 检查字符串是否包含子字符串。
func containsStr(s, substr string) bool {
	return strings.Contains(s, substr)
}

// TestConfigValidator_ValidateSyntax tests YAML syntax validation.
// TestConfigValidator_ValidateSyntax 测试 YAML 语法验证。
func TestConfigValidator_ValidateSyntax(t *testing.T) {
	validator := NewConfigValidator()

	// Valid YAML / 有效的 YAML
	validYAML := `
base:
  default_deny: true
web:
  enabled: true
  port: 8080
`
	result := validator.ValidateSyntax([]byte(validYAML))
	assert.True(t, result.Valid)
	assert.Empty(t, result.Errors)

	// Invalid YAML / 无效的 YAML
	invalidYAML := `
base:
  default_deny: true
  invalid: [unclosed
`
	result = validator.ValidateSyntax([]byte(invalidYAML))
	assert.False(t, result.Valid)
	assert.NotEmpty(t, result.Errors)
}

// TestConfigValidator_ValidateBaseConfig tests base config validation.
// TestConfigValidator_ValidateBaseConfig 测试基础配置验证。
func TestConfigValidator_ValidateBaseConfig(t *testing.T) {
	validator := NewConfigValidator()

	t.Run("ValidBaseConfig", func(t *testing.T) {
		cfg := &GlobalConfig{
			Base: BaseConfig{
				ICMPRate:        100,
				ICMPBurst:       200,
				CleanupInterval: "1m",
				PprofPort:       6060,
				Whitelist:       []string{"192.168.1.0/24", "10.0.0.1"},
			},
		}
		result := validator.Validate(cfg)
		assert.True(t, result.Valid)
	})

	t.Run("InvalidICMPRate", func(t *testing.T) {
		cfg := &GlobalConfig{
			Base: BaseConfig{
				ICMPRate:  100000000, // Exceeds max / 超过最大值
				ICMPBurst: 200,
			},
		}
		result := validator.Validate(cfg)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Errors[0].Field, "icmp_rate")
	})

	t.Run("InvalidICMPBurst", func(t *testing.T) {
		cfg := &GlobalConfig{
			Base: BaseConfig{
				ICMPRate:  100,
				ICMPBurst: 100000000, // Exceeds max / 超过最大值
			},
		}
		result := validator.Validate(cfg)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Errors[0].Field, "icmp_burst")
	})

	t.Run("BurstLessThanRate", func(t *testing.T) {
		cfg := &GlobalConfig{
			Base: BaseConfig{
				ICMPRate:  1000,
				ICMPBurst: 500, // Less than rate / 小于速率
			},
		}
		result := validator.Validate(cfg)
		assert.True(t, result.Valid) // Warning, not error / 警告，不是错误
		assert.NotEmpty(t, result.Warnings)
	})

	t.Run("InvalidCleanupInterval", func(t *testing.T) {
		cfg := &GlobalConfig{
			Base: BaseConfig{
				CleanupInterval: "invalid",
			},
		}
		result := validator.Validate(cfg)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Errors[0].Field, "cleanup_interval")
	})

	t.Run("InvalidPprofPort", func(t *testing.T) {
		cfg := &GlobalConfig{
			Base: BaseConfig{
				EnablePprof: true,
				PprofPort:   70000, // Invalid port / 无效端口
			},
		}
		result := validator.Validate(cfg)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Errors[0].Field, "pprof_port")
	})

	t.Run("InvalidWhitelistCIDR", func(t *testing.T) {
		cfg := &GlobalConfig{
			Base: BaseConfig{
				Whitelist: []string{"invalid-cidr"},
			},
		}
		result := validator.Validate(cfg)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Errors[0].Field, "whitelist")
	})

	t.Run("InvalidIPv4Mask", func(t *testing.T) {
		cfg := &GlobalConfig{
			Base: BaseConfig{
				LockListV4Mask: 33, // Invalid mask / 无效掩码
			},
		}
		result := validator.Validate(cfg)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Errors[0].Field, "lock_list_v4_mask")
	})

	t.Run("InvalidIPv6Mask", func(t *testing.T) {
		cfg := &GlobalConfig{
			Base: BaseConfig{
				LockListV6Mask: 129, // Invalid mask / 无效掩码
			},
		}
		result := validator.Validate(cfg)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Errors[0].Field, "lock_list_v6_mask")
	})
}

// TestConfigValidator_ValidateWebConfig tests web config validation.
// TestConfigValidator_ValidateWebConfig 测试 Web 配置验证。
func TestConfigValidator_ValidateWebConfig(t *testing.T) {
	validator := NewConfigValidator()

	t.Run("ValidWebConfig", func(t *testing.T) {
		cfg := &GlobalConfig{
			Web: WebConfig{
				Enabled: true,
				Port:    8080,
				Token:   "secret-token",
			},
		}
		result := validator.Validate(cfg)
		assert.True(t, result.Valid)
	})

	t.Run("InvalidPort", func(t *testing.T) {
		cfg := &GlobalConfig{
			Web: WebConfig{
				Enabled: true,
				Port:    70000, // Invalid port / 无效端口
			},
		}
		result := validator.Validate(cfg)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Errors[0].Field, "web.port")
	})

	t.Run("MissingToken", func(t *testing.T) {
		cfg := &GlobalConfig{
			Web: WebConfig{
				Enabled: true,
				Port:    8080,
				Token:   "", // Missing token / 缺少 token
			},
		}
		result := validator.Validate(cfg)
		assert.True(t, result.Valid) // Warning, not error / 警告，不是错误
		assert.NotEmpty(t, result.Warnings)
	})
}

// TestConfigValidator_ValidatePortConfig tests port config validation.
// TestConfigValidator_ValidatePortConfig 测试端口配置验证。
func TestConfigValidator_ValidatePortConfig(t *testing.T) {
	validator := NewConfigValidator()

	t.Run("ValidPortConfig", func(t *testing.T) {
		cfg := &GlobalConfig{
			Port: PortConfig{
				AllowedPorts: []uint16{80, 443, 8080},
				IPPortRules: []IPPortRule{
					{IP: "192.168.1.1", Port: 80, Action: 1},
					{IP: "10.0.0.0/24", Port: 443, Action: 2},
				},
			},
		}
		result := validator.Validate(cfg)
		assert.True(t, result.Valid)
	})

	t.Run("InvalidAllowedPort", func(t *testing.T) {
		cfg := &GlobalConfig{
			Port: PortConfig{
				AllowedPorts: []uint16{0}, // Invalid port (0 is not valid) / 无效端口（0 无效）
			},
		}
		result := validator.Validate(cfg)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Errors[0].Field, "allowed_ports")
	})

	t.Run("InvalidIPPortRuleIP", func(t *testing.T) {
		cfg := &GlobalConfig{
			Port: PortConfig{
				IPPortRules: []IPPortRule{
					{IP: "invalid-ip", Port: 80, Action: 1},
				},
			},
		}
		result := validator.Validate(cfg)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Errors[0].Field, "ip_port_rules")
	})

	t.Run("InvalidIPPortRuleAction", func(t *testing.T) {
		cfg := &GlobalConfig{
			Port: PortConfig{
				IPPortRules: []IPPortRule{
					{IP: "192.168.1.1", Port: 80, Action: 5}, // Invalid action / 无效动作
				},
			},
		}
		result := validator.Validate(cfg)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Errors[0].Field, "action")
	})
}

// TestConfigValidator_ValidateRateLimitConfig tests rate limit config validation.
// TestConfigValidator_ValidateRateLimitConfig 测试速率限制配置验证。
func TestConfigValidator_ValidateRateLimitConfig(t *testing.T) {
	validator := NewConfigValidator()

	t.Run("ValidRateLimitConfig", func(t *testing.T) {
		cfg := &GlobalConfig{
			RateLimit: RateLimitConfig{
				Enabled:         true,
				AutoBlock:       true,
				AutoBlockExpiry: "10m",
				Rules: []RateLimitRule{
					{IP: "10.0.0.0/24", Rate: 1000, Burst: 2000},
				},
			},
		}
		result := validator.Validate(cfg)
		assert.True(t, result.Valid)
	})

	t.Run("InvalidAutoBlockExpiry", func(t *testing.T) {
		cfg := &GlobalConfig{
			RateLimit: RateLimitConfig{
				Enabled:         true,
				AutoBlock:       true,
				AutoBlockExpiry: "invalid",
			},
		}
		result := validator.Validate(cfg)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Errors[0].Field, "auto_block_expiry")
	})

	t.Run("InvalidRateLimitRuleIP", func(t *testing.T) {
		cfg := &GlobalConfig{
			RateLimit: RateLimitConfig{
				Enabled: true,
				Rules: []RateLimitRule{
					{IP: "invalid-ip", Rate: 1000, Burst: 2000},
				},
			},
		}
		result := validator.Validate(cfg)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Errors[0].Field, "rules")
	})

	t.Run("RateExceedsMax", func(t *testing.T) {
		cfg := &GlobalConfig{
			RateLimit: RateLimitConfig{
				Enabled: true,
				Rules: []RateLimitRule{
					{IP: "10.0.0.1", Rate: 100000000, Burst: 2000}, // Rate exceeds max / 速率超过最大值
				},
			},
		}
		result := validator.Validate(cfg)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Errors[0].Field, "rate")
	})
}

// TestConfigValidator_ValidateConntrackConfig tests conntrack config validation.
// TestConfigValidator_ValidateConntrackConfig 测试连接跟踪配置验证。
func TestConfigValidator_ValidateConntrackConfig(t *testing.T) {
	validator := NewConfigValidator()

	t.Run("ValidConntrackConfig", func(t *testing.T) {
		cfg := &GlobalConfig{
			Conntrack: ConntrackConfig{
				Enabled:    true,
				MaxEntries: 100000,
				TCPTimeout: "1h",
				UDPTimeout: "5m",
			},
		}
		result := validator.Validate(cfg)
		assert.True(t, result.Valid)
	})

	t.Run("InvalidTCPTimeout", func(t *testing.T) {
		cfg := &GlobalConfig{
			Conntrack: ConntrackConfig{
				Enabled:    true,
				TCPTimeout: "invalid",
			},
		}
		result := validator.Validate(cfg)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Errors[0].Field, "tcp_timeout")
	})

	t.Run("NegativeMaxEntries", func(t *testing.T) {
		cfg := &GlobalConfig{
			Conntrack: ConntrackConfig{
				Enabled:    true,
				MaxEntries: -1,
			},
		}
		result := validator.Validate(cfg)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Errors[0].Field, "max_entries")
	})
}

// TestConfigValidator_ValidateLogEngineConfig tests log engine config validation.
// TestConfigValidator_ValidateLogEngineConfig 测试日志引擎配置验证。
func TestConfigValidator_ValidateLogEngineConfig(t *testing.T) {
	validator := NewConfigValidator()

	t.Run("ValidLogEngineConfig", func(t *testing.T) {
		cfg := &GlobalConfig{
			LogEngine: LogEngineConfig{
				Enabled: true,
				Workers: 4,
				Rules: []LogEngineRule{
					{
						ID:       "test_rule",
						Path:     "/var/log/test.log",
						Action:   "block",
						TTL:      "10m",
						Regex:    "error.*",
						Interval: 60,
					},
				},
			},
		}
		result := validator.Validate(cfg)
		assert.True(t, result.Valid)
	})

	t.Run("InvalidWorkers", func(t *testing.T) {
		cfg := &GlobalConfig{
			LogEngine: LogEngineConfig{
				Enabled: true,
				Workers: 0, // Invalid / 无效
			},
		}
		result := validator.Validate(cfg)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Errors[0].Field, "workers")
	})

	t.Run("MissingRuleID", func(t *testing.T) {
		cfg := &GlobalConfig{
			LogEngine: LogEngineConfig{
				Enabled: true,
				Workers: 4,
				Rules: []LogEngineRule{
					{Path: "/var/log/test.log"}, // Missing ID / 缺少 ID
				},
			},
		}
		result := validator.Validate(cfg)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Errors[0].Field, "id")
	})

	t.Run("InvalidRegex", func(t *testing.T) {
		cfg := &GlobalConfig{
			LogEngine: LogEngineConfig{
				Enabled: true,
				Workers: 4,
				Rules: []LogEngineRule{
					{
						ID:    "test",
						Path:  "/var/log/test.log",
						Regex: "[invalid", // Invalid regex / 无效正则
					},
				},
			},
		}
		result := validator.Validate(cfg)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Errors[0].Field, "regex")
	})

	t.Run("InvalidAction", func(t *testing.T) {
		cfg := &GlobalConfig{
			LogEngine: LogEngineConfig{
				Enabled: true,
				Workers: 4,
				Rules: []LogEngineRule{
					{
						ID:     "test",
						Path:   "/var/log/test.log",
						Action: "invalid", // Invalid action / 无效动作
					},
				},
			},
		}
		result := validator.Validate(cfg)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Errors[0].Field, "action")
	})
}

// TestConfigValidator_ValidateCapacityConfig tests capacity config validation.
// TestConfigValidator_ValidateCapacityConfig 测试容量配置验证。
func TestConfigValidator_ValidateCapacityConfig(t *testing.T) {
	validator := NewConfigValidator()

	t.Run("ValidCapacityConfig", func(t *testing.T) {
		cfg := &GlobalConfig{
			Capacity: CapacityConfig{
				LockList:     1000000,
				DynLockList:  1000000,
				Whitelist:    65536,
				IPPortRules:  65536,
				AllowedPorts: 1024,
			},
		}
		result := validator.Validate(cfg)
		assert.True(t, result.Valid)
	})

	t.Run("NegativeLockList", func(t *testing.T) {
		cfg := &GlobalConfig{
			Capacity: CapacityConfig{
				LockList: -1, // Invalid / 无效
			},
		}
		result := validator.Validate(cfg)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Errors[0].Field, "lock_list")
	})

	t.Run("VeryHighCapacity", func(t *testing.T) {
		cfg := &GlobalConfig{
			Capacity: CapacityConfig{
				LockList: 50000000, // Very high / 非常高
			},
		}
		result := validator.Validate(cfg)
		assert.True(t, result.Valid) // Warning, not error / 警告，不是错误
		assert.NotEmpty(t, result.Warnings)
	})
}

// TestConfigValidator_ValidateLoggingConfig tests logging config validation.
// TestConfigValidator_ValidateLoggingConfig 测试日志配置验证。
func TestConfigValidator_ValidateLoggingConfig(t *testing.T) {
	validator := NewConfigValidator()

	t.Run("ValidLoggingConfig", func(t *testing.T) {
		cfg := &GlobalConfig{
			Logging: logger.LoggingConfig{
				Enabled:    true,
				Level:      "info",
				Path:       "/var/log/netxfw.log",
				MaxSize:    10,
				MaxBackups: 3,
				MaxAge:     30,
			},
		}
		result := validator.Validate(cfg)
		assert.True(t, result.Valid)
	})

	t.Run("InvalidLogLevel", func(t *testing.T) {
		cfg := &GlobalConfig{
			Logging: logger.LoggingConfig{
				Enabled: true,
				Level:   "invalid", // Invalid level / 无效级别
				Path:    "/var/log/netxfw.log",
			},
		}
		result := validator.Validate(cfg)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Errors[0].Field, "level")
	})

	t.Run("MissingPath", func(t *testing.T) {
		cfg := &GlobalConfig{
			Logging: logger.LoggingConfig{
				Enabled: true,
				Path:    "", // Missing path / 缺少路径
			},
		}
		result := validator.Validate(cfg)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Errors[0].Field, "path")
	})
}

// TestConfigValidator_DetectConflicts tests conflict detection.
// TestConfigValidator_DetectConflicts 测试冲突检测。
func TestConfigValidator_DetectConflicts(t *testing.T) {
	validator := NewConfigValidator()

	t.Run("WhitelistRateLimitOverlap", func(t *testing.T) {
		cfg := &GlobalConfig{
			Base: BaseConfig{
				Whitelist: []string{"10.0.0.0/24"},
			},
			RateLimit: RateLimitConfig{
				Enabled: true,
				Rules: []RateLimitRule{
					{IP: "10.0.0.1", Rate: 1000, Burst: 2000}, // Overlaps with whitelist / 与白名单重叠
				},
			},
		}
		result := validator.Validate(cfg)
		assert.True(t, result.Valid) // Warning, not error / 警告，不是错误
		assert.NotEmpty(t, result.Warnings)
	})

	t.Run("DuplicatePorts", func(t *testing.T) {
		cfg := &GlobalConfig{
			Port: PortConfig{
				AllowedPorts: []uint16{80, 443, 80}, // Duplicate 80 / 重复的 80
			},
		}
		result := validator.Validate(cfg)
		assert.True(t, result.Valid) // Warning, not error / 警告，不是错误
		assert.NotEmpty(t, result.Warnings)
	})

	t.Run("WebMetricsSamePort", func(t *testing.T) {
		cfg := &GlobalConfig{
			Web: WebConfig{
				Enabled: true,
				Port:    8080,
			},
			Metrics: MetricsConfig{
				ServerEnabled: true,
				Port:          8080, // Same as web / 与 Web 相同
			},
		}
		result := validator.Validate(cfg)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Errors[0].Field, "web.port")
	})

	t.Run("DuplicateRateLimitRules", func(t *testing.T) {
		cfg := &GlobalConfig{
			RateLimit: RateLimitConfig{
				Enabled: true,
				Rules: []RateLimitRule{
					{IP: "10.0.0.1", Rate: 1000, Burst: 2000},
					{IP: "10.0.0.1", Rate: 2000, Burst: 3000}, // Duplicate IP / 重复 IP
				},
			},
		}
		result := validator.Validate(cfg)
		assert.True(t, result.Valid) // Warning, not error / 警告，不是错误
		assert.NotEmpty(t, result.Warnings)
	})
}

// TestValidateConfig tests the convenience function.
// TestValidateConfig 测试便捷函数。
func TestValidateConfig(t *testing.T) {
	validYAML := `
base:
  default_deny: true
  icmp_rate: 100
  icmp_burst: 200
web:
  enabled: true
  port: 8080
  token: "secret"
rate_limit:
  enabled: true
  rules:
    - ip: "10.0.0.0/24"
      rate: 1000
      burst: 2000
`

	result, err := ValidateConfig([]byte(validYAML))
	assert.NoError(t, err)
	assert.True(t, result.Valid)
}

// TestValidationResult_Methods tests ValidationResult methods.
// TestValidationResult_Methods 测试 ValidationResult 方法。
func TestValidationResult_Methods(t *testing.T) {
	result := &ValidationResult{
		Valid:    true,
		Errors:   []ValidationError{},
		Warnings: []ValidationWarning{},
	}

	// Test AddError / 测试 AddError
	result.AddError("test.field", "test error", 123)
	assert.False(t, result.Valid)
	assert.Len(t, result.Errors, 1)
	assert.Equal(t, "test.field", result.Errors[0].Field)
	assert.Equal(t, "test error", result.Errors[0].Message)
	assert.Equal(t, 123, result.Errors[0].Value)

	// Test AddWarning / 测试 AddWarning
	result.AddWarning("test.field", "test warning", 456)
	assert.Len(t, result.Warnings, 1)
	assert.Equal(t, "test.field", result.Warnings[0].Field)
	assert.Equal(t, "test warning", result.Warnings[0].Message)
	assert.Equal(t, 456, result.Warnings[0].Value)
}

// TestConfigValidator_NetworksOverlap tests network overlap detection.
// TestConfigValidator_NetworksOverlap 测试网络重叠检测。
func TestConfigValidator_NetworksOverlap(t *testing.T) {
	validator := NewConfigValidator()

	_, n1, _ := netParseCIDR("10.0.0.0/24")
	_, n2, _ := netParseCIDR("10.0.0.128/25")
	_, n3, _ := netParseCIDR("192.168.1.0/24")

	// n1 contains n2 / n1 包含 n2
	assert.True(t, validator.networksOverlap(n1, n2))

	// n1 and n3 don't overlap / n1 和 n3 不重叠
	assert.False(t, validator.networksOverlap(n1, n3))
}

// Helper function to parse CIDR.
// 解析 CIDR 的辅助函数。
func netParseCIDR(s string) (any, *net.IPNet, error) {
	_, ipNet, err := net.ParseCIDR(s)
	return nil, ipNet, err
}

// TestConfigValidator_ValidateMetricsConfig tests metrics config validation.
// TestConfigValidator_ValidateMetricsConfig 测试指标配置验证。
func TestConfigValidator_ValidateMetricsConfig(t *testing.T) {
	validator := NewConfigValidator()

	t.Run("ValidMetricsConfig", func(t *testing.T) {
		cfg := &GlobalConfig{
			Metrics: MetricsConfig{
				Enabled:         true,
				ServerEnabled:   true,
				Port:            9090,
				PushEnabled:     true,
				PushGatewayAddr: "localhost:9091",
				PushInterval:    "15s",
			},
		}
		result := validator.Validate(cfg)
		assert.True(t, result.Valid)
	})

	t.Run("InvalidMetricsPort", func(t *testing.T) {
		cfg := &GlobalConfig{
			Metrics: MetricsConfig{
				ServerEnabled: true,
				Port:          70000, // Invalid port / 无效端口
			},
		}
		result := validator.Validate(cfg)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Errors[0].Field, "metrics.port")
	})

	t.Run("MissingPushGatewayAddr", func(t *testing.T) {
		cfg := &GlobalConfig{
			Metrics: MetricsConfig{
				Enabled:         true,
				PushEnabled:     true,
				PushGatewayAddr: "", // Missing / 缺少
			},
		}
		result := validator.Validate(cfg)
		assert.False(t, result.Valid)
		// Check if any error contains push_gateway_addr
		// 检查是否有任何错误包含 push_gateway_addr
		found := false
		for _, err := range result.Errors {
			if containsStr(err.Field, "push_gateway_addr") {
				found = true
				break
			}
		}
		assert.True(t, found, "Expected error about push_gateway_addr")
	})

	t.Run("InvalidPushInterval", func(t *testing.T) {
		cfg := &GlobalConfig{
			Metrics: MetricsConfig{
				Enabled:         true,
				PushEnabled:     true,
				PushGatewayAddr: "localhost:9091",
				PushInterval:    "invalid",
			},
		}
		result := validator.Validate(cfg)
		assert.False(t, result.Valid)
		// Check if any error contains push_interval
		// 检查是否有任何错误包含 push_interval
		found := false
		for _, err := range result.Errors {
			if containsStr(err.Field, "push_interval") {
				found = true
				break
			}
		}
		assert.True(t, found, "Expected error about push_interval")
	})
}

// TestValidateConfigStruct tests the struct validation function.
// TestValidateConfigStruct 测试结构体验证函数。
func TestValidateConfigStruct(t *testing.T) {
	cfg := &GlobalConfig{
		Base: BaseConfig{
			ICMPRate:  100,
			ICMPBurst: 200,
		},
		Web: WebConfig{
			Enabled: true,
			Port:    8080,
			Token:   "secret",
		},
	}

	result := ValidateConfigStruct(cfg)
	assert.True(t, result.Valid)
}

// TestConfigValidator_ComplexScenarios tests complex validation scenarios.
// TestConfigValidator_ComplexScenarios 测试复杂验证场景。
func TestConfigValidator_ComplexScenarios(t *testing.T) {
	validator := NewConfigValidator()

	t.Run("FullConfigValidation", func(t *testing.T) {
		yamlConfig := `
base:
  default_deny: true
  allow_return_traffic: true
  allow_icmp: true
  icmp_rate: 10
  icmp_burst: 50
  cleanup_interval: "1m"
  whitelist:
    - "192.168.0.0/16"
    - "10.0.0.0/8"

web:
  enabled: true
  port: 11811
  token: "my-secret-token"

metrics:
  enabled: true
  server_enabled: true
  port: 11812

port:
  allowed_ports:
    - 22
    - 80
    - 443
  ip_port_rules:
    - ip: "192.168.1.100"
      port: 8080
      action: 1

conntrack:
  enabled: true
  max_entries: 100000
  tcp_timeout: "1h"
  udp_timeout: "5m"

rate_limit:
  enabled: true
  auto_block: true
  auto_block_expiry: "10m"
  rules:
    - ip: "0.0.0.0/0"
      rate: 1000
      burst: 2000

capacity:
  lock_list: 2000000
  dyn_lock_list: 2000000
  whitelist: 65536

logging:
  enabled: true
  level: "info"
  path: "/var/log/netxfw/agent.log"
  max_size: 10
  max_backups: 3
  max_age: 30
`
		var cfg GlobalConfig
		err := yaml.Unmarshal([]byte(yamlConfig), &cfg)
		assert.NoError(t, err)

		result := validator.Validate(&cfg)
		assert.True(t, result.Valid, "Expected valid config, got errors: %v", result.Errors)
	})
}
