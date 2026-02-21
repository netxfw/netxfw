package types

import (
	"testing"

	"github.com/netxfw/netxfw/internal/utils/logger"
)

// BenchmarkLoadGlobalConfig benchmarks global config loading.
// BenchmarkLoadGlobalConfig 基准测试全局配置加载。
func BenchmarkLoadGlobalConfig(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = LoadGlobalConfig("")
	}
}

// BenchmarkBaseConfigDefaults benchmarks base config default values.
// BenchmarkBaseConfigDefaults 基准测试基础配置默认值。
func BenchmarkBaseConfigDefaults(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = BaseConfig{
			DefaultDeny:        true,
			AllowReturnTraffic: true,
			AllowICMP:          true,
			EnableExpiry:       true,
			CleanupInterval:    "1h",
		}
	}
}

// BenchmarkLoggingConfigDefaults benchmarks logging config default values.
// BenchmarkLoggingConfigDefaults 基准测试日志配置默认值。
func BenchmarkLoggingConfigDefaults(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = logger.LoggingConfig{
			Enabled:    true,
			Level:      "info",
			Path:       "/var/log/netxfw/agent.log",
			MaxSize:    10,
			MaxBackups: 3,
			MaxAge:     30,
			Compress:   true,
		}
	}
}

// BenchmarkRateLimitConfigDefaults benchmarks rate limit config default values.
// BenchmarkRateLimitConfigDefaults 基准测试速率限制配置默认值。
func BenchmarkRateLimitConfigDefaults(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = RateLimitConfig{
			Enabled:         true,
			AutoBlock:       true,
			AutoBlockExpiry: "5m",
		}
	}
}

// BenchmarkConntrackConfigDefaults benchmarks conntrack config default values.
// BenchmarkConntrackConfigDefaults 基准测试连接跟踪配置默认值。
func BenchmarkConntrackConfigDefaults(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ConntrackConfig{
			Enabled: true,
		}
	}
}

// BenchmarkPortConfigDefaults benchmarks port config default values.
// BenchmarkPortConfigDefaults 基准测试端口配置默认值。
func BenchmarkPortConfigDefaults(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = PortConfig{
			AllowedPorts: []uint16{80, 443, 8080},
		}
	}
}

// BenchmarkWebConfigDefaults benchmarks web config default values.
// BenchmarkWebConfigDefaults 基准测试 Web 配置默认值。
func BenchmarkWebConfigDefaults(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = WebConfig{
			Enabled: true,
			Port:    8080,
		}
	}
}

// BenchmarkMetricsConfigDefaults benchmarks metrics config default values.
// BenchmarkMetricsConfigDefaults 基准测试指标配置默认值。
func BenchmarkMetricsConfigDefaults(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = MetricsConfig{
			Enabled: true,
			Port:    9090,
		}
	}
}

// BenchmarkGlobalConfigCreation benchmarks GlobalConfig struct creation.
// BenchmarkGlobalConfigCreation 基准测试 GlobalConfig 结构创建。
func BenchmarkGlobalConfigCreation(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = GlobalConfig{
			Base: BaseConfig{
				DefaultDeny:        true,
				AllowReturnTraffic: true,
				AllowICMP:          true,
				EnableExpiry:       true,
				CleanupInterval:    "1h",
				Whitelist:          []string{"10.0.0.0/8"},
			},
			Logging: logger.LoggingConfig{
				Enabled:  true,
				Level:    "info",
				Path:     "/var/log/netxfw/agent.log",
				MaxSize:  10,
				Compress: true,
			},
			RateLimit: RateLimitConfig{
				Enabled:         true,
				AutoBlock:       true,
				AutoBlockExpiry: "5m",
			},
			Conntrack: ConntrackConfig{
				Enabled: true,
			},
			Port: PortConfig{
				AllowedPorts: []uint16{80, 443, 8080},
			},
			Web: WebConfig{
				Enabled: true,
				Port:    8080,
			},
			Metrics: MetricsConfig{
				Enabled: true,
				Port:    9090,
			},
		}
	}
}

// BenchmarkCapacityConfigDefaults benchmarks capacity config default values.
// BenchmarkCapacityConfigDefaults 基准测试容量配置默认值。
func BenchmarkCapacityConfigDefaults(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = CapacityConfig{
			LockList:     2000000,
			DynLockList:  2000000,
			Whitelist:    65536,
			IPPortRules:  65536,
			AllowedPorts: 1024,
		}
	}
}
