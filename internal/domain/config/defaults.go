package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/netxfw/netxfw/internal/utils/logger"
)

func ensureDefaultLogDir(path string) {
	if path == "" {
		return
	}

	dir := filepath.Dir(path)
	if _, err := os.Stat(dir); err == nil {
		return
	} else if !os.IsNotExist(err) {
		return
	}

	if err := os.MkdirAll(dir, 0o750); err != nil {
		panic(fmt.Sprintf("failed to create default log directory %q: %v", dir, err))
	}
}

// DefaultConfig returns the canonical default configuration snapshot.
func DefaultConfig() Config {
	ensureDefaultLogDir("/var/log/netxfw/agent.log")

	return Config{
		Cluster: ClusterConfig{
			Enabled:    false,
			ConfigPath: "cluster.toml",
		},
		Base: BaseConfig{
			DefaultDeny:        true,
			AllowReturnTraffic: false,
			AllowICMP:          true,
			PersistRules:       true,
			CleanupInterval:    "1m",
			ICMPRate:           10,
			ICMPBurst:          50,
			LockListV4Mask:     24,
			LockListV6Mask:     64,
			EnablePprof:        false,
			PprofBind:          "127.0.0.1",
			PprofPort:          6060,
		},
		Conntrack: ConntrackConfig{
			Enabled:    true,
			MaxEntries: 100000,
			TCPTimeout: "1h",
			UDPTimeout: "5m",
		},
		RateLimit: RateLimitConfig{
			Enabled:         true,
			AutoBlock:       true,
			AutoBlockExpiry: "10m",
		},
		LogEngine: LogEngineConfig{
			Enabled: false,
			Workers: 4,
		},
		Capacity: CapacityConfig{
			Conntrack:       100000,
			LockList:        2000000,
			DynLockList:     2000000,
			Whitelist:       65536,
			IPPortRules:     65536,
			AllowedPorts:    1024,
			RateLimits:      1000,
			DropReasonStats: 1000000,
			PassReasonStats: 1000000,
		},
		Logging: logger.LoggingConfig{
			Enabled:    false,
			Path:       "/var/log/netxfw/agent.log",
			MaxSize:    10,
			MaxBackups: 3,
			MaxAge:     30,
			Compress:   true,
		},
		Web: WebConfig{
			Bind: "127.0.0.1",
			Port: 11811,
		},
		Metrics: MetricsConfig{
			Enabled:           false,
			ServerEnabled:     false,
			Bind:              "127.0.0.1",
			Port:              11812,
			TopN:              10,
			ThresholdCritical: 90,
			ThresholdHigh:     75,
			ThresholdMedium:   50,
			StatsInterval:     "1s",
			AvgPacketSize:     500,
		},
		Runtime: RuntimeServicesConfig{
			AI: AIConfig{
				Enabled: false,
				Port:    11813,
			},
			MCP: MCPConfig{
				Enabled: false,
				Port:    11814,
				Mode:    "sse",
			},
		},
	}
}
