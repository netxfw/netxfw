package ports

import (
	"reflect"
	"testing"
	"time"

	domainconfig "github.com/netxfw/netxfw/internal/domain/config"
	domainruntime "github.com/netxfw/netxfw/internal/domain/plugin/runtime"
	sdk "github.com/netxfw/netxfw/pkg/sdk"
)

func TestSDKCompatNilConversions(t *testing.T) {
	if BlockedIPsFromSDK(nil) != nil {
		t.Fatalf("expected nil blocked IP conversion")
	}
	if IPPortRulesFromSDK(nil) != nil {
		t.Fatalf("expected nil IP-port conversion")
	}
	if IPPortRulesToSDK(nil) != nil {
		t.Fatalf("expected nil SDK IP-port conversion")
	}
	if RateLimitRulesFromSDK(nil) != nil {
		t.Fatalf("expected nil rate-limit conversion")
	}
	if DropDetailEntriesFromSDK(nil) != nil {
		t.Fatalf("expected nil drop-detail conversion")
	}
	if ConfigFromSDK(nil) != nil {
		t.Fatalf("expected nil domain config")
	}
	if ConfigToSDK(nil) != nil {
		t.Fatalf("expected nil sdk config")
	}
}

func TestSDKCompatReadModelConversions(t *testing.T) {
	now := time.Unix(1700000000, 0)

	blocked := BlockedIPsFromSDK([]sdk.BlockedIP{{IP: "10.0.0.1", ExpiresAt: 12, Counter: 34}})
	if want := []BlockedIP{{IP: "10.0.0.1", ExpiresAt: 12, Counter: 34}}; !reflect.DeepEqual(blocked, want) {
		t.Fatalf("blocked conversion mismatch: got %+v want %+v", blocked, want)
	}

	rateRules := RateLimitRulesFromSDK(map[string]sdk.RateLimitConf{"10.0.0.0/24": {Rate: 100, Burst: 200}})
	if want := map[string]RateLimitConf{"10.0.0.0/24": {Rate: 100, Burst: 200}}; !reflect.DeepEqual(rateRules, want) {
		t.Fatalf("rate conversion mismatch: got %+v want %+v", rateRules, want)
	}

	drops := DropDetailEntriesFromSDK([]sdk.DropDetailEntry{{Timestamp: now, SrcIP: "1.1.1.1", DstIP: "2.2.2.2", SrcPort: 1234, DstPort: 443, Protocol: 6, Reason: 9, Count: 10, Payload: []byte("pkt")}})
	if want := []DropDetailEntry{{Timestamp: now, SrcIP: "1.1.1.1", DstIP: "2.2.2.2", SrcPort: 1234, DstPort: 443, Protocol: 6, Reason: 9, Count: 10, Payload: []byte("pkt")}}; !reflect.DeepEqual(drops, want) {
		t.Fatalf("drop detail conversion mismatch: got %+v want %+v", drops, want)
	}

	if got := PluginTypeFromSDK(sdk.PluginTypeCore); got != PluginTypeCore {
		t.Fatalf("expected core plugin type, got %s", got)
	}
	if got := PluginTypeFromSDK(sdk.PluginTypeExtension); got != PluginTypeExtension {
		t.Fatalf("expected extension plugin type, got %s", got)
	}
	if got := RuntimeKindFromPluginType(PluginTypeCore); got != domainruntime.KindCore {
		t.Fatalf("expected core runtime kind, got %s", got)
	}
	if got := RuntimeKindFromPluginType(PluginTypeExtension); got != domainruntime.KindExtension {
		t.Fatalf("expected extension runtime kind, got %s", got)
	}

	health := HealthCheckResultToSDK(HealthCheckResult{Status: HealthStatusDegraded, Message: "slow", Details: map[string]any{"latency": "high"}})
	if health.Status != sdk.HealthStatusDegraded || health.Message != "slow" || health.Details["latency"] != "high" {
		t.Fatalf("unexpected health conversion: %+v", health)
	}
}

func TestSDKCompatConfigRoundTrip(t *testing.T) {
	original := &sdk.GlobalConfig{
		Cluster: sdk.ClusterConfig{Enabled: true, ConfigPath: "/etc/netxfw/cluster.toml"},
		Base: sdk.BaseConfig{
			DefaultDeny: true, AllowReturnTraffic: true, AllowICMP: true, Interfaces: []string{"eth0"},
			EnableAFXDP: true, StrictProtocol: true, DropFragments: true, StrictTCP: true, SYNLimit: true,
			BogonFilter: true, ICMPRate: 10, ICMPBurst: 20, Whitelist: []string{"10.0.0.0/8"},
			LockListFile: "/etc/netxfw/deny.txt", LockListBinary: "/etc/netxfw/deny.bin.zst",
			LockListMergeThreshold: 10, LockListV4Mask: 24, LockListV6Mask: 64, BPFPinPath: "/sys/fs/bpf/netxfw",
			EnableExpiry: true, CleanupInterval: "1m", PersistRules: true, EnablePprof: true, PprofBind: "127.0.0.1", PprofPort: 6060, BackupKeep: 3,
		},
		Web:       sdk.WebConfig{Enabled: true, Bind: "127.0.0.1", Port: 11811, Token: "web-token"},
		Metrics:   sdk.MetricsConfig{Enabled: true, ServerEnabled: true, Bind: "127.0.0.1", Port: 11812, Token: "metrics-token", PushEnabled: true, PushGatewayAddr: "http://127.0.0.1:9091", PushInterval: "15s", TextfileEnabled: true, TextfilePath: "/var/lib/node_exporter", TopN: 5, ThresholdCritical: 90, ThresholdHigh: 75, ThresholdMedium: 50, StatsInterval: "1s", AvgPacketSize: 500},
		Port:      sdk.PortConfig{AllowedPorts: []uint16{22, 443}, IPPortRules: []sdk.IPPortRule{{IP: "192.0.2.1/32", Port: 443, Action: 1}}},
		Conntrack: sdk.ConntrackConfig{Enabled: true, MaxEntries: 1000, TCPTimeout: "1h", UDPTimeout: "5m"},
		RateLimit: sdk.RateLimitConfig{Enabled: true, AutoBlock: true, AutoBlockExpiry: "10m", Rules: []sdk.RateLimitRule{{IP: "0.0.0.0/0", Rate: 1000, Burst: 2000}}},
		LogEngine: sdk.LogEngineConfig{Enabled: true, Workers: 2, MaxWindow: 60, Rules: []sdk.LogEngineRule{{ID: "ssh", Path: "/var/log/auth.log", TailPosition: "end", Expression: "true", Action: "log", Keywords: []string{"ssh"}, Contains: []string{"Failed"}, AnyContains: []string{"Invalid"}, NotContains: []string{"Accepted"}, And: []string{"a"}, Is: []string{"b"}, Or: []string{"c"}, Not: []string{"d"}, Regex: "Failed", Threshold: 3, Interval: 60, TTL: "10m"}}},
		Capacity:  sdk.CapacityConfig{Conntrack: 1000, LockList: 2000, DynLockList: 3000, Whitelist: 4000, IPPortRules: 5000, AllowedPorts: 100, RateLimits: 6000, DropReasonStats: 7000, PassReasonStats: 8000},
		Logging:   sdk.LoggingConfig{Enabled: true, Level: "info", Path: "/var/log/netxfw/agent.log", Format: "json", MaxSize: 10, MaxBackups: 3, MaxAge: 30, Compress: true},
		Cloud:     sdk.CloudConfig{Enabled: true, Provider: "aws", ProxyProtocol: sdk.ProxyProtocolConfig{Enabled: true, TrustedLBRanges: []string{"10.0.0.0/8"}, CacheTTL: "5m"}},
		BPFPlugin: sdk.BPFPluginSettings{Enabled: true, Plugins: []sdk.BPFPluginConfig{{Path: "/usr/lib/netxfw/plugins/filter.o", Index: 2, Enabled: true, Description: "filter"}}},
		Modules:   []sdk.ModuleConfig{{Name: "sanity", Enabled: true, Priority: 1}},
		Runtime:   sdk.RuntimeServicesConfig{AI: sdk.AIConfig{Enabled: true, Port: 11813, Model: "small", APIKey: "key", BaseURL: "http://127.0.0.1"}, MCP: sdk.MCPConfig{Enabled: true, Port: 11814, Mode: "sse"}},
	}

	domainCfg := ConfigFromSDK(original)
	if domainCfg == nil {
		t.Fatalf("expected domain config")
	}
	if domainCfg.Web.Token != original.Web.Token || domainCfg.Metrics.Token != original.Metrics.Token || domainCfg.Base.PprofBind != original.Base.PprofBind {
		t.Fatalf("security fields were not preserved: %+v", domainCfg)
	}

	roundTrip := ConfigToSDK(domainCfg)
	if !reflect.DeepEqual(roundTrip, original) {
		t.Fatalf("roundtrip mismatch:\ngot:  %+v\nwant: %+v", roundTrip, original)
	}

	domainOnly := &domainconfig.Config{Port: domainconfig.PortConfig{AllowedPorts: []uint16{80}, IPPortRules: []domainconfig.IPPortRule{{IP: "203.0.113.1/32", Port: 80, Action: 1}}}}
	sdkCfg := ConfigToSDK(domainOnly)
	if len(sdkCfg.Port.AllowedPorts) != 1 || sdkCfg.Port.AllowedPorts[0] != 80 || len(sdkCfg.Port.IPPortRules) != 1 {
		t.Fatalf("domain to SDK port conversion failed: %+v", sdkCfg.Port)
	}
}
