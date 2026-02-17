//go:build linux
// +build linux

package xdp

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/livp123/netxfw/pkg/sdk"
)

// Logger defines the logging interface used by the XDP manager.
// Logger 定义 XDP 管理器使用的日志接口。
// It matches the sdk.Logger interface but decouples the dependency.
// 它匹配 sdk.Logger 接口，但解耦了依赖关系。
type Logger interface {
	Infof(template string, args ...interface{})
	Warnf(template string, args ...interface{})
	Errorf(template string, args ...interface{})
}

// Generate Go bindings for the BPF program / 为 BPF 程序生成 Go 绑定
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang NetXfw ../../bpf/netxfw.bpf.c -- -I../../bpf

// Global config indices / 全局配置索引
const (
	configDefaultDeny        = 0
	configAllowReturnTraffic = 1
	configAllowICMP          = 2
	configEnableConntrack    = 3
	configConntrackTimeout   = 4
	configICMPRate           = 5
	configICMPBurst          = 6
	configEnableAFXDP        = 7
	configVersion            = 8
	configStrictProto        = 9
	configEnableRateLimit    = 10
	configDropFragments      = 11
	configStrictTCP          = 12
	configSYNLimit           = 13
	configBogonFilter        = 14
	configAutoBlock          = 15
	configAutoBlockExpiry    = 16
)

// Program indices for jmp_table / jmp_table 的程序索引
const (
	ProgIdxIPv4        = 0
	ProgIdxIPv6        = 1
	ProgIdxPluginStart = 2
	ProgIdxPluginEnd   = 15
)

// Re-export SDK types for internal use if needed, or just use sdk.X
// 如有需要，重新导出 SDK 类型供内部使用，或直接使用 sdk.X
type RateLimitConf = sdk.RateLimitConf
type IPPortRule = sdk.IPPortRule
type ConntrackEntry = sdk.ConntrackEntry
type BlockedIP = sdk.BlockedIP
type DropDetailEntry = sdk.DropDetailEntry

/**
 * Manager handles the lifecycle of eBPF objects and links.
 * Manager 负责 eBPF 对象和链路的生命周期管理。
 */
type Manager struct {
	objs   NetXfwObjects
	links  []link.Link
	logger Logger

	// Core maps / 核心 Map
	conntrackMap      *ebpf.Map // Connection tracking / 连接跟踪
	ratelimitMap      *ebpf.Map // Rate limit (config + state combined) / 速率限制（配置 + 状态合并）
	staticBlacklist   *ebpf.Map // Static blacklist (persistent) / 静态黑名单（持久化）
	dynamicBlacklist  *ebpf.Map // Dynamic blacklist (auto-expiry) / 动态黑名单（自动过期）
	criticalBlacklist *ebpf.Map // Critical blacklist (highest priority) / 危机封锁（最高优先级）
	whitelist         *ebpf.Map // Whitelist / 白名单
	ruleMap           *ebpf.Map // IP+Port rules / IP+端口规则
	statsGlobalMap    *ebpf.Map // Global statistics / 全局统计
	topDropMap        *ebpf.Map // Top drop statistics / Top 丢弃统计
	topPassMap        *ebpf.Map // Top pass statistics / Top 通过统计
	globalConfig      *ebpf.Map // Global configuration / 全局配置
	jmpTable          *ebpf.Map // Program jump table / 程序跳转表
	xskMap            *ebpf.Map // AF_XDP socket map / AF_XDP socket 映射

	// Statistics cache / 统计缓存
	statsCache *StatsCache

	// Incremental updater for config changes / 配置变更的增量更新器
	incrementalUpdater *IncrementalUpdater

	// Performance statistics tracker / 性能统计跟踪器
	perfStats *PerformanceStats

	// Backward compatibility aliases (deprecated) / 向后兼容别名（已弃用）
	// These will be removed in a future version / 这些将在未来版本中移除
	lockList        *ebpf.Map // Deprecated: use staticBlacklist / 已弃用：使用 staticBlacklist
	dynLockList     *ebpf.Map // Deprecated: use dynamicBlacklist / 已弃用：使用 dynamicBlacklist
	dropReasonStats *ebpf.Map // Deprecated: use topDropMap / 已弃用：使用 topDropMap
	passReasonStats *ebpf.Map // Deprecated: use topPassMap / 已弃用：使用 topPassMap
}

// Map getters / Map 获取器

// ConntrackMap returns the connection tracking map.
// ConntrackMap 返回连接跟踪 Map。
func (m *Manager) ConntrackMap() *ebpf.Map {
	return m.conntrackMap
}

// RatelimitMap returns the rate limit map (config + state combined).
// RatelimitMap 返回速率限制 Map（配置 + 状态合并）。
func (m *Manager) RatelimitMap() *ebpf.Map {
	return m.ratelimitMap
}

// StaticBlacklist returns the static blacklist map.
// StaticBlacklist 返回静态黑名单 Map。
func (m *Manager) StaticBlacklist() *ebpf.Map {
	return m.staticBlacklist
}

// DynamicBlacklist returns the dynamic blacklist map.
// DynamicBlacklist 返回动态黑名单 Map。
func (m *Manager) DynamicBlacklist() *ebpf.Map {
	return m.dynamicBlacklist
}

// CriticalBlacklist returns the critical blacklist map.
// CriticalBlacklist 返回危机封锁 Map。
func (m *Manager) CriticalBlacklist() *ebpf.Map {
	return m.criticalBlacklist
}

// Whitelist returns the whitelist map.
// Whitelist 返回白名单 Map。
func (m *Manager) Whitelist() *ebpf.Map {
	return m.whitelist
}

// RuleMap returns the IP+Port rules map.
// RuleMap 返回 IP+端口规则 Map。
func (m *Manager) RuleMap() *ebpf.Map {
	return m.ruleMap
}

// StatsGlobalMap returns the global statistics map.
// StatsGlobalMap 返回全局统计 Map。
func (m *Manager) StatsGlobalMap() *ebpf.Map {
	return m.statsGlobalMap
}

// TopDropMap returns the top drop statistics map.
// TopDropMap 返回 Top 丢弃统计 Map。
func (m *Manager) TopDropMap() *ebpf.Map {
	return m.topDropMap
}

// TopPassMap returns the top pass statistics map.
// TopPassMap 返回 Top 通过统计 Map。
func (m *Manager) TopPassMap() *ebpf.Map {
	return m.topPassMap
}

// GlobalConfig returns the global configuration map.
// GlobalConfig 返回全局配置 Map。
func (m *Manager) GlobalConfig() *ebpf.Map {
	return m.globalConfig
}

// JmpTable returns the program jump table.
// JmpTable 返回程序跳转表。
func (m *Manager) JmpTable() *ebpf.Map {
	return m.jmpTable
}

// XskMap returns the AF_XDP socket map.
// XskMap 返回 AF_XDP socket Map。
func (m *Manager) XskMap() *ebpf.Map {
	return m.xskMap
}

// StatsCache returns the statistics cache.
// StatsCache 返回统计缓存。
func (m *Manager) StatsCache() *StatsCache {
	return m.statsCache
}

// IncrementalUpdater returns the incremental updater.
// IncrementalUpdater 返回增量更新器。
func (m *Manager) IncrementalUpdater() *IncrementalUpdater {
	return m.incrementalUpdater
}

// PerfStats returns the performance statistics tracker.
// PerfStats 返回性能统计跟踪器。
func (m *Manager) PerfStats() interface{} {
	return m.perfStats
}

// Backward compatibility getters (deprecated) / 向后兼容获取器（已弃用）

// LockList returns the static blacklist map (deprecated: use StaticBlacklist).
// LockList 返回静态黑名单 Map（已弃用：使用 StaticBlacklist）。
func (m *Manager) LockList() *ebpf.Map {
	return m.staticBlacklist
}

// DynLockList returns the dynamic blacklist map (deprecated: use DynamicBlacklist).
// DynLockList 返回动态黑名单 Map（已弃用：使用 DynamicBlacklist）。
func (m *Manager) DynLockList() *ebpf.Map {
	return m.dynamicBlacklist
}

// DropReasonStats returns the top drop map (deprecated: use TopDropMap).
// DropReasonStats 返回 Top 丢弃 Map（已弃用：使用 TopDropMap）。
func (m *Manager) DropReasonStats() *ebpf.Map {
	return m.topDropMap
}

// PassReasonStats returns the top pass map (deprecated: use TopPassMap).
// PassReasonStats 返回 Top 通过 Map（已弃用：使用 TopPassMap）。
func (m *Manager) PassReasonStats() *ebpf.Map {
	return m.topPassMap
}

// Deprecated getters for removed maps / 已移除 Map 的弃用获取器
// These return nil and will be removed in a future version / 这些返回 nil，将在未来版本中移除

// AllowedPorts returns nil (deprecated: use RuleMap).
// AllowedPorts 返回 nil（已弃用：使用 RuleMap）。
func (m *Manager) AllowedPorts() *ebpf.Map {
	return nil
}

// IPPortRules returns nil (deprecated: use RuleMap).
// IPPortRules 返回 nil（已弃用：使用 RuleMap）。
func (m *Manager) IPPortRules() *ebpf.Map {
	return nil
}

// RatelimitConfig returns nil (deprecated: use RatelimitMap).
// RatelimitConfig 返回 nil（已弃用：使用 RatelimitMap）。
func (m *Manager) RatelimitConfig() *ebpf.Map {
	return nil
}
