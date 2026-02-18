package sdk

import (
	"time"

	"github.com/cilium/ebpf"
	"github.com/livp123/netxfw/internal/plugins/types"
)

// =============================================================================
// Core Interfaces - 核心接口
// =============================================================================

// Firewall defines the high-level interface for firewall operations.
// This is the primary interface for most plugins (AI, MCP, LogEngine, etc.).
// Firewall 定义了防火墙操作的高级接口。
// 这是大多数插件（AI、MCP、日志引擎等）的主要接口。
type Firewall interface {
	// GetStats returns total pass and drop counts.
	// GetStats 返回总的通过和丢弃计数。
	GetStats() (pass uint64, drop uint64)

	// GetDropLogs returns recent drop log entries.
	// GetDropLogs 返回最近的丢弃日志条目。
	GetDropLogs() ([]DropLogEntry, error)

	// Blacklist Operations
	// 黑名单操作
	AddBlacklistIP(cidr string) error
	AddBlacklistIPWithFile(cidr string, file string) error
	AddDynamicBlacklistIP(cidr string, ttl time.Duration) error
	RemoveBlacklistIP(cidr string) error

	// BlockIP is a helper that calls AddBlacklistIP or AddDynamicBlacklistIP.
	// BlockIP 是一个辅助函数，调用 AddBlacklistIP 或 AddDynamicBlacklistIP。
	BlockIP(cidr string, duration time.Duration) error
}

// ManagerInterface defines the low-level interface for XDP operations.
// This provides direct access to BPF maps and low-level configuration.
// ManagerInterface 定义了 XDP 操作的低级接口。
// 这提供了对 BPF Map 和低级配置的直接访问。
type ManagerInterface interface {
	// Sync Operations - 同步操作
	SyncFromFiles(cfg *types.GlobalConfig, overwrite bool) error
	SyncToFiles(cfg *types.GlobalConfig) error
	VerifyAndRepair(cfg *types.GlobalConfig) error

	// Map Getters - Map 获取器（不推荐直接使用，优先使用高级方法）
	LockList() *ebpf.Map
	DynLockList() *ebpf.Map
	Whitelist() *ebpf.Map
	IPPortRules() *ebpf.Map
	AllowedPorts() *ebpf.Map
	RateLimitConfig() *ebpf.Map
	GlobalConfig() *ebpf.Map
	ConntrackMap() *ebpf.Map

	// Configuration - 配置方法
	SetDefaultDeny(enable bool) error
	SetStrictTCP(enable bool) error
	SetSYNLimit(enable bool) error
	SetBogonFilter(enable bool) error
	SetEnableAFXDP(enable bool) error
	SetEnableRateLimit(enable bool) error
	SetDropFragments(enable bool) error

	// Advanced Configuration - 高级配置
	SetAutoBlock(enable bool) error
	SetAutoBlockExpiry(duration time.Duration) error
	SetConntrack(enable bool) error
	SetConntrackTimeout(timeout time.Duration) error
	SetAllowReturnTraffic(enable bool) error
	SetAllowICMP(enable bool) error
	SetStrictProtocol(enable bool) error
	SetICMPRateLimit(rate, burst uint64) error

	// Blacklist Operations - 黑名单操作
	AddBlacklistIP(cidr string) error
	AddBlacklistIPWithFile(cidr string, file string) error
	AddDynamicBlacklistIP(cidr string, ttl time.Duration) error
	RemoveBlacklistIP(cidr string) error
	ClearBlacklist() error
	IsIPInBlacklist(cidr string) (bool, error)
	ListBlacklistIPs(limit int, search string) ([]BlockedIP, int, error)
	ListDynamicBlacklistIPs(limit int, search string) ([]BlockedIP, int, error)

	// Whitelist Operations - 白名单操作
	AddWhitelistIP(cidr string, port uint16) error
	RemoveWhitelistIP(cidr string) error
	ClearWhitelist() error
	IsIPInWhitelist(cidr string) (bool, error)
	ListWhitelistIPs(limit int, search string) ([]string, int, error)

	// IP Port Rules Operations - IP 端口规则操作
	AddIPPortRule(cidr string, port uint16, action uint8) error
	RemoveIPPortRule(cidr string, port uint16) error
	ClearIPPortRules() error
	ListIPPortRules(isIPv6 bool, limit int, search string) ([]IPPortRule, int, error)

	// Allowed Ports Operations - 允许端口操作
	AllowPort(port uint16) error
	RemoveAllowedPort(port uint16) error
	ClearAllowedPorts() error
	ListAllowedPorts() ([]uint16, error)

	// Rate Limit Operations - 限速操作
	AddRateLimitRule(cidr string, rate uint64, burst uint64) error
	RemoveRateLimitRule(cidr string) error
	ClearRateLimitRules() error
	ListRateLimitRules(limit int, search string) (map[string]RateLimitConf, int, error)

	// Conntrack Operations - 连接跟踪操作
	ListAllConntrackEntries() ([]ConntrackEntry, error)

	// Stats - 统计
	GetDropDetails() ([]DropDetailEntry, error)
	GetPassDetails() ([]DropDetailEntry, error)
	GetDropCount() (uint64, error)
	GetPassCount() (uint64, error)
	GetLockedIPCount() (int, error)
	GetWhitelistCount() (int, error)
	GetConntrackCount() (int, error)
	GetDynLockListCount() (uint64, error)

	// Cached Stats - 缓存统计（用于性能优化）
	InvalidateStatsCache()

	// Performance Statistics - 性能统计
	PerfStats() interface{}

	Close() error
}

// =============================================================================
// Feature-Specific Interfaces - 功能特定接口
// =============================================================================

// BlacklistAPI defines the interface for blacklist operations.
// BlacklistAPI 定义了黑名单操作的接口。
type BlacklistAPI interface {
	// Add adds an IP or CIDR to the blacklist.
	// Add 将 IP 或 CIDR 添加到黑名单。
	Add(cidr string) error

	// AddWithDuration adds an IP or CIDR to the blacklist with an expiration time.
	// AddWithDuration 将 IP 或 CIDR 添加到具有过期时间的黑名单中。
	AddWithDuration(cidr string, duration time.Duration) error

	// AddWithFile adds an IP or CIDR to the blacklist and persists it to a file.
	// AddWithFile 将 IP 或 CIDR 添加到黑名单并持久化到文件。
	AddWithFile(cidr string, file string) error

	// Remove removes an IP or CIDR from the blacklist.
	// Remove 从黑名单中移除 IP 或 CIDR。
	Remove(cidr string) error

	// Clear removes all entries from the blacklist.
	// Clear 移除黑名单中的所有条目。
	Clear() error

	// Contains checks if an IP is in the blacklist.
	// Contains 检查 IP 是否在黑名单中。
	Contains(ip string) (bool, error)

	// List returns a list of blacklisted IPs.
	// List 返回黑名单 IP 的列表。
	List(limit int, search string) ([]BlockedIP, int, error)
}

// WhitelistAPI defines the interface for whitelist operations.
// WhitelistAPI 定义了白名单操作的接口。
type WhitelistAPI interface {
	// Add adds an IP or CIDR to the whitelist.
	// Add 将 IP 或 CIDR 添加到白名单。
	// Optional port can be provided. If port > 0, it whitelists only that port.
	Add(cidr string, port uint16) error

	// AddWithPort adds an IP or CIDR to the whitelist for a specific port.
	// AddWithPort 将特定端口的 IP 或 CIDR 添加到白名单。
	AddWithPort(cidr string, port uint16) error

	// Remove removes an IP or CIDR from the whitelist.
	// Remove 从白名单中移除 IP 或 CIDR。
	Remove(cidr string) error

	// Clear removes all entries from the whitelist.
	// Clear 移除白名单中的所有条目。
	Clear() error

	// Contains checks if an IP is in the whitelist.
	// Contains 检查 IP 是否在白名单中。
	Contains(ip string) (bool, error)

	// List returns a list of whitelisted IPs.
	// List 返回白名单 IP 的列表。
	List(limit int, search string) ([]string, int, error)
}

// RuleAPI defines the interface for rule operations (IP/Port rules).
// RuleAPI 定义了规则操作（IP/端口规则）的接口。
type RuleAPI interface {
	// Add adds an IP/Port rule.
	// Add 添加一个 IP/端口规则。
	Add(cidr string, port uint16, action uint8) error

	// Remove removes an IP/Port rule.
	// Remove 移除一个 IP/端口规则。
	Remove(cidr string, port uint16) error

	// Clear removes all IP/Port rules.
	// Clear 移除所有 IP/端口规则。
	Clear() error

	// List returns a list of IP/Port rules.
	// List 返回 IP/端口规则的列表。
	List(isIPv6 bool, limit int, search string) ([]IPPortRule, int, error)

	// AddIPPortRule adds an IP/Port rule.
	// AddIPPortRule 添加一个 IP/端口规则。
	AddIPPortRule(cidr string, port uint16, action uint8) error

	// RemoveIPPortRule removes an IP/Port rule.
	// RemoveIPPortRule 移除一个 IP/端口规则。
	RemoveIPPortRule(cidr string, port uint16) error

	// ListIPPortRules returns a list of IP/Port rules.
	// ListIPPortRules 返回 IP/端口规则的列表。
	ListIPPortRules(limit int, search string) ([]IPPortRule, int, error)

	// AllowPort adds a port to the global allowed list.
	// AllowPort 将端口添加到全局允许列表。
	AllowPort(port uint16) error

	// RemoveAllowedPort removes a port from the global allowed list.
	// RemoveAllowedPort 从全局允许列表中移除端口。
	RemoveAllowedPort(port uint16) error

	// AddRateLimitRule adds a rate limit rule for an IP.
	// AddRateLimitRule 为 IP 添加限速规则。
	AddRateLimitRule(ip string, rate, burst uint64) error

	// RemoveRateLimitRule removes a rate limit rule for an IP.
	// RemoveRateLimitRule 移除 IP 的限速规则。
	RemoveRateLimitRule(ip string) error

	// ListRateLimitRules lists rate limit rules.
	// ListRateLimitRules 列出限速规则。
	ListRateLimitRules(limit int, search string) (map[string]RateLimitConf, int, error)
}

// SecurityAPI defines methods for security configuration.
// SecurityAPI 定义了安全配置的方法。
type SecurityAPI interface {
	SetDefaultDeny(enable bool) error
	SetEnableAFXDP(enable bool) error
	SetDropFragments(enable bool) error
	SetStrictTCP(enable bool) error
	SetSYNLimit(enable bool) error
	SetConntrack(enable bool) error
	SetConntrackTimeout(timeout time.Duration) error
	SetBogonFilter(enable bool) error
	SetAutoBlock(enable bool) error
	SetAutoBlockExpiry(duration time.Duration) error
}

// StatsAPI defines the interface for statistics operations.
// StatsAPI 定义了统计操作的接口。
type StatsAPI interface {
	// GetCounters returns global pass and drop counts.
	// GetCounters 返回全局放行和丢弃计数。
	GetCounters() (pass uint64, drop uint64, err error)

	// GetDropDetails returns detailed drop statistics.
	// GetDropDetails 返回详细的拦截统计信息。
	GetDropDetails() ([]DropDetailEntry, error)

	// GetPassDetails returns detailed pass statistics.
	// GetPassDetails 返回详细的放行统计信息。
	GetPassDetails() ([]DropDetailEntry, error)

	// GetLockedIPCount returns the number of currently locked IPs.
	// GetLockedIPCount 返回当前被锁定的 IP 数量。
	GetLockedIPCount() (int, error)
}

// ConntrackAPI defines methods for connection tracking operations.
// ConntrackAPI 定义了连接跟踪操作的方法。
type ConntrackAPI interface {
	// List returns all active connections.
	// List 返回所有活动连接。
	List() ([]ConntrackEntry, error)

	// Count returns the number of active connections.
	// Count 返回活动连接的数量。
	Count() (int, error)
}

// SyncAPI defines methods for synchronizing configuration.
// SyncAPI 定义了配置同步的方法。
type SyncAPI interface {
	// ToConfig synchronizes state to the configuration.
	// ToConfig 将状态同步到配置。
	ToConfig(cfg *types.GlobalConfig) error

	// ToMap synchronizes configuration to BPF maps.
	// ToMap 将配置同步到 BPF Map。
	ToMap(cfg *types.GlobalConfig, overwrite bool) error

	// VerifyAndRepair verifies and repairs the state.
	// VerifyAndRepair 验证并修复状态。
	VerifyAndRepair(cfg *types.GlobalConfig) error
}
