package sdk

import (
	"time"

	"github.com/cilium/ebpf"
	"github.com/livp123/netxfw/internal/plugins/types"
)

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
	// Sync Operations
	SyncFromFiles(cfg *types.GlobalConfig, overwrite bool) error
	SyncToFiles(cfg *types.GlobalConfig) error
	VerifyAndRepair(cfg *types.GlobalConfig) error

	// Map Getters (discouraged for direct use, prefer high-level methods)
	LockList() *ebpf.Map
	DynLockList() *ebpf.Map
	Whitelist() *ebpf.Map
	IPPortRules() *ebpf.Map
	AllowedPorts() *ebpf.Map
	RateLimitConfig() *ebpf.Map
	GlobalConfig() *ebpf.Map
	ConntrackMap() *ebpf.Map

	// Configuration
	SetDefaultDeny(enable bool) error
	SetStrictTCP(enable bool) error
	SetSYNLimit(enable bool) error
	SetBogonFilter(enable bool) error
	SetEnableAFXDP(enable bool) error
	SetEnableRateLimit(enable bool) error
	SetDropFragments(enable bool) error

	// Advanced Configuration
	SetAutoBlock(enable bool) error
	SetAutoBlockExpiry(duration time.Duration) error
	SetConntrack(enable bool) error
	SetConntrackTimeout(timeout time.Duration) error
	SetAllowReturnTraffic(enable bool) error
	SetAllowICMP(enable bool) error
	SetStrictProtocol(enable bool) error
	SetICMPRateLimit(rate, burst uint64) error

	// Blacklist Operations
	AddBlacklistIP(cidr string) error
	AddBlacklistIPWithFile(cidr string, file string) error
	AddDynamicBlacklistIP(cidr string, ttl time.Duration) error
	RemoveBlacklistIP(cidr string) error
	ClearBlacklist() error
	IsIPInBlacklist(cidr string) (bool, error)
	ListBlacklistIPs(limit int, search string) ([]BlockedIP, int, error)
	ListDynamicBlacklistIPs(limit int, search string) ([]BlockedIP, int, error)

	// Whitelist Operations
	AddWhitelistIP(cidr string, port uint16) error
	RemoveWhitelistIP(cidr string) error
	ClearWhitelist() error
	IsIPInWhitelist(cidr string) (bool, error)
	ListWhitelistIPs(limit int, search string) ([]string, int, error)

	// IP Port Rules Operations
	AddIPPortRule(cidr string, port uint16, action uint8) error
	RemoveIPPortRule(cidr string, port uint16) error
	ClearIPPortRules() error
	ListIPPortRules(isIPv6 bool, limit int, search string) ([]IPPortRule, int, error)

	// Allowed Ports Operations
	AllowPort(port uint16) error
	RemoveAllowedPort(port uint16) error
	ClearAllowedPorts() error
	ListAllowedPorts() ([]uint16, error)

	// Rate Limit Operations
	AddRateLimitRule(cidr string, rate uint64, burst uint64) error
	RemoveRateLimitRule(cidr string) error
	ClearRateLimitRules() error
	ListRateLimitRules(limit int, search string) (map[string]RateLimitConf, int, error)

	// Conntrack Operations
	ListAllConntrackEntries() ([]ConntrackEntry, error)

	// Stats
	GetDropDetails() ([]DropDetailEntry, error)
	GetPassDetails() ([]DropDetailEntry, error)
	GetDropCount() (uint64, error)
	GetPassCount() (uint64, error)
	GetLockedIPCount() (int, error)
	GetWhitelistCount() (int, error)
	GetConntrackCount() (int, error)

	Close() error
}

// BlockedIP represents an IP address in the blacklist.
type BlockedIP struct {
	IP        string
	ExpiresAt uint64
	Counter   uint64
}

// IPPortRule represents an IP+Port rule.
type IPPortRule struct {
	IP     string
	Port   uint16
	Action uint8 // 1=Allow, 2=Deny
}

// RateLimitConf represents rate limiting configuration for a CIDR.
type RateLimitConf struct {
	Rate  uint64
	Burst uint64
}

// ConntrackEntry represents a single connection tracking entry.
type ConntrackEntry struct {
	SrcIP    string
	DstIP    string
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
	LastSeen time.Time
}

// DropDetailEntry represents detailed statistics for dropped/passed packets.
type DropDetailEntry struct {
	Timestamp time.Time
	SrcIP     string
	DstIP     string
	SrcPort   uint16
	DstPort   uint16
	Protocol  uint8
	Reason    uint32
	Count     uint64
	Payload   []byte
}

// DropLogEntry matches DropDetailEntry but specifically for high-level logs.
type DropLogEntry struct {
	Timestamp time.Time
	SrcIP     string
	DstIP     string
	SrcPort   uint16
	DstPort   uint16
	Protocol  uint8
	Reason    uint32
	Count     uint64
	Payload   []byte
}
