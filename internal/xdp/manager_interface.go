package xdp

import (
	"time"

	"github.com/cilium/ebpf"
	"github.com/livp123/netxfw/internal/plugins/types"
)

// ManagerInterface defines the interface for XDP operations.
// ManagerInterface 定义了 XDP 操作的接口。
type ManagerInterface interface {
	// Sync Operations
	SyncFromFiles(cfg *types.GlobalConfig, overwrite bool) error
	SyncToFiles(cfg *types.GlobalConfig) error

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
