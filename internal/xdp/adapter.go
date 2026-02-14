package xdp

import (
	"fmt"
	"time"

	"github.com/cilium/ebpf"
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/utils/iputil"
)

type Adapter struct {
	manager *Manager
}

func NewAdapter(m *Manager) *Adapter {
	return &Adapter{manager: m}
}

// Sync Operations
func (a *Adapter) SyncFromFiles(cfg *types.GlobalConfig, overwrite bool) error {
	return a.manager.SyncFromFiles(cfg, overwrite)
}
func (a *Adapter) SyncToFiles(cfg *types.GlobalConfig) error {
	return a.manager.SyncToFiles(cfg)
}

// Map Getters
func (a *Adapter) LockList() *ebpf.Map        { return a.manager.LockList() }
func (a *Adapter) DynLockList() *ebpf.Map     { return a.manager.DynLockList() }
func (a *Adapter) Whitelist() *ebpf.Map       { return a.manager.Whitelist() }
func (a *Adapter) IPPortRules() *ebpf.Map     { return a.manager.IPPortRules() }
func (a *Adapter) AllowedPorts() *ebpf.Map    { return a.manager.AllowedPorts() }
func (a *Adapter) RateLimitConfig() *ebpf.Map { return a.manager.RatelimitConfig() }
func (a *Adapter) GlobalConfig() *ebpf.Map    { return a.manager.GlobalConfig() }
func (a *Adapter) ConntrackMap() *ebpf.Map    { return a.manager.ConntrackMap() }

// Configuration
func (a *Adapter) SetDefaultDeny(enable bool) error     { return a.manager.SetDefaultDeny(enable) }
func (a *Adapter) SetStrictTCP(enable bool) error       { return a.manager.SetStrictTCP(enable) }
func (a *Adapter) SetSYNLimit(enable bool) error        { return a.manager.SetSYNLimit(enable) }
func (a *Adapter) SetBogonFilter(enable bool) error     { return a.manager.SetBogonFilter(enable) }
func (a *Adapter) SetEnableAFXDP(enable bool) error     { return a.manager.SetEnableAFXDP(enable) }
func (a *Adapter) SetEnableRateLimit(enable bool) error { return a.manager.SetEnableRateLimit(enable) }
func (a *Adapter) SetDropFragments(enable bool) error {
	return a.manager.SetDropFragments(enable)
}

// Advanced Configuration
func (a *Adapter) SetAutoBlock(enable bool) error {
	return a.manager.SetAutoBlock(enable)
}
func (a *Adapter) SetAutoBlockExpiry(duration time.Duration) error {
	return a.manager.SetAutoBlockExpiry(duration)
}
func (a *Adapter) SetConntrack(enable bool) error {
	return a.manager.SetConntrack(enable)
}
func (a *Adapter) SetConntrackTimeout(timeout time.Duration) error {
	// Adapter only supports single timeout for now as per underlying manager
	// Ideally, manager should be updated to support TCP/UDP separation if needed
	return a.manager.SetConntrackTimeout(timeout)
}
func (a *Adapter) SetAllowReturnTraffic(enable bool) error {
	return a.manager.SetAllowReturnTraffic(enable)
}
func (a *Adapter) SetAllowICMP(enable bool) error {
	return a.manager.SetAllowICMP(enable)
}
func (a *Adapter) SetStrictProtocol(enable bool) error {
	// Map SetStrictProtocol to SetStrictProto
	return a.manager.SetStrictProto(enable)
}
func (a *Adapter) SetICMPRateLimit(rate, burst uint64) error {
	return a.manager.SetICMPRateLimit(rate, burst)
}

// Blacklist Operations
func (a *Adapter) AddBlacklistIP(cidr string) error {
	return LockIP(a.manager.LockList(), cidr)
}
func (a *Adapter) AddBlacklistIPWithFile(cidr string, file string) error {
	return a.manager.BlockStatic(cidr, file)
}
func (a *Adapter) AddDynamicBlacklistIP(cidr string, ttl time.Duration) error {
	return a.manager.BlockDynamic(cidr, ttl)
}
func (a *Adapter) RemoveBlacklistIP(cidr string) error {
	return UnlockIP(a.manager.LockList(), cidr)
}
func (a *Adapter) ClearBlacklist() error {
	return ClearBlacklistMap(a.manager.LockList())
}
func (a *Adapter) IsIPInBlacklist(cidr string) (bool, error) {
	return IsIPInMap(a.manager.LockList(), cidr)
}
func (a *Adapter) ListBlacklistIPs(limit int, search string) ([]BlockedIP, int, error) {
	return ListBlockedIPs(a.manager.LockList(), false, limit, search)
}
func (a *Adapter) ListDynamicBlacklistIPs(limit int, search string) ([]BlockedIP, int, error) {
	return ListBlockedIPs(a.manager.DynLockList(), false, limit, search)
}

// Whitelist Operations
func (a *Adapter) AddWhitelistIP(cidr string, port uint16) error {
	return AllowIP(a.manager.Whitelist(), cidr, port)
}
func (a *Adapter) RemoveWhitelistIP(cidr string) error {
	return UnlockIP(a.manager.Whitelist(), cidr)
}
func (a *Adapter) ClearWhitelist() error {
	return ClearBlacklistMap(a.manager.Whitelist())
}
func (a *Adapter) IsIPInWhitelist(cidr string) (bool, error) {
	return IsIPInMap(a.manager.Whitelist(), cidr)
}
func (a *Adapter) ListWhitelistIPs(limit int, search string) ([]string, int, error) {
	return ListWhitelistIPs(a.manager.Whitelist(), limit, search)
}

// IP Port Rules Operations
func (a *Adapter) AddIPPortRule(cidr string, port uint16, action uint8) error {
	return AddIPPortRuleToMapString(a.manager.IPPortRules(), cidr, port, action)
}
func (a *Adapter) RemoveIPPortRule(cidr string, port uint16) error {
	return RemoveIPPortRuleFromMapString(a.manager.IPPortRules(), cidr, port)
}
func (a *Adapter) ClearIPPortRules() error {
	return ClearIPPortMap(a.manager.IPPortRules())
}
func (a *Adapter) ListIPPortRules(isIPv6 bool, limit int, search string) ([]IPPortRule, int, error) {
	return ListIPPortRulesFromMap(a.manager.IPPortRules(), limit, search)
}

// Allowed Ports Operations
func (a *Adapter) AllowPort(port uint16) error {
	return AllowPortToMap(a.manager.AllowedPorts(), port, nil)
}
func (a *Adapter) RemoveAllowedPort(port uint16) error {
	return RemovePortFromMap(a.manager.AllowedPorts(), port)
}
func (a *Adapter) ClearAllowedPorts() error {
	return ClearPortMap(a.manager.AllowedPorts())
}
func (a *Adapter) ListAllowedPorts() ([]uint16, error) {
	return ListAllowedPortsFromMap(a.manager.AllowedPorts())
}

// Rate Limit Operations
func (a *Adapter) AddRateLimitRule(cidr string, rate uint64, burst uint64) error {
	ipNet, err := iputil.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %v", err)
	}
	return a.manager.AddRateLimitRule(ipNet, rate, burst)
}
func (a *Adapter) RemoveRateLimitRule(cidr string) error {
	ipNet, err := iputil.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %v", err)
	}
	return a.manager.RemoveRateLimitRule(ipNet)
}
func (a *Adapter) ClearRateLimitRules() error {
	return ClearRateLimitMap(a.manager.RatelimitConfig())
}
func (a *Adapter) ListRateLimitRules(limit int, search string) (map[string]RateLimitConf, int, error) {
	return ListRateLimitRulesFromMap(a.manager.RatelimitConfig(), limit, search)
}

// Conntrack Operations
func (a *Adapter) ListAllConntrackEntries() ([]ConntrackEntry, error) {
	return a.manager.ListConntrackEntries()
}

// Stats
func (a *Adapter) GetDropDetails() ([]DropDetailEntry, error) {
	return a.manager.GetDropDetails()
}
func (a *Adapter) GetPassDetails() ([]DropDetailEntry, error) {
	return a.manager.GetPassDetails()
}
func (a *Adapter) GetDropCount() (uint64, error) {
	return a.manager.GetDropCount()
}
func (a *Adapter) GetPassCount() (uint64, error) {
	return a.manager.GetPassCount()
}
func (a *Adapter) GetLockedIPCount() (int, error) {
	count, err := a.manager.GetLockedIPCount()
	return int(count), err
}
func (a *Adapter) GetWhitelistCount() (int, error) {
	count, err := a.manager.GetWhitelistCount()
	return int(count), err
}
func (a *Adapter) GetConntrackCount() (int, error) {
	count, err := a.manager.GetConntrackCount()
	return int(count), err
}

func (a *Adapter) Close() error {
	return a.manager.Close()
}
