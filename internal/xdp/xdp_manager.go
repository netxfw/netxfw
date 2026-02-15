//go:build linux
// +build linux

package xdp

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/livp123/netxfw/internal/config"
	"github.com/livp123/netxfw/internal/plugins/types"
)

const (
	CONFIG_DEFAULT_DENY         = 0
	CONFIG_ALLOW_RETURN_TRAFFIC = 1
	CONFIG_ALLOW_ICMP           = 2
	CONFIG_ENABLE_CONNTRACK     = 3
	CONFIG_CONNTRACK_TIMEOUT    = 4
	CONFIG_ICMP_RATE            = 5
	CONFIG_ICMP_BURST           = 6
	CONFIG_ENABLE_AF_XDP        = 7
	CONFIG_CONFIG_VERSION       = 8
	CONFIG_STRICT_PROTO         = 9
	CONFIG_ENABLE_RATELIMIT     = 10
	CONFIG_DROP_FRAGMENTS       = 11
	CONFIG_STRICT_TCP           = 12
	CONFIG_SYN_LIMIT            = 13
	CONFIG_BOGON_FILTER         = 14
	CONFIG_AUTO_BLOCK           = 15
	CONFIG_AUTO_BLOCK_EXPIRY    = 16
)

/**
 * MatchesCapacity checks if the current map capacities match the provided config.
 * MatchesCapacity 检查当前的 Map 容量是否与提供的配置匹配。
 */
func (m *Manager) MatchesCapacity(cfg types.CapacityConfig) bool {
	if cfg.LockList > 0 {
		if m.lockList == nil || m.lockList.MaxEntries() != uint32(cfg.LockList) {
			return false
		}
	}
	if cfg.DynLockList > 0 {
		if m.dynLockList == nil || m.dynLockList.MaxEntries() != uint32(cfg.DynLockList) {
			return false
		}
	}
	if cfg.Whitelist > 0 {
		if m.whitelist == nil || m.whitelist.MaxEntries() != uint32(cfg.Whitelist) {
			return false
		}
	}
	if cfg.IPPortRules > 0 {
		if m.ipPortRules == nil || m.ipPortRules.MaxEntries() != uint32(cfg.IPPortRules) {
			return false
		}
	}
	if cfg.Conntrack > 0 {
		if m.conntrackMap == nil || m.conntrackMap.MaxEntries() != uint32(cfg.Conntrack) {
			return false
		}
	}
	if cfg.AllowedPorts > 0 {
		if m.allowedPorts == nil || m.allowedPorts.MaxEntries() != uint32(cfg.AllowedPorts) {
			return false
		}
	}
	return true
}

/**
 * NewManager initializes the BPF objects and removes memory limits.
 * Supports dynamic map capacity adjustment.
 * NewManager 初始化 BPF 对象并移除内存限制，支持动态调整 Map 容量。
 */
func NewManager(cfg types.CapacityConfig, logger Logger) (*Manager, error) {
	// Remove resource limits for BPF / 移除 BPF 资源限制
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	// Load BPF collection spec / 加载 BPF 集合规范
	spec, err := LoadNetXfw()
	if err != nil {
		return nil, fmt.Errorf("load netxfw spec: %w", err)
	}

	// Dynamic capacity adjustment / 动态调整容量
	if cfg.Conntrack > 0 {
		if m, ok := spec.Maps[config.MapConntrack]; ok {
			m.MaxEntries = uint32(cfg.Conntrack)
		}
	}
	if cfg.LockList > 0 {
		if m, ok := spec.Maps[config.MapLockList]; ok {
			m.MaxEntries = uint32(cfg.LockList)
		}
	}
	if cfg.DynLockList > 0 {
		if m, ok := spec.Maps[config.MapDynLockList]; ok {
			m.MaxEntries = uint32(cfg.DynLockList)
		}
	}
	if cfg.Whitelist > 0 {
		if m, ok := spec.Maps[config.MapWhitelist]; ok {
			m.MaxEntries = uint32(cfg.Whitelist)
		}
	}
	if cfg.IPPortRules > 0 {
		if m, ok := spec.Maps[config.MapIPPortRules]; ok {
			m.MaxEntries = uint32(cfg.IPPortRules)
		}
	}
	if cfg.AllowedPorts > 0 {
		if m, ok := spec.Maps[config.MapAllowedPorts]; ok {
			m.MaxEntries = uint32(cfg.AllowedPorts)
		}
	}

	// Load BPF objects into the kernel / 将 BPF 对象加载到内核
	var objs NetXfwObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("load eBPF objects: %w", err)
	}

	manager := &Manager{
		objs:            objs,
		lockList:        objs.LockList,
		dynLockList:     objs.DynLockList,
		whitelist:       objs.Whitelist,
		allowedPorts:    objs.AllowedPorts,
		ipPortRules:     objs.IpPortRules,
		globalConfig:    objs.GlobalConfig,
		dropStats:       objs.DropStats,
		passStats:       objs.PassStats,
		icmpLimitMap:    objs.IcmpLimitMap,
		conntrackMap:    objs.ConntrackMap,
		ratelimitConfig: objs.RatelimitConfig,
		ratelimitState:  objs.RatelimitState,
		jmpTable:        objs.JmpTable,
		dropReasonStats: objs.DropReasonStats,
		passReasonStats: objs.PassReasonStats,
		logger:          logger,
	}

	// Initialize jump table with default protocol handlers / 初始化跳转表，填充默认的协议处理程序
	if objs.XdpIpv4 != nil {
		if err := objs.JmpTable.Update(uint32(ProgIdxIPv4), objs.XdpIpv4, ebpf.UpdateAny); err != nil {
			return nil, fmt.Errorf("failed to update jmp_table with xdp_ipv4: %w", err)
		}
	}
	if objs.XdpIpv6 != nil {
		if err := objs.JmpTable.Update(uint32(ProgIdxIPv6), objs.XdpIpv6, ebpf.UpdateAny); err != nil {
			return nil, fmt.Errorf("failed to update jmp_table with xdp_ipv6: %w", err)
		}
	}

	return manager, nil
}

/**
 * NewManagerFromPins loads a manager using maps already pinned to the filesystem.
 * This is useful for CLI tools that need to interact with a running XDP program.
 * NewManagerFromPins 使用已固定到文件系统的 Map 加载管理器。
 * 这对于需要与正在运行的 XDP 程序交互的 CLI 工具非常有用。
 */
func NewManagerFromPins(path string, logger Logger) (*Manager, error) {
	// Remove resource limits for BPF / 移除 BPF 资源限制
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	// We still need to load objects to get the program, but we will replace maps with pinned ones
	// 我们仍需加载对象以获取程序，但将使用固定的 Map 替换它们
	var objs NetXfwObjects
	if err := LoadNetXfwObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load eBPF objects: %w", err)
	}

	m := &Manager{
		objs:   objs,
		logger: logger,
	}

	loadMap := func(name string, fallback *ebpf.Map) *ebpf.Map {
		mp, err := ebpf.LoadPinnedMap(path+"/"+name, nil)
		if err != nil {
			logger.Warnf("⚠️  Could not load pinned %s: %v", name, err)
			return fallback
		}
		return mp
	}

	m.lockList = loadMap(config.MapLockList, objs.LockList)
	m.dynLockList = loadMap(config.MapDynLockList, objs.DynLockList)
	m.whitelist = loadMap(config.MapWhitelist, objs.Whitelist)
	m.allowedPorts = loadMap(config.MapAllowedPorts, objs.AllowedPorts)
	m.ipPortRules = loadMap(config.MapIPPortRules, objs.IpPortRules)
	m.globalConfig = loadMap(config.MapGlobalConfig, objs.GlobalConfig)
	m.dropStats = loadMap(config.MapDropStats, objs.DropStats)
	m.dropReasonStats = loadMap(config.MapDropReasonStats, objs.DropReasonStats)
	m.passStats = loadMap(config.MapPassStats, objs.PassStats)
	m.passReasonStats = loadMap(config.MapPassReasonStats, objs.PassReasonStats)
	m.icmpLimitMap = loadMap(config.MapICMPLimit, objs.IcmpLimitMap)
	m.conntrackMap = loadMap(config.MapConntrack, objs.ConntrackMap)
	m.ratelimitConfig = loadMap(config.MapRatelimitConfig, objs.RatelimitConfig)
	m.ratelimitState = loadMap(config.MapRatelimitState, objs.RatelimitState)

	return m, nil
}

// Close releases all BPF resources.
// Note: Persistent links are NOT closed here to allow them to stay in kernel.
// Close 释放所有 BPF 资源。
// 注意：此处不关闭持久链接，以允许它们保留在内核中。
func (m *Manager) Close() error {
	err := m.objs.Close()
	// We no longer automatically close links here to keep them persistent.
	// Links are now pinned and should be managed via Detach or manually.
	// 我们不再在此处自动关闭链接，以保持其持久性。
	// 链接现在已被固定，应通过 Detach 或手动管理。
	return err
}
