//go:build linux
// +build linux

package xdp

import (
	"fmt"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/netxfw/netxfw/internal/plugins/types"
)

/**
 * MatchesCapacity checks if the current map capacities match the provided config.
 * MatchesCapacity 检查当前的 Map 容量是否与提供的配置匹配。
 */
func (m *Manager) MatchesCapacity(cfg types.CapacityConfig) bool {
	if cfg.LockList > 0 {
		if m.staticBlacklist == nil || m.staticBlacklist.MaxEntries() != uint32(cfg.LockList) { // #nosec G115 // cfg values are always valid for uint32
			return false
		}
	}
	if cfg.DynLockList > 0 {
		if m.dynamicBlacklist == nil || m.dynamicBlacklist.MaxEntries() != uint32(cfg.DynLockList) { // #nosec G115 // cfg values are always valid for uint32
			return false
		}
	}
	if cfg.Whitelist > 0 {
		if m.whitelist == nil || m.whitelist.MaxEntries() != uint32(cfg.Whitelist) { // #nosec G115 // cfg values are always valid for uint32
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
	// Note: Using new unified map names
	// 注意：使用新的统一 Map 名称
	if cfg.Conntrack > 0 {
		if m, ok := spec.Maps["conntrack_map"]; ok {
			m.MaxEntries = uint32(cfg.Conntrack) // #nosec G115 // cfg values are always valid for uint32
		}
	}
	if cfg.LockList > 0 {
		if m, ok := spec.Maps["static_blacklist"]; ok {
			m.MaxEntries = uint32(cfg.LockList) // #nosec G115 // cfg values are always valid for uint32
		}
	}
	if cfg.DynLockList > 0 {
		if m, ok := spec.Maps["dynamic_blacklist"]; ok {
			m.MaxEntries = uint32(cfg.DynLockList) // #nosec G115 // cfg values are always valid for uint32
		}
	}
	if cfg.Whitelist > 0 {
		if m, ok := spec.Maps["whitelist"]; ok {
			m.MaxEntries = uint32(cfg.Whitelist) // #nosec G115 // cfg values are always valid for uint32
		}
	}

	// Load BPF objects into the kernel / 将 BPF 对象加载到内核
	var objs NetXfwObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("load eBPF objects: %w", err)
	}

	manager := &Manager{
		objs:   objs,
		logger: logger,
	}

	// Initialize map references from bpf2go generated objects
	// 从 bpf2go 生成的对象初始化 Map 引用
	manager.initMapReferences(&objs)

	// Initialize statistics cache / 初始化统计缓存
	manager.statsCache = NewStatsCache(manager)

	// Initialize incremental updater / 初始化增量更新器
	manager.incrementalUpdater = NewIncrementalUpdater(manager)

	// Initialize performance statistics tracker / 初始化性能统计跟踪器
	manager.perfStats = NewPerformanceStats()

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

// initMapReferences initializes map references from BPF objects
// initMapReferences 从 BPF 对象初始化 Map 引用
// Uses bpf2go generated field names (new unified names)
// 使用 bpf2go 生成的字段名称（新的统一名称）
func (m *Manager) initMapReferences(objs *NetXfwObjects) {
	// Core maps - using bpf2go generated names (new unified names)
	// 核心 Map - 使用 bpf2go 生成的名称（新的统一名称）
	m.conntrackMap = objs.ConntrackMap
	m.staticBlacklist = objs.StaticBlacklist
	m.dynamicBlacklist = objs.DynamicBlacklist
	m.criticalBlacklist = objs.CriticalBlacklist
	m.whitelist = objs.Whitelist
	m.ruleMap = objs.RuleMap
	m.topDropMap = objs.TopDropMap
	m.topPassMap = objs.TopPassMap
	m.statsGlobalMap = objs.StatsGlobalMap
	m.ratelimitMap = objs.RatelimitMap
	m.globalConfig = objs.GlobalConfig
	m.jmpTable = objs.JmpTable
	m.xskMap = objs.XskMap
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

	// Prepare map replacements to reuse pinned maps
	// 准备 Map 替换以重用固定的 Map
	opts := &ebpf.CollectionOptions{
		MapReplacements: make(map[string]*ebpf.Map),
	}

	// Map names (using new unified names)
	// Map 名称（使用新的统一名称）
	mapNames := []string{
		"conntrack_map",
		"static_blacklist",
		"dynamic_blacklist",
		"critical_blacklist",
		"whitelist",
		"rule_map",
		"stats_global_map",
		"ratelimit_map",
		"top_drop_map",
		"top_pass_map",
		"global_config",
		"jmp_table",
		"xsk_map",
	}

	// Try to load each pinned map
	// 尝试加载每个固定的 Map
	for _, name := range mapNames {
		mp, err := ebpf.LoadPinnedMap(filepath.Join(path, name), nil)
		if err == nil {
			opts.MapReplacements[name] = mp
		} else {
			// It's okay if some maps are missing (e.g. first run), we'll create new ones
			// 如果缺少某些 Map（例如首次运行），也没关系，我们将创建新的
			logger.Infof("[PIN] Could not load pinned map %s (will create new): %v", name, err)
		}
	}

	// Load objects with map replacements
	// 加载带有 Map 替换的对象
	var objs NetXfwObjects

	// Temporarily adjust MaxEntries in spec to match pinned maps if needed
	// 如果需要，临时调整规范中的 MaxEntries 以匹配固定的 Map
	spec, err := LoadNetXfw()
	if err == nil {
		for name, pinnedMap := range opts.MapReplacements {
			if specMap, ok := spec.Maps[name]; ok {
				if specMap.MaxEntries != pinnedMap.MaxEntries() {
					// Update spec to match pinned map capacity to avoid incompatibility error
					// 更新规范以匹配固定 Map 的容量，避免不兼容错误
					specMap.MaxEntries = pinnedMap.MaxEntries()
				}
			}
		}
		// Load using the modified spec
		if err := spec.LoadAndAssign(&objs, opts); err != nil {
			for _, m := range opts.MapReplacements {
				m.Close()
			}
			return nil, fmt.Errorf("load eBPF objects: %w", err)
		}
	} else {
		// Fallback to standard load if spec loading fails (unlikely)
		// 如果规范加载失败（不太可能），则回退到标准加载
		if err := LoadNetXfwObjects(&objs, opts); err != nil {
			for _, m := range opts.MapReplacements {
				m.Close()
			}
			return nil, fmt.Errorf("load eBPF objects: %w", err)
		}
	}

	m := &Manager{
		objs:   objs,
		logger: logger,
	}
	m.initMapReferences(&objs)

	// Initialize statistics cache / 初始化统计缓存
	m.statsCache = NewStatsCache(m)

	// Initialize incremental updater / 初始化增量更新器
	m.incrementalUpdater = NewIncrementalUpdater(m)

	// Initialize performance statistics tracker / 初始化性能统计跟踪器
	m.perfStats = NewPerformanceStats()

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

// GetHealthChecker returns a health checker for this manager.
// GetHealthChecker 返回此管理器的健康检查器。
func (m *Manager) GetHealthChecker() *HealthChecker {
	return NewHealthChecker(m)
}
