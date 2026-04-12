//go:build linux
// +build linux

package xdp

import (
	"fmt"
	"sort"

	"github.com/cilium/ebpf"
	"github.com/netxfw/netxfw/internal/plugins/types"
)

// Module definition
type ModuleDef struct {
	ID      uint32
	Program *ebpf.Program
}

// SyncModules updates the execution chain based on configuration
// SyncModules 根据配置更新执行链
func (m *Manager) SyncModules(configs []types.ModuleConfig) error {
	if m.chainMap == nil || m.jmpTable == nil {
		return fmt.Errorf("maps not initialized")
	}

	// Default modules if config is empty (fallback to hardcoded default order)
	// 如果配置为空，使用默认模块（回退到硬编码的默认顺序）
	if len(configs) == 0 {
		m.logger.Warnf("No modules configured, skipping chain update")
		return nil
	}

	// 1. Sort modules by priority
	// 1. 按优先级排序模块
	sorted := make([]types.ModuleConfig, len(configs))
	copy(sorted, configs)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Priority < sorted[j].Priority
	})

	// 2. Build the chain
	// 2. 构建链
	// We need to map Name -> Program & ID
	modMap := map[string]ModuleDef{
		"sanity":             {ModuleIDSanity, m.objs.XdpSanity},
		"critical_blacklist": {ModuleIDCritical, m.objs.XdpCritical},
		"whitelist":          {ModuleIDWhitelist, m.objs.XdpWhitelist},
		"blacklist":          {ModuleIDBlacklist, m.objs.XdpBlacklist},
		"dynamic_blacklist":  {ModuleIDDynamicBlacklist, m.objs.XdpDynamicBlacklist},
		"ratelimit":          {ModuleIDRateLimit, m.objs.XdpRatelimit},
		"conntrack":          {ModuleIDConntrack, m.objs.XdpConntrack},
		"ip_port_rules":      {ModuleIDRules, m.objs.XdpRules},
		"icmp":               {ModuleIDICMP, m.objs.XdpIcmp},
		"return_traffic":     {ModuleIDReturn, m.objs.XdpReturn},
	}

	// Current pointer in the chain
	var previousModID uint32 = ModuleIDEntry

	// We use a fixed offset for module programs in jmp_table to avoid collision with plugins (2-15)
	// 使用固定偏移量以避免与插件冲突 (2-15)
	// Starting at 20 gives plenty of room for plugins
	// 从 20 开始，为插件留出足够空间
	startIdx := uint32(20)

	m.logger.Infof("Syncing %d modules...", len(sorted))

	for i, cfg := range sorted {
		if !cfg.Enabled {
			continue
		}

		def, ok := modMap[cfg.Name]
		if !ok {
			m.logger.Warnf("Unknown module: %s", cfg.Name)
			continue
		}

		if def.Program == nil {
			// Might be nil if not loaded/found in BPF object
			m.logger.Warnf("Module program not loaded: %s", cfg.Name)
			continue
		}

		// Assign an index in jmp_table
		progIdx := startIdx + uint32(i)

		// 1. Update jmp_table with the program
		// 1. 更新 jmp_table
		if err := m.jmpTable.Update(progIdx, def.Program, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("failed to update jmp_table for %s: %w", cfg.Name, err)
		}

		// 2. Link previous module to this one
		// 2. 将上一个模块链接到此模块
		// chain_map[previousModID] = progIdx
		if err := m.chainMap.Update(previousModID, progIdx, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("failed to update chain_map for %s: %w", cfg.Name, err)
		}

		m.logger.Infof("Module Linked: %s (ID: %d) -> JmpIdx: %d", cfg.Name, def.ID, progIdx)

		previousModID = def.ID
	}

	// Terminate the chain
	// 终止链
	// Delete the entry for the last module to ensure it doesn't call anything
	if err := m.chainMap.Delete(previousModID); err != nil {
		if !isKeyNotExist(err) {
			m.logger.Warnf("Failed to terminate chain at ID %d: %v", previousModID, err)
		}
	}

	return nil
}

func isKeyNotExist(err error) bool {
	// Check if error is KeyNotExist
	return err != nil && err.Error() == "key does not exist"
}
