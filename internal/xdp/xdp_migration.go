//go:build linux
// +build linux

package xdp

import (
	"github.com/cilium/ebpf"
)

/**
 * MigrateState copies all entries from an old manager's maps to this manager's maps.
 * This is used for hot-reloading to preserve conntrack state and rules.
 * MigrateState 将旧管理器的 Map 条目复制到此管理器的 Map 中，用于热加载以保留状态。
 */
func (m *Manager) MigrateState(old *Manager) error {
	// Migrate Conntrack / 迁移连接跟踪 (Conntrack)
	if old.conntrackMap != nil && m.conntrackMap != nil {
		var key NetXfwCtKey
		var val NetXfwCtValue
		iter := old.conntrackMap.Iterate()
		for iter.Next(&key, &val) {
			m.conntrackMap.Put(&key, &val)
		}
	}

	// Migrate Lock List / 迁移锁定列表 (Lock List)
	if old.lockList != nil && m.lockList != nil {
		var key NetXfwLpmKey
		var val NetXfwRuleValue
		iter := old.lockList.Iterate()
		for iter.Next(&key, &val) {
			m.lockList.Put(&key, &val)
		}
	}

	// Migrate Dynamic Lock List / 迁移动态锁定列表 (Dynamic Lock List)
	if old.dynLockList != nil && m.dynLockList != nil {
		var key NetXfwIn6Addr
		var val NetXfwRuleValue
		iter := old.dynLockList.Iterate()
		for iter.Next(&key, &val) {
			m.dynLockList.Put(&key, &val)
		}
	}

	// Migrate Whitelist / 迁移白名单 (Whitelist)
	if old.whitelist != nil && m.whitelist != nil {
		var key NetXfwLpmKey
		var val NetXfwRuleValue
		iter := old.whitelist.Iterate()
		for iter.Next(&key, &val) {
			m.whitelist.Put(&key, &val)
		}
	}

	// Migrate IP+Port Rules / 迁移 IP+端口规则 (IP+Port Rules)
	if old.ipPortRules != nil && m.ipPortRules != nil {
		var key NetXfwLpmIpPortKey
		var val NetXfwRuleValue
		iter := old.ipPortRules.Iterate()
		for iter.Next(&key, &val) {
			m.ipPortRules.Put(&key, &val)
		}
	}

	// Migrate Allowed Ports (PERCPU HASH) / 迁移允许端口 (Allowed Ports)
	if old.allowedPorts != nil && m.allowedPorts != nil {
		var key uint16
		numCPU, _ := ebpf.PossibleCPU()
		val := make([]NetXfwRuleValue, numCPU)
		iter := old.allowedPorts.Iterate()
		for iter.Next(&key, &val) {
			m.allowedPorts.Put(&key, &val)
		}
	}

	// Migrate Rate Limit Config (LPM TRIE) / 迁移速率限制配置 (Rate Limit Config)
	if old.ratelimitConfig != nil && m.ratelimitConfig != nil {
		var key NetXfwLpmKey
		var val NetXfwRatelimitConf
		iter := old.ratelimitConfig.Iterate()
		for iter.Next(&key, &val) {
			m.ratelimitConfig.Put(&key, &val)
		}
	}

	// Migrate Rate Limit State (LRU HASH) / 迁移速率限制状态 (Rate Limit State)
	if old.ratelimitState != nil && m.ratelimitState != nil {
		var key NetXfwIn6Addr
		var val NetXfwRatelimitStats
		iter := old.ratelimitState.Iterate()
		for iter.Next(&key, &val) {
			m.ratelimitState.Put(&key, &val)
		}
	}

	// Migrate Global Config (ARRAY) / 迁移全局配置
	if old.globalConfig != nil && m.globalConfig != nil {
		var key uint32
		var val uint64
		iter := old.globalConfig.Iterate()
		for iter.Next(&key, &val) {
			m.globalConfig.Put(&key, &val)
		}
	}

	// Migrate ICMP Limit Map (LRU HASH) / 迁移 ICMP 限制 Map
	if old.icmpLimitMap != nil && m.icmpLimitMap != nil {
		var key NetXfwIn6Addr
		var val NetXfwIcmpStats
		iter := old.icmpLimitMap.Iterate()
		for iter.Next(&key, &val) {
			m.icmpLimitMap.Put(&key, &val)
		}
	}

	// Migrate Drop Stats (PERCPU ARRAY) / 迁移拦截统计
	if old.dropStats != nil && m.dropStats != nil {
		var key uint32
		numCPU, _ := ebpf.PossibleCPU()
		val := make([]uint64, numCPU)
		iter := old.dropStats.Iterate()
		for iter.Next(&key, &val) {
			m.dropStats.Put(&key, &val)
		}
	}

	// Migrate Pass Stats (PERCPU ARRAY) / 迁移放行统计
	if old.passStats != nil && m.passStats != nil {
		var key uint32
		numCPU, _ := ebpf.PossibleCPU()
		val := make([]uint64, numCPU)
		iter := old.passStats.Iterate()
		for iter.Next(&key, &val) {
			m.passStats.Put(&key, &val)
		}
	}

	// Migrate Drop Reason Stats (PERCPU HASH) / 迁移详细拦截统计
	if old.dropReasonStats != nil && m.dropReasonStats != nil {
		var key NetXfwDropDetailKey
		numCPU, _ := ebpf.PossibleCPU()
		val := make([]uint64, numCPU)
		iter := old.dropReasonStats.Iterate()
		for iter.Next(&key, &val) {
			m.dropReasonStats.Put(&key, &val)
		}
	}

	// Migrate Pass Reason Stats (PERCPU HASH) / 迁移详细放行统计
	if old.passReasonStats != nil && m.passReasonStats != nil {
		var key NetXfwDropDetailKey
		numCPU, _ := ebpf.PossibleCPU()
		val := make([]uint64, numCPU)
		iter := old.passReasonStats.Iterate()
		for iter.Next(&key, &val) {
			m.passReasonStats.Put(&key, &val)
		}
	}

	return nil
}
