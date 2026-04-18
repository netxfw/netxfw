//go:build linux
// +build linux

package xdp

import "github.com/cilium/ebpf"

// migrateMap copies all entries from source map to destination map.
// migrateMap 将源 Map 的所有条目复制到目标 Map。
func migrateMap[K any, V any](src, dst *ebpf.Map) {
	if src == nil || dst == nil {
		return
	}
	var key K
	var val V
	iter := src.Iterate()
	for iter.Next(&key, &val) {
		dst.Put(&key, &val)
	}
}

// MigrateState copies all entries from an old manager's maps to this manager's maps.
// This is used for hot-reloading to preserve conntrack state and rules.
// MigrateState 将旧管理器的 Map 条目复制到此管理器的 Map 中，用于热加载以保留状态。
func (m *Manager) MigrateState(old *Manager) error {
	// Migrate Conntrack / 迁移连接跟踪
	migrateMap[NetXfwCtKey, NetXfwCtValue](old.conntrackMap, m.conntrackMap)

	// Migrate Static Blacklist / 迁移静态黑名单
	migrateMap[NetXfwLpmKey, NetXfwRuleValue](old.staticBlacklist, m.staticBlacklist)

	// Migrate Dynamic Blacklist / 迁移动态黑名单
	migrateMap[NetXfwIn6Addr, NetXfwRuleValue](old.dynamicBlacklist, m.dynamicBlacklist)

	// Migrate Critical Blacklist / 迁移危机封锁
	migrateMap[NetXfwIn6Addr, NetXfwRuleValue](old.criticalBlacklist, m.criticalBlacklist)

	// Migrate Whitelist / 迁移白名单
	migrateMap[NetXfwLpmKey, NetXfwRuleValue](old.whitelist, m.whitelist)

	// Migrate Rule Map (IP+Port Rules) / 迁移规则 Map
	migrateMap[NetXfwLpmIpPortKey, NetXfwRuleValue](old.ruleMap, m.ruleMap)

	// Migrate Rate Limit Map / 迁移速率限制 Map
	migrateMap[NetXfwIn6Addr, NetXfwRatelimitValue](old.ratelimitMap, m.ratelimitMap)

	// Migrate Global Config / 迁移全局配置
	migrateMap[uint32, uint64](old.globalConfig, m.globalConfig)

	// Migrate Top Drop Map / 迁移 Top 丢弃统计 Map
	migrateMap[NetXfwTopStatsKey, uint64](old.topDropMap, m.topDropMap)

	// Migrate Top Pass Map / 迁移 Top 通过统计 Map
	migrateMap[NetXfwTopStatsKey, uint64](old.topPassMap, m.topPassMap)

	// Migrate Stats Global Map / 迁移全局统计 Map
	migrateMap[uint32, NetXfwStatsGlobal](old.statsGlobalMap, m.statsGlobalMap)

	return nil
}
