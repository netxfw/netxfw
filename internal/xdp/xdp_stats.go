//go:build linux
// +build linux

package xdp

import (
	"fmt"
	"net"
	"time"

	"github.com/cilium/ebpf"
	"github.com/livp123/netxfw/pkg/sdk"
)

/**
 * GetDropDetails retrieves detailed drop statistics from the top_drop_map.
 * GetDropDetails 从 top_drop_map 获取详细的丢弃统计信息。
 */
func (m *Manager) GetDropDetails() ([]sdk.DropDetailEntry, error) {
	if m.topDropMap == nil {
		return nil, nil
	}
	return GetTopStatsFromMap(m.topDropMap, "top_drop_map")
}

/**
 * GetPassDetails retrieves detailed pass statistics from the top_pass_map.
 * GetPassDetails 从 top_pass_map 获取详细的通过统计信息。
 */
func (m *Manager) GetPassDetails() ([]sdk.DropDetailEntry, error) {
	if m.topPassMap == nil {
		return nil, nil
	}
	return GetTopStatsFromMap(m.topPassMap, "top_pass_map")
}

/**
 * GetDropDetailsFromMap retrieves detailed drop statistics from a given map.
 * GetDropDetailsFromMap 从给定的 Map 获取详细的丢弃统计信息。
 * Deprecated: Use GetTopStatsFromMap instead.
 */
func GetDropDetailsFromMap(m *ebpf.Map) ([]sdk.DropDetailEntry, error) {
	return GetTopStatsFromMap(m, "top_drop_map")
}

/**
 * GetPassDetailsFromMap retrieves detailed pass statistics from a given map.
 * GetPassDetailsFromMap 从给定的 Map 获取详细的通过统计信息。
 * Deprecated: Use GetTopStatsFromMap instead.
 */
func GetPassDetailsFromMap(m *ebpf.Map) ([]sdk.DropDetailEntry, error) {
	return GetTopStatsFromMap(m, "top_pass_map")
}

/**
 * GetTopStatsFromMap retrieves detailed statistics from a LRU HASH map.
 * GetTopStatsFromMap 从 LRU HASH Map 获取详细统计信息。
 * Uses unified top_stats_key struct.
 * 使用统一的 top_stats_key 结构体。
 */
func GetTopStatsFromMap(m *ebpf.Map, mapName string) ([]sdk.DropDetailEntry, error) {
	var results []sdk.DropDetailEntry
	var key NetXfwTopStatsKey
	var value uint64

	iter := m.Iterate()
	for iter.Next(&key, &value) {
		if value > 0 {
			var srcIP string
			isMappedIPv4 := key.SrcIp.In6U.U6Addr8[10] == 0xff && key.SrcIp.In6U.U6Addr8[11] == 0xff
			if isMappedIPv4 {
				srcIP = net.IP(key.SrcIp.In6U.U6Addr8[12:]).String()
			} else {
				srcIP = net.IP(key.SrcIp.In6U.U6Addr8[:]).String()
			}

			results = append(results, sdk.DropDetailEntry{
				Reason:   key.Reason,
				Protocol: uint8(key.Protocol),
				SrcIP:    srcIP,
				DstPort:  key.DstPort,
				Count:    value,
			})
		}
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterate %s: %w", mapName, err)
	}

	return results, nil
}

/**
 * GetStats retrieves the total pass and drop counts from stats_global_map.
 * GetStats 从 stats_global_map 获取总的通过和丢弃计数。
 * Uses unified stats_global struct.
 * 使用统一的 stats_global 结构体。
 * Note: stats_global_map is PERCPU_ARRAY, requires slice for lookup.
 * 注意：stats_global_map 是 PERCPU_ARRAY，需要使用切片进行查找。
 */
func (m *Manager) GetStats() (uint64, uint64) {
	var totalPass, totalDrop uint64

	if m.statsGlobalMap == nil {
		return 0, 0
	}

	var key uint32
	// PERCPU map requires slice of values
	// PERCPU Map 需要值切片
	numCPU, err := ebpf.PossibleCPU()
	if err != nil {
		return 0, 0
	}
	statsSlice := make([]NetXfwStatsGlobal, numCPU)
	if err := m.statsGlobalMap.Lookup(&key, &statsSlice); err == nil {
		// Sum values from all CPUs
		// 汇总所有 CPU 的值
		for _, stats := range statsSlice {
			totalPass += stats.TotalPass
			totalDrop += stats.TotalDrop
		}
	}

	return totalPass, totalDrop
}

/**
 * GetMapCount returns the total number of entries in a map.
 * GetMapCount 返回 Map 中的条目总数。
 */
func GetMapCount(m *ebpf.Map) (int, error) {
	if m == nil {
		return 0, nil
	}
	count := 0
	iter := m.Iterate()
	var key []byte
	var val []byte
	for iter.Next(&key, &val) {
		count++
	}
	return count, iter.Err()
}

/**
 * GetDropCount retrieves global drop statistics from stats_global_map.
 * GetDropCount 从 stats_global_map 获取全局丢弃统计信息。
 * Note: stats_global_map is PERCPU_ARRAY, requires slice for lookup.
 * 注意：stats_global_map 是 PERCPU_ARRAY，需要使用切片进行查找。
 */
func (m *Manager) GetDropCount() (uint64, error) {
	if m.statsGlobalMap == nil {
		return 0, nil
	}
	var key uint32
	// PERCPU map requires slice of values
	// PERCPU Map 需要值切片
	numCPU, err := ebpf.PossibleCPU()
	if err != nil {
		return 0, err
	}
	statsSlice := make([]NetXfwStatsGlobal, numCPU)
	if err := m.statsGlobalMap.Lookup(&key, &statsSlice); err != nil {
		return 0, err
	}
	// Sum values from all CPUs
	// 汇总所有 CPU 的值
	var totalDrop uint64
	for _, stats := range statsSlice {
		totalDrop += stats.TotalDrop
	}
	return totalDrop, nil
}

/**
 * GetPassCount retrieves global pass statistics from stats_global_map.
 * GetPassCount 从 stats_global_map 获取全局通过统计信息。
 * Note: stats_global_map is PERCPU_ARRAY, requires slice for lookup.
 * 注意：stats_global_map 是 PERCPU_ARRAY，需要使用切片进行查找。
 */
func (m *Manager) GetPassCount() (uint64, error) {
	if m.statsGlobalMap == nil {
		return 0, nil
	}
	var key uint32
	// PERCPU map requires slice of values
	// PERCPU Map 需要值切片
	numCPU, err := ebpf.PossibleCPU()
	if err != nil {
		return 0, err
	}
	statsSlice := make([]NetXfwStatsGlobal, numCPU)
	if err := m.statsGlobalMap.Lookup(&key, &statsSlice); err != nil {
		return 0, err
	}
	// Sum values from all CPUs
	// 汇总所有 CPU 的值
	var totalPass uint64
	for _, stats := range statsSlice {
		totalPass += stats.TotalPass
	}
	return totalPass, nil
}

/**
 * GetLockedIPCount returns the total number of entries in the blacklist maps.
 * GetLockedIPCount 返回黑名单 Map 中的条目总数。
 */
func (m *Manager) GetLockedIPCount() (uint64, error) {
	count, err := GetMapCount(m.staticBlacklist)
	return uint64(count), err
}

/**
 * GetWhitelistCount returns the total number of entries in the whitelist map.
 * GetWhitelistCount 返回白名单 Map 中的条目总数。
 */
func (m *Manager) GetWhitelistCount() (uint64, error) {
	count, err := GetMapCount(m.whitelist)
	return uint64(count), err
}

/**
 * GetConntrackCount returns the total number of entries in the conntrack map.
 * GetConntrackCount 返回连接跟踪 Map 中的条目总数。
 */
func (m *Manager) GetConntrackCount() (uint64, error) {
	count, err := GetMapCount(m.conntrackMap)
	return uint64(count), err
}

/**
 * GetDynLockListCount returns the total number of entries in the dynamic blacklist map.
 * GetDynLockListCount 返回动态黑名单 Map 中的条目总数。
 */
func (m *Manager) GetDynLockListCount() (uint64, error) {
	count, err := GetMapCount(m.dynamicBlacklist)
	return uint64(count), err
}

/**
 * GetCriticalBlacklistCount returns the total number of entries in the critical blacklist map.
 * GetCriticalBlacklistCount 返回危机封锁 Map 中的条目总数。
 */
func (m *Manager) GetCriticalBlacklistCount() (uint64, error) {
	count, err := GetMapCount(m.criticalBlacklist)
	return uint64(count), err
}

/**
 * ListConntrackEntries iterates over the conntrack map and returns entries.
 * ListConntrackEntries 遍历连接跟踪 Map 并返回条目。
 */
func (m *Manager) ListConntrackEntries() ([]ConntrackEntry, error) {
	if m.conntrackMap == nil {
		return nil, nil
	}

	var entries []ConntrackEntry
	iter := m.conntrackMap.Iterate()

	var key NetXfwCtKey
	var val NetXfwCtValue

	for iter.Next(&key, &val) {
		var srcIP, dstIP string

		// Parse source IP / 解析源 IP
		isSrcMappedIPv4 := key.SrcIp.In6U.U6Addr8[10] == 0xff && key.SrcIp.In6U.U6Addr8[11] == 0xff
		if isSrcMappedIPv4 {
			srcIP = net.IP(key.SrcIp.In6U.U6Addr8[12:]).String()
		} else {
			srcIP = net.IP(key.SrcIp.In6U.U6Addr8[:]).String()
		}

		// Parse destination IP / 解析目标 IP
		isDstMappedIPv4 := key.DstIp.In6U.U6Addr8[10] == 0xff && key.DstIp.In6U.U6Addr8[11] == 0xff
		if isDstMappedIPv4 {
			dstIP = net.IP(key.DstIp.In6U.U6Addr8[12:]).String()
		} else {
			dstIP = net.IP(key.DstIp.In6U.U6Addr8[:]).String()
		}

		entry := ConntrackEntry{
			SrcIP:    srcIP,
			DstIP:    dstIP,
			SrcPort:  key.SrcPort,
			DstPort:  key.DstPort,
			Protocol: key.Protocol,
			LastSeen: time.Unix(0, int64(val.LastSeen)),
		}
		entries = append(entries, entry)
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterate conntrack: %w", err)
	}

	return entries, nil
}

/**
 * GetGlobalStats retrieves all global statistics from stats_global_map.
 * GetGlobalStats 从 stats_global_map 获取所有全局统计信息。
 * Uses unified stats_global struct.
 * 使用统一的 stats_global 结构体。
 * Note: stats_global_map is PERCPU_ARRAY, requires slice for lookup.
 * 注意：stats_global_map 是 PERCPU_ARRAY，需要使用切片进行查找。
 */
func (m *Manager) GetGlobalStats() (*GlobalStats, error) {
	result := &GlobalStats{}

	if m.statsGlobalMap == nil {
		return result, nil
	}

	var key uint32
	// PERCPU map requires slice of values
	// PERCPU Map 需要值切片
	numCPU, err := ebpf.PossibleCPU()
	if err != nil {
		return result, err
	}
	statsSlice := make([]NetXfwStatsGlobal, numCPU)
	if err := m.statsGlobalMap.Lookup(&key, &statsSlice); err != nil {
		return result, err
	}

	// Sum values from all CPUs
	// 汇总所有 CPU 的值
	for _, stats := range statsSlice {
		result.TotalPackets += stats.TotalPackets
		result.TotalPass += stats.TotalPass
		result.TotalDrop += stats.TotalDrop
		result.DropBlacklist += stats.DropBlacklist
		result.DropNoRule += stats.DropNoRule
		result.DropInvalid += stats.DropInvalid
		result.DropRateLimit += stats.DropRateLimit
		result.DropSynFlood += stats.DropSynFlood
		result.DropIcmpLimit += stats.DropIcmpLimit
		result.DropPortBlocked += stats.DropPortBlocked
		result.PassWhitelist += stats.PassWhitelist
		result.PassRule += stats.PassRule
		result.PassReturn += stats.PassReturn
		result.PassEstablished += stats.PassEstablished
	}

	return result, nil
}

// GlobalStats represents aggregated global statistics.
// GlobalStats 表示聚合的全局统计信息。
type GlobalStats struct {
	TotalPackets    uint64 // Total packets processed / 处理的总数据包
	TotalPass       uint64 // Total passed packets / 通过的总数据包
	TotalDrop       uint64 // Total dropped packets / 丢弃的总数据包
	DropBlacklist   uint64 // Dropped by blacklist / 被黑名单丢弃
	DropNoRule      uint64 // Dropped: no matching rule / 丢弃：无匹配规则
	DropInvalid     uint64 // Dropped: invalid packet / 丢弃：无效数据包
	DropRateLimit   uint64 // Dropped: rate limit / 丢弃：速率限制
	DropSynFlood    uint64 // Dropped: SYN flood / 丢弃：SYN 洪水
	DropIcmpLimit   uint64 // Dropped: ICMP limit / 丢弃：ICMP 限制
	DropPortBlocked uint64 // Dropped: port blocked / 丢弃：端口被阻止
	PassWhitelist   uint64 // Passed by whitelist / 被白名单通过
	PassRule        uint64 // Passed by rule / 被规则通过
	PassReturn      uint64 // Passed: return traffic / 通过：回程流量
	PassEstablished uint64 // Passed: established connection / 通过：已建立连接
}

// GetCachedGlobalStats returns cached global statistics.
// GetCachedGlobalStats 返回缓存的全局统计信息。
func (m *Manager) GetCachedGlobalStats() (*GlobalStats, error) {
	if m.statsCache == nil {
		return m.GetGlobalStats()
	}
	return m.statsCache.GetGlobalStats()
}

// GetCachedDropDetails returns cached drop details.
// GetCachedDropDetails 返回缓存的丢弃详情。
func (m *Manager) GetCachedDropDetails() ([]sdk.DropDetailEntry, error) {
	if m.statsCache == nil {
		return m.GetDropDetails()
	}
	return m.statsCache.GetDropDetails()
}

// GetCachedPassDetails returns cached pass details.
// GetCachedPassDetails 返回缓存的通过详情。
func (m *Manager) GetCachedPassDetails() ([]sdk.DropDetailEntry, error) {
	if m.statsCache == nil {
		return m.GetPassDetails()
	}
	return m.statsCache.GetPassDetails()
}

// GetCachedMapCounts returns cached map entry counts.
// GetCachedMapCounts 返回缓存的 Map 条目计数。
func (m *Manager) GetCachedMapCounts() (MapCounts, error) {
	if m.statsCache == nil {
		blacklist, _ := m.GetLockedIPCount()
		whitelist, _ := m.GetWhitelistCount()
		conntrack, _ := m.GetConntrackCount()
		dynamicBlacklist, _ := m.GetDynLockListCount()
		return MapCounts{
			Blacklist:        blacklist,
			Whitelist:        whitelist,
			Conntrack:        conntrack,
			DynamicBlacklist: dynamicBlacklist,
			UpdatedAt:        time.Now(),
		}, nil
	}
	return m.statsCache.GetMapCounts()
}

// InvalidateStatsCache clears the statistics cache.
// InvalidateStatsCache 清除统计缓存。
func (m *Manager) InvalidateStatsCache() {
	if m.statsCache != nil {
		m.statsCache.InvalidateAll()
	}
}
