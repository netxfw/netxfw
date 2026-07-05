//go:build linux
// +build linux

package xdp

import (
	"fmt"
	"net"
	"time"

	"github.com/cilium/ebpf"
	sdk "github.com/netxfw/netxfw/pkg/sdk"
)

/**
 * GetDropDetails retrieves detailed drop statistics from the top_drop_map.
 * GetDropDetails 从 top_drop_map 获取详细的丢弃统计信息。
 */
func (m *Manager) GetDropDetails() ([]sdk.DropDetailEntry, error) {
	if m.topDropMap == nil {
		return nil, nil
	}
	return GetTopStatsFromMap(m.topDropMap, "top_drop_map", 0)
}

/**
 * GetPassDetails retrieves detailed pass statistics from the top_pass_map.
 * GetPassDetails 从 top_pass_map 获取详细的通过统计信息。
 */
func (m *Manager) GetPassDetails() ([]sdk.DropDetailEntry, error) {
	if m.topPassMap == nil {
		return nil, nil
	}
	return GetTopStatsFromMap(m.topPassMap, "top_pass_map", 0)
}

/**
 * GetDropDetailsFromMap retrieves detailed drop statistics from a given map.
 * GetDropDetailsFromMap 从给定的 Map 获取详细的丢弃统计信息。
 * Deprecated: Use GetTopStatsFromMap instead.
 */
func GetDropDetailsFromMap(m *ebpf.Map) ([]sdk.DropDetailEntry, error) {
	return GetTopStatsFromMap(m, "top_drop_map", 0)
}

/**
 * GetPassDetailsFromMap retrieves detailed pass statistics from a given map.
 * GetPassDetailsFromMap 从给定的 Map 获取详细的通过统计信息。
 * Deprecated: Use GetTopStatsFromMap instead.
 */
func GetPassDetailsFromMap(m *ebpf.Map) ([]sdk.DropDetailEntry, error) {
	return GetTopStatsFromMap(m, "top_pass_map", 0)
}

/**
 * GetTopStatsFromMap retrieves detailed statistics from a LRU HASH map.
 * GetTopStatsFromMap 从 LRU HASH Map 获取详细统计信息。
 * Uses unified top_stats_key struct.
 * 使用统一的 top_stats_key 结构体。
 */
func GetTopStatsFromMap(m *ebpf.Map, mapName string, maxResults int) ([]sdk.DropDetailEntry, error) {
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
			if maxResults > 0 && len(results) >= maxResults {
				break
			}
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
	statsSlice := acquireStatsGlobalSlice()
	defer releaseStatsGlobalSlice(statsSlice)
	if err := m.statsGlobalMap.Lookup(&key, statsSlice); err == nil {
		for i := range *statsSlice {
			totalPass += (*statsSlice)[i].TotalPass
			totalDrop += (*statsSlice)[i].TotalDrop
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
	statsSlice := acquireStatsGlobalSlice()
	defer releaseStatsGlobalSlice(statsSlice)
	if err := m.statsGlobalMap.Lookup(&key, statsSlice); err != nil {
		return 0, err
	}
	var totalDrop uint64
	for i := range *statsSlice {
		totalDrop += (*statsSlice)[i].TotalDrop
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
	statsSlice := acquireStatsGlobalSlice()
	defer releaseStatsGlobalSlice(statsSlice)
	if err := m.statsGlobalMap.Lookup(&key, statsSlice); err != nil {
		return 0, err
	}
	var totalPass uint64
	for i := range *statsSlice {
		totalPass += (*statsSlice)[i].TotalPass
	}
	return totalPass, nil
}

/**
 * GetLockedIPCount returns the total number of entries in the blacklist maps.
 * GetLockedIPCount 返回黑名单 Map 中的条目总数。
 */
func (m *Manager) GetLockedIPCount() (uint64, error) {
	count, err := GetMapCount(m.staticBlacklist)
	return uint64(count), err // #nosec G115 // count is always valid
}

/**
 * GetWhitelistCount returns the total number of entries in the whitelist map.
 * GetWhitelistCount 返回白名单 Map 中的条目总数。
 */
func (m *Manager) GetWhitelistCount() (uint64, error) {
	count, err := GetMapCount(m.whitelist)
	return uint64(count), err // #nosec G115 // count is always valid
}

/**
 * GetConntrackCount returns the total number of entries in the conntrack map.
 * GetConntrackCount 返回连接跟踪 Map 中的条目总数。
 */
func (m *Manager) GetConntrackCount() (uint64, error) {
	count, err := GetMapCount(m.conntrackMap)
	return uint64(count), err // #nosec G115 // count is always valid
}

/**
 * GetDynLockListCount returns the total number of entries in the dynamic blacklist map.
 * GetDynLockListCount 返回动态黑名单 Map 中的条目总数。
 */
func (m *Manager) GetDynLockListCount() (uint64, error) {
	count, err := GetMapCount(m.dynamicBlacklist)
	return uint64(count), err // #nosec G115 // count is always valid
}

/**
 * GetCriticalBlacklistCount returns the total number of entries in the critical blacklist map.
 * GetCriticalBlacklistCount 返回危机封锁 Map 中的条目总数。
 */
func (m *Manager) GetCriticalBlacklistCount() (uint64, error) {
	count, err := GetMapCount(m.criticalBlacklist)
	return uint64(count), err // #nosec G115 // count is always valid
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
			LastSeen: time.Unix(0, int64(val.LastSeen)), // #nosec G115 // timestamp from BPF is always valid
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
func (m *Manager) GetGlobalStats() (*sdk.GlobalStats, error) {
	result := &sdk.GlobalStats{}

	if m.statsGlobalMap == nil {
		return result, nil
	}

	var key uint32
	statsSlice := acquireStatsGlobalSlice()
	defer releaseStatsGlobalSlice(statsSlice)
	if err := m.statsGlobalMap.Lookup(&key, statsSlice); err != nil {
		return result, err
	}

	for i := range *statsSlice {
		result.TotalPackets += (*statsSlice)[i].TotalPackets
		result.TotalPass += (*statsSlice)[i].TotalPass
		result.TotalDrop += (*statsSlice)[i].TotalDrop
		result.DropBlacklist += (*statsSlice)[i].DropBlacklist
		result.DropNoRule += (*statsSlice)[i].DropNoRule
		result.DropInvalid += (*statsSlice)[i].DropInvalid
		result.DropRateLimit += (*statsSlice)[i].DropRateLimit
		result.DropSynFlood += (*statsSlice)[i].DropSynFlood
		result.DropIcmpLimit += (*statsSlice)[i].DropIcmpLimit
		result.DropPortBlocked += (*statsSlice)[i].DropPortBlocked
		result.DropDefaultDeny += (*statsSlice)[i].DropDefaultDeny
		result.PassWhitelist += (*statsSlice)[i].PassWhitelist
		result.PassRule += (*statsSlice)[i].PassRule
		result.PassReturn += (*statsSlice)[i].PassReturn
		result.PassEstablished += (*statsSlice)[i].PassEstablished
	}

	return result, nil
}

// GetCachedGlobalStats returns cached global statistics.
// GetCachedGlobalStats 返回缓存的全局统计信息。
func (m *Manager) GetCachedGlobalStats() (*sdk.GlobalStats, error) {
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
