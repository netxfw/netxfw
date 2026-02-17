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
 */
func GetTopStatsFromMap(m *ebpf.Map, mapName string) ([]sdk.DropDetailEntry, error) {
	var results []sdk.DropDetailEntry
	var key NetXfwDropDetailKey
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
 * GetStats retrieves the total pass and drop counts from drop_stats and pass_stats maps.
 * GetStats 从 drop_stats 和 pass_stats Map 获取总的通过和丢弃计数。
 * Note: Uses existing bpf2go generated maps until stats_global_map is generated.
 * 注意：使用现有的 bpf2go 生成的 Map，直到 stats_global_map 被生成。
 */
func (m *Manager) GetStats() (uint64, uint64) {
	var totalPass, totalDrop uint64

	// Use existing drop_stats and pass_stats maps (bpf2go generated)
	// 使用现有的 drop_stats 和 pass_stats Map（bpf2go 生成）
	if m.objs.DropStats != nil {
		var key uint32 = 0
		var stats []uint64
		if err := m.objs.DropStats.Lookup(&key, &stats); err == nil {
			for _, s := range stats {
				totalDrop += s
			}
		}
	}

	if m.objs.PassStats != nil {
		var key uint32 = 0
		var stats []uint64
		if err := m.objs.PassStats.Lookup(&key, &stats); err == nil {
			for _, s := range stats {
				totalPass += s
			}
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
 * GetDropCount retrieves global drop statistics from drop_stats map.
 * GetDropCount 从 drop_stats Map 获取全局丢弃统计信息。
 */
func (m *Manager) GetDropCount() (uint64, error) {
	if m.objs.DropStats == nil {
		return 0, nil
	}
	var key uint32 = 0
	var stats []uint64
	if err := m.objs.DropStats.Lookup(&key, &stats); err != nil {
		return 0, err
	}
	var total uint64
	for _, s := range stats {
		total += s
	}
	return total, nil
}

/**
 * GetPassCount retrieves global pass statistics from pass_stats map.
 * GetPassCount 从 pass_stats Map 获取全局通过统计信息。
 */
func (m *Manager) GetPassCount() (uint64, error) {
	if m.objs.PassStats == nil {
		return 0, nil
	}
	var key uint32 = 0
	var stats []uint64
	if err := m.objs.PassStats.Lookup(&key, &stats); err != nil {
		return 0, err
	}
	var total uint64
	for _, s := range stats {
		total += s
	}
	return total, nil
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
 * GetGlobalStats retrieves all global statistics from drop_stats and pass_stats maps.
 * GetGlobalStats 从 drop_stats 和 pass_stats Map 获取所有全局统计信息。
 * Note: Uses existing bpf2go generated maps until stats_global_map is generated.
 * 注意：使用现有的 bpf2go 生成的 Map，直到 stats_global_map 被生成。
 */
func (m *Manager) GetGlobalStats() (*GlobalStats, error) {
	result := &GlobalStats{}

	// Use existing drop_stats and pass_stats maps (bpf2go generated)
	// 使用现有的 drop_stats 和 pass_stats Map（bpf2go 生成）
	if m.objs.DropStats != nil {
		var key uint32 = 0
		var stats []uint64
		if err := m.objs.DropStats.Lookup(&key, &stats); err == nil {
			for _, s := range stats {
				result.TotalDrop += s
			}
		}
	}

	if m.objs.PassStats != nil {
		var key uint32 = 0
		var stats []uint64
		if err := m.objs.PassStats.Lookup(&key, &stats); err == nil {
			for _, s := range stats {
				result.TotalPass += s
			}
		}
	}

	result.TotalPackets = result.TotalPass + result.TotalDrop

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

// Helper function for case-insensitive contains
// 用于不区分大小写包含的辅助函数
func containsIgnoreCase(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && containsSubstring(s, substr)))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			sc := s[i+j]
			subc := substr[j]
			if sc >= 'A' && sc <= 'Z' {
				sc += 32
			}
			if subc >= 'A' && subc <= 'Z' {
				subc += 32
			}
			if sc != subc {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
