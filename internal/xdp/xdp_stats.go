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
 * GetDropDetails retrieves detailed drop statistics from the PERCPU HASH map.
 * GetDropDetails 从 PERCPU HASH Map 中获取详细的拦截统计信息.
 */
func (m *Manager) GetDropDetails() ([]sdk.DropDetailEntry, error) {
	if m.dropReasonStats == nil {
		return nil, nil
	}
	return GetDetailsFromMap(m.dropReasonStats, "drop reason stats")
}

/**
 * GetPassDetails retrieves detailed pass statistics (whitelist/return traffic).
 * GetPassDetails 获取详细的放行统计信息（白名单/回程流量）.
 */
func (m *Manager) GetPassDetails() ([]sdk.DropDetailEntry, error) {
	if m.passReasonStats == nil {
		return nil, nil
	}
	return GetDetailsFromMap(m.passReasonStats, "pass reason stats")
}

/**
 * GetDropDetailsFromMap retrieves detailed drop statistics from a given map.
 * GetDropDetailsFromMap 从给定的 Map 中获取详细的拦截统计信息.
 * Deprecated: Use GetDetailsFromMap instead.
 */
func GetDropDetailsFromMap(m *ebpf.Map) ([]sdk.DropDetailEntry, error) {
	return GetDetailsFromMap(m, "drop reason stats")
}

/**
 * GetPassDetailsFromMap retrieves detailed pass statistics from a given map.
 * GetPassDetailsFromMap 从给定的 Map 中获取详细的放行统计信息.
 * Deprecated: Use GetDetailsFromMap instead.
 */
func GetPassDetailsFromMap(m *ebpf.Map) ([]sdk.DropDetailEntry, error) {
	return GetDetailsFromMap(m, "pass reason stats")
}

/**
 * GetDetailsFromMap retrieves detailed statistics from a given PERCPU HASH map.
 * GetDetailsFromMap 从给定的 PERCPU HASH Map 中获取详细统计信息.
 */
func GetDetailsFromMap(m *ebpf.Map, mapName string) ([]sdk.DropDetailEntry, error) {
	var results []sdk.DropDetailEntry
	var key NetXfwDropDetailKey
	var values []uint64 // PERCPU value is a slice of uint64 / PERCPU 值是 uint64 切片

	iter := m.Iterate()
	for iter.Next(&key, &values) {
		var totalCount uint64
		for _, v := range values {
			totalCount += v
		}

		if totalCount > 0 {
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
				Count:    totalCount,
			})
		}
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterate %s: %w", mapName, err)
	}

	return results, nil
}

/**
 * GetStats retrieves the total pass and drop counts from BPF maps.
 * GetStats 从 BPF Map 中获取总的放行和拦截计数。
 */
func (m *Manager) GetStats() (uint64, uint64) {
	var totalPass, totalDrop uint64

	// Pass stats (PERCPU_ARRAY, max_entries 1) / 放行统计
	var passVals []uint64
	var key uint32 = 0
	if err := m.passStats.Lookup(&key, &passVals); err == nil {
		for _, v := range passVals {
			totalPass += v
		}
	}

	// Drop stats (PERCPU_ARRAY, max_entries 1) / 拦截统计
	var dropVals []uint64
	if err := m.dropStats.Lookup(&key, &dropVals); err == nil {
		for _, v := range dropVals {
			totalDrop += v
		}
	}

	return totalPass, totalDrop
}

/**
 * GetMapCount returns the total number of entries in a map.
 */
func GetMapCount(m *ebpf.Map) (int, error) {
	if m == nil {
		return 0, nil
	}
	count := 0
	iter := m.Iterate()
	var key []byte
	var val []byte
	// Using generic iteration since we just want to count
	for iter.Next(&key, &val) {
		count++
	}
	return count, iter.Err()
}

/**
 * GetCounterValueFromMap retrieves a global counter value from a PERCPU_ARRAY map.
 */
func GetCounterValueFromMap(m *ebpf.Map) (uint64, error) {
	if m == nil {
		return 0, nil
	}
	var key uint32 = 0
	var values []uint64
	if err := m.Lookup(&key, &values); err != nil {
		return 0, err
	}
	var total uint64
	for _, v := range values {
		total += v
	}
	return total, nil
}

/**
 * GetDropCount retrieves global drop statistics from the PERCPU map.
 * GetDropCount 从 PERCPU Map 中获取全局拦截统计信息。
 */
func (m *Manager) GetDropCount() (uint64, error) {
	return GetCounterValueFromMap(m.dropStats)
}

/**
 * GetPassCount retrieves global pass statistics from the PERCPU map.
 * GetPassCount 从 PERCPU Map 中获取全局放行统计信息。
 */
func (m *Manager) GetPassCount() (uint64, error) {
	return GetCounterValueFromMap(m.passStats)
}

/**
 * GetLockedIPCount returns the total number of entries in the lock list maps.
 * GetLockedIPCount 返回锁定列表 Map 中的条目总数。
 */
func (m *Manager) GetLockedIPCount() (uint64, error) {
	// Count unified locked IPs / 统计统一锁定 IP
	count, err := GetMapCount(m.lockList)
	return uint64(count), err
}

/**
 * GetWhitelistCount returns the total number of entries in the whitelist maps.
 * GetWhitelistCount 返回白名单 Map 中的条目总数。
 */
func (m *Manager) GetWhitelistCount() (uint64, error) {
	count, err := GetMapCount(m.whitelist)
	return uint64(count), err
}

/**
 * GetConntrackCount returns the total number of entries in the conntrack maps.
 * GetConntrackCount 返回连接跟踪 Map 中的条目总数。
 */
func (m *Manager) GetConntrackCount() (uint64, error) {
	count, err := GetMapCount(m.conntrackMap)
	return uint64(count), err
}

/**
 * ListConntrackEntries retrieves all active connections from the conntrack maps.
 * ListConntrackEntries 从连接跟踪 Map 中获取所有活动连接。
 */
func (m *Manager) ListConntrackEntries() ([]ConntrackEntry, error) {
	if m.conntrackMap == nil {
		return nil, nil
	}
	return ListConntrackEntriesFromMap(m.conntrackMap)
}

/**
 * ListConntrackEntriesFromMap retrieves all active connections from a given map.
 * ListConntrackEntriesFromMap 从给定的 Map 中获取所有活动连接。
 */
func ListConntrackEntriesFromMap(m *ebpf.Map) ([]ConntrackEntry, error) {
	var entries []ConntrackEntry

	// List unified entries / 列出统一条目
	var key NetXfwCtKey
	var val NetXfwCtValue
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		var srcIP, dstIP string

		// Check for IPv4-mapped IPv6 / 检查 IPv4 映射的 IPv6
		if key.SrcIp.In6U.U6Addr8[10] == 0xff && key.SrcIp.In6U.U6Addr8[11] == 0xff {
			srcIP = net.IP(key.SrcIp.In6U.U6Addr8[12:]).String()
		} else {
			srcIP = net.IP(key.SrcIp.In6U.U6Addr8[:]).String()
		}

		if key.DstIp.In6U.U6Addr8[10] == 0xff && key.DstIp.In6U.U6Addr8[11] == 0xff {
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
