//go:build linux
// +build linux

package xdp

import (
	"fmt"
	"net"
	"time"
)

/**
 * DropDetailEntry represents a single drop event aggregated by reason/IP/port.
 */
type DropDetailEntry struct {
	Reason   uint32
	Protocol uint32
	SrcIP    string
	DstPort  uint16
	Count    uint64
}

/**
 * GetDropDetails retrieves detailed drop statistics from the PERCPU HASH map.
 */
func (m *Manager) GetDropDetails() ([]DropDetailEntry, error) {
	if m.dropReasonStats == nil {
		return nil, nil
	}

	var results []DropDetailEntry
	var key NetXfwDropDetailKey
	var values []uint64 // PERCPU value is a slice of uint64

	iter := m.dropReasonStats.Iterate()
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

			results = append(results, DropDetailEntry{
				Reason:   key.Reason,
				Protocol: key.Protocol,
				SrcIP:    srcIP,
				DstPort:  key.DstPort,
				Count:    totalCount,
			})
		}
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterate drop reason stats: %w", err)
	}

	return results, nil
}

/**
 * GetPassDetails retrieves detailed pass statistics (whitelist/return traffic).
 */
func (m *Manager) GetPassDetails() ([]DropDetailEntry, error) {
	if m.passReasonStats == nil {
		return nil, nil
	}

	var results []DropDetailEntry
	var key NetXfwDropDetailKey
	var values []uint64

	iter := m.passReasonStats.Iterate()
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

			results = append(results, DropDetailEntry{
				Reason:   key.Reason,
				Protocol: key.Protocol,
				SrcIP:    srcIP,
				DstPort:  key.DstPort,
				Count:    totalCount,
			})
		}
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterate pass reason stats: %w", err)
	}

	return results, nil
}

/**
 * GetStats retrieves the total pass and drop counts from BPF maps.
 */
func (m *Manager) GetStats() (uint64, uint64) {
	var totalPass, totalDrop uint64

	// Pass stats (PERCPU_ARRAY, max_entries 1)
	var passVals []uint64
	var key uint32 = 0
	if err := m.passStats.Lookup(&key, &passVals); err == nil {
		for _, v := range passVals {
			totalPass += v
		}
	}

	// Drop stats (PERCPU_ARRAY, max_entries 1)
	var dropVals []uint64
	if err := m.dropStats.Lookup(&key, &dropVals); err == nil {
		for _, v := range dropVals {
			totalDrop += v
		}
	}

	return totalPass, totalDrop
}

/**
 * GetDropCount retrieves global drop statistics from the PERCPU map.
 * GetDropCount 从 PERCPU Map 中获取全局拦截统计信息。
 */
func (m *Manager) GetDropCount() (uint64, error) {
	if m.dropStats == nil {
		return 0, nil
	}
	var key uint32 = 0
	var values []uint64
	if err := m.dropStats.Lookup(&key, &values); err != nil {
		return 0, err
	}
	var total uint64
	for _, v := range values {
		total += v
	}
	return total, nil
}

/**
 * GetPassCount retrieves global pass statistics from the PERCPU map.
 * GetPassCount 从 PERCPU Map 中获取全局放行统计信息。
 */
func (m *Manager) GetPassCount() (uint64, error) {
	if m.passStats == nil {
		return 0, nil
	}
	var key uint32 = 0
	var values []uint64
	if err := m.passStats.Lookup(&key, &values); err != nil {
		return 0, err
	}
	var total uint64
	for _, v := range values {
		total += v
	}
	return total, nil
}

/**
 * GetLockedIPCount returns the total number of entries in the lock list maps.
 * GetLockedIPCount 返回锁定列表 Map 中的条目总数。
 */
func (m *Manager) GetLockedIPCount() (uint64, error) {
	var count uint64

	// Count unified locked IPs
	if m.lockList != nil {
		iter := m.lockList.Iterate()
		var key NetXfwLpmKey
		var val NetXfwRuleValue
		for iter.Next(&key, &val) {
			count++
		}
	}

	return count, nil
}

/**
 * GetWhitelistCount returns the total number of entries in the whitelist maps.
 */
func (m *Manager) GetWhitelistCount() (uint64, error) {
	var count uint64
	if m.whitelist != nil {
		iter := m.whitelist.Iterate()
		var key NetXfwLpmKey
		var val NetXfwRuleValue
		for iter.Next(&key, &val) {
			count++
		}
	}
	return count, nil
}

/**
 * GetConntrackCount returns the total number of entries in the conntrack maps.
 */
func (m *Manager) GetConntrackCount() (uint64, error) {
	var count uint64
	if m.conntrackMap != nil {
		iter := m.conntrackMap.Iterate()
		var key NetXfwCtKey
		var val NetXfwCtValue
		for iter.Next(&key, &val) {
			count++
		}
	}
	return count, nil
}

/**
 * ListConntrackEntries retrieves all active connections from the conntrack maps.
 */
func (m *Manager) ListConntrackEntries() ([]ConntrackEntry, error) {
	var entries []ConntrackEntry

	// List unified entries
	if m.conntrackMap != nil {
		var key NetXfwCtKey
		var val NetXfwCtValue
		iter := m.conntrackMap.Iterate()
		for iter.Next(&key, &val) {
			var srcIP, dstIP string

			// Check for IPv4-mapped IPv6
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
	}

	return entries, nil
}
