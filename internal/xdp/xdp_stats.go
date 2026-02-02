//go:build linux
// +build linux

package xdp

import (
	"fmt"
	"net"
	"time"
)

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

	// Count IPv4 locked IPs
	if m.lockList != nil {
		iter := m.lockList.Iterate()
		var key NetXfwLpmKey4
		var val NetXfwRuleValue
		for iter.Next(&key, &val) {
			count++
		}
	}

	// Count IPv6 locked IPs
	if m.lockList6 != nil {
		iter := m.lockList6.Iterate()
		var key NetXfwLpmKey6
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
		var key NetXfwLpmKey4
		var val NetXfwRuleValue
		for iter.Next(&key, &val) {
			count++
		}
	}
	if m.whitelist6 != nil {
		iter := m.whitelist6.Iterate()
		var key NetXfwLpmKey6
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
	if m.conntrackMap6 != nil {
		iter := m.conntrackMap6.Iterate()
		var key NetXfwCtKey6
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

	// List IPv4 entries
	if m.conntrackMap != nil {
		var key NetXfwCtKey
		var val NetXfwCtValue
		iter := m.conntrackMap.Iterate()
		for iter.Next(&key, &val) {
			entry := ConntrackEntry{
				SrcIP:    intToIP(key.SrcIp).String(),
				DstIP:    intToIP(key.DstIp).String(),
				SrcPort:  key.SrcPort,
				DstPort:  key.DstPort,
				Protocol: key.Protocol,
				LastSeen: time.Unix(0, int64(val.LastSeen)),
			}
			entries = append(entries, entry)
		}
		if err := iter.Err(); err != nil {
			return nil, fmt.Errorf("iterate ipv4 conntrack: %w", err)
		}
	}

	// List IPv6 entries
	if m.conntrackMap6 != nil {
		var key NetXfwCtKey6
		var val NetXfwCtValue
		iter := m.conntrackMap6.Iterate()
		for iter.Next(&key, &val) {
			entry := ConntrackEntry{
				SrcIP:    net.IP(key.SrcIp.In6U.U6Addr8[:]).String(),
				DstIP:    net.IP(key.DstIp.In6U.U6Addr8[:]).String(),
				SrcPort:  key.SrcPort,
				DstPort:  key.DstPort,
				Protocol: key.Protocol,
				LastSeen: time.Unix(0, int64(val.LastSeen)),
			}
			entries = append(entries, entry)
		}
		if err := iter.Err(); err != nil {
			return nil, fmt.Errorf("iterate ipv6 conntrack: %w", err)
		}
	}

	return entries, nil
}
