//go:build linux
// +build linux

package xdp

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/cilium/ebpf"
)

/**
 * AddIPPortRule adds an IP+Port rule to the firewall.
 * action: 1 for allow, 2 for deny
 */
func (m *Manager) AddIPPortRule(ipNet *net.IPNet, port uint16, action uint8, expiresAt *time.Time) error {
	ones, _ := ipNet.Mask.Size()
	val := NetXfwRuleValue{
		Counter:   uint64(action),
		ExpiresAt: timeToBootNS(expiresAt),
	}
	ip := ipNet.IP.To4()
	if ip != nil {
		key := NetXfwLpmIp4PortKey{
			Prefixlen: uint32(32 + ones),
			Port:      port,
			Pad:       0,
			Ip:        binary.LittleEndian.Uint32(ip),
		}
		return m.ipPortRules.Update(&key, &val, ebpf.UpdateAny)
	}

	ip = ipNet.IP.To16()
	if ip != nil {
		key := NetXfwLpmIp6PortKey{
			Prefixlen: uint32(32 + ones),
			Port:      port,
			Pad:       0,
		}
		copy(key.Ip.In6U.U6Addr8[:], ip)
		return m.ipPortRules6.Update(&key, &val, ebpf.UpdateAny)
	}

	return fmt.Errorf("invalid IP address")
}

/**
 * RemoveIPPortRule removes an IP+Port rule.
 */
func (m *Manager) RemoveIPPortRule(ipNet *net.IPNet, port uint16) error {
	ones, _ := ipNet.Mask.Size()
	ip := ipNet.IP.To4()
	if ip != nil {
		key := NetXfwLpmIp4PortKey{
			Prefixlen: uint32(32 + ones),
			Port:      port,
			Pad:       0,
			Ip:        binary.LittleEndian.Uint32(ip),
		}
		return m.ipPortRules.Delete(&key)
	}

	ip = ipNet.IP.To16()
	if ip != nil {
		key := NetXfwLpmIp6PortKey{
			Prefixlen: uint32(32 + ones),
			Port:      port,
			Pad:       0,
		}
		copy(key.Ip.In6U.U6Addr8[:], ip)
		return m.ipPortRules6.Delete(&key)
	}

	return fmt.Errorf("invalid IP address")
}

/**
 * AllowPort adds a port to the allowed ports list.
 */
func (m *Manager) AllowPort(port uint16, expiresAt *time.Time) error {
	// BPF_MAP_TYPE_PERCPU_HASH requires a slice of values for update if we want to set it for all CPUs
	numCPU, err := ebpf.PossibleCPU()
	if err != nil {
		return fmt.Errorf("get possible CPUs: %w", err)
	}
	val := NetXfwRuleValue{
		Counter:   1,
		ExpiresAt: timeToBootNS(expiresAt),
	}
	vals := make([]NetXfwRuleValue, numCPU)
	for i := 0; i < numCPU; i++ {
		vals[i] = val
	}
	// For PERCPU maps, Update expects the slice itself, not a pointer to it
	return m.allowedPorts.Update(&port, vals, ebpf.UpdateAny)
}

/**
 * RemovePort removes a port from the allowed ports list.
 */
func (m *Manager) RemovePort(port uint16) error {
	return m.allowedPorts.Delete(&port)
}

/**
 * ListIPPortRules returns all configured IP+Port rules with limit and search support.
 */
func (m *Manager) ListIPPortRules(isIPv6 bool, limit int, search string) (map[string]string, int, error) {
	rules := make(map[string]string)
	mapToIterate := m.ipPortRules
	if isIPv6 {
		mapToIterate = m.ipPortRules6
	}

	if mapToIterate == nil {
		return rules, 0, nil
	}

	count := 0
	iter := mapToIterate.Iterate()

	if isIPv6 {
		var key NetXfwLpmIp6PortKey
		var val NetXfwRuleValue
		for iter.Next(&key, &val) {
			prefixLen := key.Prefixlen - 32
			ip := net.IP(key.Ip.In6U.U6Addr8[:])
			ipStr := ip.String()
			fullStr := fmt.Sprintf("%s/%d:%d", ipStr, prefixLen, key.Port)

			if search != "" && !strings.Contains(fullStr, search) {
				continue
			}

			count++
			if limit > 0 && len(rules) >= limit {
				continue // Keep counting total but stop adding to map
			}

			action := "allow"
			if val.Counter == 2 {
				action = "deny"
			}
			rules[fullStr] = action
		}
	} else {
		var key NetXfwLpmIp4PortKey
		var val NetXfwRuleValue
		for iter.Next(&key, &val) {
			prefixLen := key.Prefixlen - 32
			ip := intToIP(key.Ip)
			ipStr := ip.String()
			fullStr := fmt.Sprintf("%s/%d:%d", ipStr, prefixLen, key.Port)

			if search != "" && !strings.Contains(fullStr, search) {
				continue
			}

			count++
			if limit > 0 && len(rules) >= limit {
				continue // Keep counting total but stop adding to map
			}

			action := "allow"
			if val.Counter == 2 {
				action = "deny"
			}
			rules[fullStr] = action
		}
	}
	return rules, count, iter.Err()
}

/**
 * ListAllowedPorts retrieves all globally allowed ports.
 */
func (m *Manager) ListAllowedPorts() ([]uint16, error) {
	var ports []uint16
	var port uint16
	// Note: BPF_MAP_TYPE_PERCPU_HASH returns a slice of values, one per CPU
	numCPU, err := ebpf.PossibleCPU()
	if err != nil {
		return nil, fmt.Errorf("get possible CPUs: %w", err)
	}
	val := make([]NetXfwRuleValue, numCPU)
	iter := m.allowedPorts.Iterate()
	// IMPORTANT: In cilium/ebpf, when iterating over a PERCPU map,
	// the Next() call expects the value to be a slice.
	for iter.Next(&port, &val) {
		ports = append(ports, port)
	}
	if err := iter.Err(); err != nil {
		// If iteration fails, try to just see if map is empty
		return ports, nil
	}
	return ports, nil
}
