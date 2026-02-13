//go:build linux
// +build linux

package xdp

import (
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

	var key NetXfwLpmIpPortKey
	key.Port = port

	if ip4 := ipNet.IP.To4(); ip4 != nil {
		key.Prefixlen = uint32(96 + ones)
		key.Ip.In6U.U6Addr8[10] = 0xff
		key.Ip.In6U.U6Addr8[11] = 0xff
		copy(key.Ip.In6U.U6Addr8[12:], ip4)
	} else {
		key.Prefixlen = uint32(ones)
		copy(key.Ip.In6U.U6Addr8[:], ipNet.IP.To16())
	}

	return m.ipPortRules.Update(&key, &val, ebpf.UpdateAny)
}

/**
 * RemoveIPPortRule removes an IP+Port rule.
 */
func (m *Manager) RemoveIPPortRule(ipNet *net.IPNet, port uint16) error {
	ones, _ := ipNet.Mask.Size()

	var key NetXfwLpmIpPortKey
	key.Port = port

	if ip4 := ipNet.IP.To4(); ip4 != nil {
		key.Prefixlen = uint32(96 + ones)
		key.Ip.In6U.U6Addr8[10] = 0xff
		key.Ip.In6U.U6Addr8[11] = 0xff
		copy(key.Ip.In6U.U6Addr8[12:], ip4)
	} else {
		key.Prefixlen = uint32(ones)
		copy(key.Ip.In6U.U6Addr8[:], ipNet.IP.To16())
	}

	return m.ipPortRules.Delete(&key)
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

	if mapToIterate == nil {
		return rules, 0, nil
	}

	count := 0
	iter := mapToIterate.Iterate()

	var key NetXfwLpmIpPortKey
	var val NetXfwRuleValue

	for iter.Next(&key, &val) {
		var ipStr string
		var prefixLen uint32

		isMappedIPv4 := key.Ip.In6U.U6Addr8[10] == 0xff && key.Ip.In6U.U6Addr8[11] == 0xff

		if isMappedIPv4 {
			ip := net.IP(key.Ip.In6U.U6Addr8[12:])
			ipStr = ip.String()
			if key.Prefixlen >= 96 {
				prefixLen = key.Prefixlen - 96
			}
		} else {
			ip := net.IP(key.Ip.In6U.U6Addr8[:])
			ipStr = ip.String()
			prefixLen = key.Prefixlen
		}

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

/**
 * AddRateLimitRule adds a rate limit rule for an IP.
 */
func (m *Manager) AddRateLimitRule(ipNet *net.IPNet, rate, burst uint64) error {
	ones, _ := ipNet.Mask.Size()
	var key NetXfwLpmKey

	ip4 := ipNet.IP.To4()
	if ip4 != nil {
		key.Prefixlen = uint32(96 + ones)
		key.Data.In6U.U6Addr8[10] = 0xff
		key.Data.In6U.U6Addr8[11] = 0xff
		copy(key.Data.In6U.U6Addr8[12:], ip4)
	} else {
		ip6 := ipNet.IP.To16()
		if ip6 == nil {
			return fmt.Errorf("invalid IP address")
		}
		key.Prefixlen = uint32(ones)
		copy(key.Data.In6U.U6Addr8[:], ip6)
	}

	val := NetXfwRatelimitConf{
		Rate:  rate,
		Burst: burst,
	}
	return m.ratelimitConfig.Update(&key, &val, ebpf.UpdateAny)
}

/**
 * RemoveRateLimitRule removes a rate limit rule.
 */
func (m *Manager) RemoveRateLimitRule(ipNet *net.IPNet) error {
	ones, _ := ipNet.Mask.Size()
	var key NetXfwLpmKey

	ip4 := ipNet.IP.To4()
	if ip4 != nil {
		key.Prefixlen = uint32(96 + ones)
		key.Data.In6U.U6Addr8[10] = 0xff
		key.Data.In6U.U6Addr8[11] = 0xff
		copy(key.Data.In6U.U6Addr8[12:], ip4)

		// Cleanup state
		// Note: We need to cleanup the state for this IP.
		// The state map uses struct in6_addr as key.
		var stateKey NetXfwIn6Addr
		stateKey.In6U.U6Addr8[10] = 0xff
		stateKey.In6U.U6Addr8[11] = 0xff
		copy(stateKey.In6U.U6Addr8[12:], ip4)
		_ = m.ratelimitState.Delete(&stateKey)

	} else {
		ip6 := ipNet.IP.To16()
		if ip6 == nil {
			return fmt.Errorf("invalid IP address")
		}
		key.Prefixlen = uint32(ones)
		copy(key.Data.In6U.U6Addr8[:], ip6)

		// Cleanup state
		var stateKey NetXfwIn6Addr
		copy(stateKey.In6U.U6Addr8[:], ip6)
		_ = m.ratelimitState.Delete(&stateKey)
	}

	return m.ratelimitConfig.Delete(&key)
}

/**
 * ListRateLimitRules returns all configured rate limit rules.
 */
func (m *Manager) ListRateLimitRules(limit int, search string) (map[string]RateLimitConf, int, error) {
	rules := make(map[string]RateLimitConf)
	count := 0

	if m.ratelimitConfig == nil {
		return rules, 0, nil
	}

	iter := m.ratelimitConfig.Iterate()
	var key NetXfwLpmKey
	var val NetXfwRatelimitConf

	for iter.Next(&key, &val) {
		var ipStr string
		var prefixLen uint32

		isMappedIPv4 := key.Data.In6U.U6Addr8[10] == 0xff && key.Data.In6U.U6Addr8[11] == 0xff

		if isMappedIPv4 {
			ip := net.IP(key.Data.In6U.U6Addr8[12:])
			ipStr = ip.String()
			prefixLen = key.Prefixlen - 96
		} else {
			ip := net.IP(key.Data.In6U.U6Addr8[:])
			ipStr = ip.String()
			prefixLen = key.Prefixlen
		}

		fullStr := fmt.Sprintf("%s/%d", ipStr, prefixLen)

		if search != "" && !strings.Contains(fullStr, search) {
			continue
		}

		count++
		if limit > 0 && len(rules) >= limit {
			continue
		}

		rules[fullStr] = RateLimitConf{
			Rate:  val.Rate,
			Burst: val.Burst,
		}
	}

	return rules, count, nil
}
