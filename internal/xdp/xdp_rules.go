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
 * AddIPPortRule 向防火墙添加 IP+端口规则。
 * action: 1 表示允许，2 表示拒绝
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
		// IPv4-mapped IPv6 / IPv4 映射的 IPv6
		key.Prefixlen = uint32(96 + ones)
		key.Ip.In6U.U6Addr8[10] = 0xff
		key.Ip.In6U.U6Addr8[11] = 0xff
		copy(key.Ip.In6U.U6Addr8[12:], ip4)
	} else {
		// Native IPv6 / 原生 IPv6
		key.Prefixlen = uint32(ones)
		copy(key.Ip.In6U.U6Addr8[:], ipNet.IP.To16())
	}

	return m.ipPortRules.Update(&key, &val, ebpf.UpdateAny)
}

/**
 * RemoveIPPortRule removes an IP+Port rule.
 * RemoveIPPortRule 移除 IP+端口规则。
 */
func (m *Manager) RemoveIPPortRule(ipNet *net.IPNet, port uint16) error {
	ones, _ := ipNet.Mask.Size()

	var key NetXfwLpmIpPortKey
	key.Port = port

	if ip4 := ipNet.IP.To4(); ip4 != nil {
		// IPv4-mapped IPv6 / IPv4 映射的 IPv6
		key.Prefixlen = uint32(96 + ones)
		key.Ip.In6U.U6Addr8[10] = 0xff
		key.Ip.In6U.U6Addr8[11] = 0xff
		copy(key.Ip.In6U.U6Addr8[12:], ip4)
	} else {
		// Native IPv6 / 原生 IPv6
		key.Prefixlen = uint32(ones)
		copy(key.Ip.In6U.U6Addr8[:], ipNet.IP.To16())
	}

	return m.ipPortRules.Delete(&key)
}

/**
 * AllowPort adds a port to the allowed ports list.
 * AllowPort 向允许端口列表添加一个端口。
 */
func (m *Manager) AllowPort(port uint16, expiresAt *time.Time) error {
	// BPF_MAP_TYPE_PERCPU_HASH requires a slice of values for update if we want to set it for all CPUs
	// BPF_MAP_TYPE_PERCPU_HASH 如果我们要为所有 CPU 设置更新，则需要一个值切片
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
	// 对于 PERCPU Map，Update 期望切片本身，而不是指向它的指针
	return m.allowedPorts.Update(&port, vals, ebpf.UpdateAny)
}

/**
 * RemovePort removes a port from the allowed ports list.
 * RemovePort 从允许端口列表中移除一个端口。
 */
func (m *Manager) RemovePort(port uint16) error {
	return m.allowedPorts.Delete(&port)
}

/**
 * ListIPPortRules returns all configured IP+Port rules with limit and search support.
 * ListIPPortRules 返回所有配置的 IP+端口规则，支持限制和搜索。
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
 * ListAllowedPorts 获取所有全局允许的端口。
 */
func (m *Manager) ListAllowedPorts() ([]uint16, error) {
	var ports []uint16
	var port uint16
	// Note: BPF_MAP_TYPE_PERCPU_HASH returns a slice of values, one per CPU
	// 注意：BPF_MAP_TYPE_PERCPU_HASH 返回一个值切片，每个 CPU 一个
	numCPU, err := ebpf.PossibleCPU()
	if err != nil {
		return nil, fmt.Errorf("get possible CPUs: %w", err)
	}
	val := make([]NetXfwRuleValue, numCPU)
	iter := m.allowedPorts.Iterate()
	// IMPORTANT: In cilium/ebpf, when iterating over a PERCPU map, the Next() call expects the value to be a slice.
	// 重要：在 cilium/ebpf 中，遍历 PERCPU Map 时，Next() 调用期望值为切片。
	for iter.Next(&port, &val) {
		ports = append(ports, port)
	}
	if err := iter.Err(); err != nil {
		// If iteration fails, try to just see if map is empty
		// 如果遍历失败，尝试查看 Map 是否为空
		return ports, nil
	}
	return ports, nil
}

/**
 * AddRateLimitRule adds a rate limit rule for an IP.
 * AddRateLimitRule 为 IP 添加速率限制规则。
 */
func (m *Manager) AddRateLimitRule(ipNet *net.IPNet, rate, burst uint64) error {
	ones, _ := ipNet.Mask.Size()
	var key NetXfwLpmKey

	ip4 := ipNet.IP.To4()
	if ip4 != nil {
		// IPv4-mapped IPv6 / IPv4 映射的 IPv6
		key.Prefixlen = uint32(96 + ones)
		key.Data.In6U.U6Addr8[10] = 0xff
		key.Data.In6U.U6Addr8[11] = 0xff
		copy(key.Data.In6U.U6Addr8[12:], ip4)
	} else {
		// Native IPv6 / 原生 IPv6
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
 * RemoveRateLimitRule 移除速率限制规则。
 */
func (m *Manager) RemoveRateLimitRule(ipNet *net.IPNet) error {
	ones, _ := ipNet.Mask.Size()
	var key NetXfwLpmKey

	ip4 := ipNet.IP.To4()
	if ip4 != nil {
		// IPv4-mapped IPv6 / IPv4 映射的 IPv6
		key.Prefixlen = uint32(96 + ones)
		key.Data.In6U.U6Addr8[10] = 0xff
		key.Data.In6U.U6Addr8[11] = 0xff
		copy(key.Data.In6U.U6Addr8[12:], ip4)

		// Cleanup state / 清理状态
		// Note: We need to cleanup the state for this IP.
		// The state map uses struct in6_addr as key.
		// 注意：我们需要清理该 IP 的状态。状态 Map 使用 struct in6_addr 作为键。
		var stateKey NetXfwIn6Addr
		stateKey.In6U.U6Addr8[10] = 0xff
		stateKey.In6U.U6Addr8[11] = 0xff
		copy(stateKey.In6U.U6Addr8[12:], ip4)
		_ = m.ratelimitState.Delete(&stateKey)

	} else {
		// Native IPv6 / 原生 IPv6
		ip6 := ipNet.IP.To16()
		if ip6 == nil {
			return fmt.Errorf("invalid IP address")
		}
		key.Prefixlen = uint32(ones)
		copy(key.Data.In6U.U6Addr8[:], ip6)

		// Cleanup state / 清理状态
		var stateKey NetXfwIn6Addr
		copy(stateKey.In6U.U6Addr8[:], ip6)
		_ = m.ratelimitState.Delete(&stateKey)
	}

	return m.ratelimitConfig.Delete(&key)
}

/**
 * ListRateLimitRules returns all configured rate limit rules.
 * ListRateLimitRules 返回所有配置的速率限制规则。
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
