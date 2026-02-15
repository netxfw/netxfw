//go:build linux
// +build linux

package xdp

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/livp123/netxfw/internal/utils/iputil"
)

/**
 * AddIPPortRuleToMap adds an IP+Port rule to the map.
 * AddIPPortRuleToMap 向 Map 中添加一条 IP+端口规则。
 */
func AddIPPortRuleToMap(mapPtr *ebpf.Map, ipNet *net.IPNet, port uint16, action uint8, expiresAt *time.Time) error {
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

	return mapPtr.Update(&key, &val, ebpf.UpdateAny)
}

/**
 * AddIPPortRuleToMapString adds an IP+Port rule to the map using CIDR string.
 * AddIPPortRuleToMapString 使用 CIDR 字符串向 Map 中添加一条 IP+端口规则。
 */
func AddIPPortRuleToMapString(mapPtr *ebpf.Map, cidr string, port uint16, action uint8) error {
	ipNet, err := iputil.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %v", err)
	}
	return AddIPPortRuleToMap(mapPtr, ipNet, port, action, nil)
}

/**
 * AddIPPortRule adds an IP+Port rule to the firewall.
 * action: 1 for allow, 2 for deny
 * AddIPPortRule 向防火墙添加 IP+端口规则。
 * action: 1 表示允许，2 表示拒绝
 */
func (m *Manager) AddIPPortRule(ipNet *net.IPNet, port uint16, action uint8, expiresAt *time.Time) error {
	return AddIPPortRuleToMap(m.ipPortRules, ipNet, port, action, expiresAt)
}

/**
 * RemoveIPPortRuleFromMap removes an IP+Port rule from the map.
 * RemoveIPPortRuleFromMap 从 Map 中移除一条 IP+端口规则。
 */
func RemoveIPPortRuleFromMap(mapPtr *ebpf.Map, ipNet *net.IPNet, port uint16) error {
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

	return mapPtr.Delete(&key)
}

/**
 * RemoveIPPortRuleFromMapString removes an IP+Port rule from the map using CIDR string.
 * RemoveIPPortRuleFromMapString 使用 CIDR 字符串从 Map 中移除一条 IP+端口规则。
 */
func RemoveIPPortRuleFromMapString(mapPtr *ebpf.Map, cidr string, port uint16) error {
	ipNet, err := iputil.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %v", err)
	}
	return RemoveIPPortRuleFromMap(mapPtr, ipNet, port)
}

/**
 * RemoveIPPortRule removes an IP+Port rule.
 * RemoveIPPortRule 移除 IP+端口规则。
 */
func (m *Manager) RemoveIPPortRule(ipNet *net.IPNet, port uint16) error {
	return RemoveIPPortRuleFromMap(m.ipPortRules, ipNet, port)
}

/**
 * AllowPortToMap adds a port to the allowed ports map.
 * AllowPortToMap 向允许端口 Map 中添加一个端口。
 */
func AllowPortToMap(mapPtr *ebpf.Map, port uint16, expiresAt *time.Time) error {
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
	return mapPtr.Update(&port, vals, ebpf.UpdateAny)
}

/**
 * AllowPort adds a port to the allowed ports list.
 * AllowPort 向允许端口列表添加一个端口。
 */
func (m *Manager) AllowPort(port uint16, expiresAt *time.Time) error {
	return AllowPortToMap(m.allowedPorts, port, expiresAt)
}

/**
 * RemovePortFromMap removes a port from the allowed ports map.
 */
func RemovePortFromMap(mapPtr *ebpf.Map, port uint16) error {
	return mapPtr.Delete(&port)
}

/**
 * RemovePort removes a port from the allowed ports list.
 * RemovePort 从允许端口列表中移除一个端口。
 */
func (m *Manager) RemovePort(port uint16) error {
	return RemovePortFromMap(m.allowedPorts, port)
}

/* ListIPPortRulesFromMap iterates over the map and returns structured rules.
 */
func ListIPPortRulesFromMap(mapPtr *ebpf.Map, limit int, search string) ([]IPPortRule, int, error) {
	var rules []IPPortRule
	if mapPtr == nil {
		return rules, 0, nil
	}

	count := 0
	iter := mapPtr.Iterate()

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
			continue
		}

		rules = append(rules, IPPortRule{
			IP:     fmt.Sprintf("%s/%d", ipStr, prefixLen),
			Port:   key.Port,
			Action: uint8(val.Counter),
		})
	}
	return rules, count, iter.Err()
}

/**
 * ListIPPortRules returns all configured IP+Port rules with limit and search support.
 * ListIPPortRules 返回所有配置的 IP+端口规则，支持限制和搜索。
 */
func (m *Manager) ListIPPortRules(isIPv6 bool, limit int, search string) (map[string]string, int, error) {
	rulesMap := make(map[string]string)
	rulesSlice, count, err := ListIPPortRulesFromMap(m.ipPortRules, limit, search)
	if err != nil {
		return nil, 0, err
	}

	for _, r := range rulesSlice {
		key := fmt.Sprintf("%s:%d", r.IP, r.Port)
		action := "allow"
		if r.Action == 2 {
			action = "deny"
		}
		rulesMap[key] = action
	}
	return rulesMap, count, nil
}

/**
 * ListAllowedPortsFromMap retrieves all globally allowed ports from map.
 */
func ListAllowedPortsFromMap(mapPtr *ebpf.Map) ([]uint16, error) {
	var ports []uint16
	var port uint16
	// Note: BPF_MAP_TYPE_PERCPU_HASH returns a slice of values, one per CPU
	// 注意：BPF_MAP_TYPE_PERCPU_HASH 返回一个值切片，每个 CPU 一个
	_, err := ebpf.PossibleCPU()
	if err != nil {
		return nil, fmt.Errorf("get possible CPUs: %w", err)
	}
	// We don't need val here really but iterating requires it
	// iterating PERCPU map requires value to be slice.
	// We can't pre-allocate exact slice size without calling PossibleCPU, but Iterate handles it?
	// The original code allocated val := make([]NetXfwRuleValue, numCPU)

	numCPU, _ := ebpf.PossibleCPU()
	val := make([]NetXfwRuleValue, numCPU)

	iter := mapPtr.Iterate()
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
 * ListAllowedPorts retrieves all globally allowed ports.
 * ListAllowedPorts 获取所有全局允许的端口。
 */
func (m *Manager) ListAllowedPorts() ([]uint16, error) {
	return ListAllowedPortsFromMap(m.allowedPorts)
}

/**
 * AddRateLimitRuleToMap adds a rate limit rule to the map.
 */
func AddRateLimitRuleToMap(configMap *ebpf.Map, ipNet *net.IPNet, rate, burst uint64) error {
	ones, _ := ipNet.Mask.Size()
	var key NetXfwLpmKey

	ip4 := ipNet.IP.To4()
	if ip4 != nil {
		// IPv4-mapped IPv6
		key.Prefixlen = uint32(96 + ones)
		key.Data.In6U.U6Addr8[10] = 0xff
		key.Data.In6U.U6Addr8[11] = 0xff
		copy(key.Data.In6U.U6Addr8[12:], ip4)
	} else {
		// Native IPv6
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
	return configMap.Update(&key, &val, ebpf.UpdateAny)
}

/**
 * AddRateLimitRuleToMapString adds a rate limit rule using CIDR string.
 */
func AddRateLimitRuleToMapString(configMap *ebpf.Map, cidr string, rate, burst uint64) error {
	ipNet, err := iputil.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %v", err)
	}
	return AddRateLimitRuleToMap(configMap, ipNet, rate, burst)
}

/**
 * AddRateLimitRule adds a rate limit rule for an IP.
 * AddRateLimitRule 为 IP 添加速率限制规则。
 */
func (m *Manager) AddRateLimitRule(ipNet *net.IPNet, rate, burst uint64) error {
	return AddRateLimitRuleToMap(m.ratelimitConfig, ipNet, rate, burst)
}

/**
 * RemoveRateLimitRuleFromMaps removes a rate limit rule from config and state maps.
 */
func RemoveRateLimitRuleFromMaps(configMap, stateMap *ebpf.Map, ipNet *net.IPNet) error {
	ones, _ := ipNet.Mask.Size()
	var key NetXfwLpmKey

	ip4 := ipNet.IP.To4()
	if ip4 != nil {
		// IPv4-mapped IPv6
		key.Prefixlen = uint32(96 + ones)
		key.Data.In6U.U6Addr8[10] = 0xff
		key.Data.In6U.U6Addr8[11] = 0xff
		copy(key.Data.In6U.U6Addr8[12:], ip4)

		// Cleanup state
		if stateMap != nil {
			var stateKey NetXfwIn6Addr
			stateKey.In6U.U6Addr8[10] = 0xff
			stateKey.In6U.U6Addr8[11] = 0xff
			copy(stateKey.In6U.U6Addr8[12:], ip4)
			_ = stateMap.Delete(&stateKey)
		}

	} else {
		// Native IPv6
		ip6 := ipNet.IP.To16()
		if ip6 == nil {
			return fmt.Errorf("invalid IP address")
		}
		key.Prefixlen = uint32(ones)
		copy(key.Data.In6U.U6Addr8[:], ip6)

		// Cleanup state
		if stateMap != nil {
			var stateKey NetXfwIn6Addr
			copy(stateKey.In6U.U6Addr8[:], ip6)
			_ = stateMap.Delete(&stateKey)
		}
	}

	return configMap.Delete(&key)
}

/**
 * RemoveRateLimitRuleFromMapsString removes a rate limit rule using CIDR string.
 */
func RemoveRateLimitRuleFromMapsString(configMap, stateMap *ebpf.Map, cidr string) error {
	ipNet, err := iputil.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %v", err)
	}
	return RemoveRateLimitRuleFromMaps(configMap, stateMap, ipNet)
}

/**
 * RemoveRateLimitRule removes a rate limit rule.
 * RemoveRateLimitRule 移除速率限制规则。
 */
func (m *Manager) RemoveRateLimitRule(ipNet *net.IPNet) error {
	return RemoveRateLimitRuleFromMaps(m.ratelimitConfig, m.ratelimitState, ipNet)
}

/**
 * ListRateLimitRulesFromMap returns all configured rate limit rules from the map.
 */
func ListRateLimitRulesFromMap(mapPtr *ebpf.Map, limit int, search string) (map[string]RateLimitConf, int, error) {
	rules := make(map[string]RateLimitConf)
	count := 0

	if mapPtr == nil {
		return rules, 0, nil
	}

	iter := mapPtr.Iterate()
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

/**
 * ListRateLimitRules returns all configured rate limit rules.
 * ListRateLimitRules 返回所有配置的速率限制规则。
 */
func (m *Manager) ListRateLimitRules(limit int, search string) (map[string]RateLimitConf, int, error) {
	return ListRateLimitRulesFromMap(m.ratelimitConfig, limit, search)
}

/**
 * ClearLpmMap clears a map that uses NetXfwLpmKey.
 */
func ClearLpmMap(m *ebpf.Map) error {
	// This function is kept for backward compatibility or if we want a generic clearer.
	// But it's hard to implement generically because keys differ.
	return fmt.Errorf("not implemented, use specific Clear*Map functions")
}

// Helper to collect keys
func collectLpmKeys(m *ebpf.Map, value interface{}) ([]NetXfwLpmKey, error) {
	var keys []NetXfwLpmKey
	var key NetXfwLpmKey
	iter := m.Iterate()
	for iter.Next(&key, value) {
		keys = append(keys, key)
	}
	return keys, iter.Err()
}

/**
 * ClearBlacklistMap clears the blacklist/whitelist map.
 */
func ClearBlacklistMap(m *ebpf.Map) error {
	if m == nil {
		return nil
	}
	var val NetXfwRuleValue
	keys, err := collectLpmKeys(m, &val)
	if err != nil {
		return err
	}
	for _, k := range keys {
		_ = m.Delete(k)
	}
	return nil
}

/**
 * ClearRateLimitMap clears the rate limit config map.
 */
func ClearRateLimitMap(m *ebpf.Map) error {
	if m == nil {
		return nil
	}
	var val NetXfwRatelimitConf
	keys, err := collectLpmKeys(m, &val)
	if err != nil {
		return err
	}
	for _, k := range keys {
		_ = m.Delete(k)
	}
	return nil
}

/**
 * ClearIPPortMap clears the IP+Port rules map.
 */
func ClearIPPortMap(m *ebpf.Map) error {
	if m == nil {
		return nil
	}
	var keys []NetXfwLpmIpPortKey
	var key NetXfwLpmIpPortKey
	var val NetXfwRuleValue
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		keys = append(keys, key)
	}
	if err := iter.Err(); err != nil {
		return err
	}

	for _, k := range keys {
		_ = m.Delete(k)
	}
	return nil
}

/**
 * ClearPortMap clears the allowed ports map.
 */
func ClearPortMap(m *ebpf.Map) error {
	if m == nil {
		return nil
	}
	var keys []uint16
	var key uint16
	// PERCPU map value is slice
	numCPU, _ := ebpf.PossibleCPU()
	val := make([]NetXfwRuleValue, numCPU)

	iter := m.Iterate()
	for iter.Next(&key, &val) {
		keys = append(keys, key)
	}
	if err := iter.Err(); err != nil {
		return err
	}

	for _, k := range keys {
		_ = m.Delete(k)
	}
	return nil
}
