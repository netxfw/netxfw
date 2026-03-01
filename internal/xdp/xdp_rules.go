//go:build linux
// +build linux

package xdp

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/netxfw/netxfw/internal/utils/fileutil"
	"github.com/netxfw/netxfw/internal/utils/iputil"
)

// BlockStatic adds an IP to the static blocklist (LPM trie) and optionally persists it to a file.
// It reuses the underlying LockIP helper for BPF map operations.
// BlockStatic 将 IP 添加到静态黑名单（LPM Trie）并可选择将其持久化到文件。
// 它复用底层的 LockIP 辅助函数进行 BPF Map 操作。
func (m *Manager) BlockStatic(ipStr string, persistFile string) error {
	ipNet, err := iputil.ParseCIDR(ipStr)
	if err != nil {
		return fmt.Errorf("invalid IP or CIDR %s: %w", ipStr, err)
	}
	cidr := ipNet.String()

	// Use LockList (Static) / 使用 LockList（静态）
	mapObj := m.LockList()

	// Reuse existing LockIP helper / 复用现有的 LockIP 辅助函数
	if err := LockIP(mapObj, cidr); err != nil {
		return fmt.Errorf("failed to add to static blacklist %s: %v", cidr, err)
	}

	// Persist to lock list file if configured / 如果配置了，持久化到锁定列表文件
	if persistFile != "" {
		if err := fileutil.AppendToFile(persistFile, cidr); err != nil {
			m.logger.Warnf("[WARN] Failed to write to lock list file: %v", err)
		} else {
			m.logger.Infof("[SAVE] Persisted IP %s to %s", cidr, persistFile)
		}
	}

	m.logger.Infof("[BLOCK] Added IP %s to STATIC blacklist (permanent)", cidr)
	return nil
}

// AllowStatic adds an IP/CIDR to the whitelist.
// AllowStatic 将 IP/CIDR 添加到白名单。
func (m *Manager) AllowStatic(ipStr string, port uint16) error {
	mapObj := m.Whitelist()

	if err := AllowIP(mapObj, ipStr, port); err != nil {
		return fmt.Errorf("failed to allow %s: %v", ipStr, err)
	}
	return nil
}

// RemoveAllowStatic removes an IP/CIDR from the whitelist.
// RemoveAllowStatic 从白名单中移除 IP/CIDR。
func (m *Manager) RemoveAllowStatic(ipStr string) error {
	mapObj := m.Whitelist()

	if err := UnlockIP(mapObj, ipStr); err != nil {
		return fmt.Errorf("failed to remove from whitelist %s: %v", ipStr, err)
	}
	return nil
}

// ListWhitelist returns all whitelisted IPs/CIDRs.
// ListWhitelist 返回所有白名单中的 IP/CIDR。
func (m *Manager) ListWhitelist(isIPv6 bool) ([]string, error) {
	mapObj := m.Whitelist()
	// Use 0 limit to get all / 使用 0 限制以获取全部
	ips, _, err := ListWhitelistIPs(mapObj, 0, "")
	return ips, err
}

// BlockDynamic adds an IP to the dynamic blocklist (LRU hash) with a TTL.
// BlockDynamic 将 IP 添加到带有 TTL 的动态黑名单（LRU Hash）中。
func (m *Manager) BlockDynamic(ipStr string, ttl time.Duration) error {
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		return fmt.Errorf("invalid IP address %s: %w", ipStr, err)
	}

	expiry := uint64(0)
	if ttl > 0 {
		expiry = uint64(time.Now().Add(ttl).UnixNano())
	}

	if ip.Is4() {
		mapObj := m.DynLockList()
		if mapObj == nil {
			return fmt.Errorf("dyn_lock_list not available")
		}

		// Use mapped IPv6 for key / 使用映射的 IPv6 作为键
		key := acquireIn6Addr()
		defer releaseIn6Addr(key)
		b := ip.As4()
		// ::ffff:a.b.c.d
		key.In6U.U6Addr8[10] = 0xff
		key.In6U.U6Addr8[11] = 0xff
		copy(key.In6U.U6Addr8[12:], b[:])

		val := acquireRuleValue()
		defer releaseRuleValue(val)
		val.Counter = 2 // Deny / 拒绝
		val.ExpiresAt = expiry
		if err := mapObj.Update(key, val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("failed to block IPv4 %s: %v", ip, err)
		}
	} else if ip.Is6() {
		mapObj := m.DynLockList()
		if mapObj == nil {
			return fmt.Errorf("dyn_lock_list not available")
		}

		key := acquireIn6Addr()
		defer releaseIn6Addr(key)
		b := ip.As16()
		copy(key.In6U.U6Addr8[:], b[:])

		val := acquireRuleValue()
		defer releaseRuleValue(val)
		val.Counter = 2 // Deny / 拒绝
		val.ExpiresAt = expiry

		if err := mapObj.Update(key, val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("failed to block IPv6 %s: %v", ip, err)
		}
	}

	m.logger.Infof("[BLOCK] Blocked IP %s for %v (expiry: %d)", ip, ttl, expiry)
	return nil
}

// UnblockDynamic removes an IP from the dynamic blocklist (LRU hash).
// UnblockDynamic 从动态黑名单（LRU Hash）中移除 IP。
func (m *Manager) UnblockDynamic(ipStr string) error {
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		return fmt.Errorf("invalid IP address %s: %w", ipStr, err)
	}

	if ip.Is4() {
		mapObj := m.DynLockList()
		if mapObj == nil {
			return fmt.Errorf("dyn_lock_list not available")
		}

		// Use mapped IPv6 for key / 使用映射的 IPv6 作为键
		key := acquireIn6Addr()
		defer releaseIn6Addr(key)
		b := ip.As4()
		// ::ffff:a.b.c.d
		key.In6U.U6Addr8[10] = 0xff
		key.In6U.U6Addr8[11] = 0xff
		copy(key.In6U.U6Addr8[12:], b[:])

		if err := mapObj.Delete(key); err != nil {
			// Ignore if not found / 如果未找到则忽略
			if strings.Contains(err.Error(), "key does not exist") {
				m.logger.Infof("[INFO] IP %s not found in dynamic blacklist", ip)
				return nil
			}
			return fmt.Errorf("failed to unblock IPv4 %s: %v", ip, err)
		}
	} else if ip.Is6() {
		mapObj := m.DynLockList()
		if mapObj == nil {
			return fmt.Errorf("dyn_lock_list not available")
		}

		key := acquireIn6Addr()
		defer releaseIn6Addr(key)
		b := ip.As16()
		copy(key.In6U.U6Addr8[:], b[:])

		if err := mapObj.Delete(key); err != nil {
			// Ignore if not found / 如果未找到则忽略
			if strings.Contains(err.Error(), "key does not exist") {
				m.logger.Infof("[INFO] IP %s not found in dynamic blacklist", ip)
				return nil
			}
			return fmt.Errorf("failed to unblock IPv6 %s: %v", ip, err)
		}
	}

	m.logger.Infof("[OK] Unblocked IP %s from dynamic blacklist", ip)
	return nil
}

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
		key.Prefixlen = uint32(96 + ones) // #nosec G115 // prefixlen is always 0-128
		key.Ip.In6U.U6Addr8[10] = 0xff
		key.Ip.In6U.U6Addr8[11] = 0xff
		copy(key.Ip.In6U.U6Addr8[12:], ip4)
	} else {
		// Native IPv6 / 原生 IPv6
		key.Prefixlen = uint32(ones) // #nosec G115 // prefixlen is always 0-128
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
	return AddIPPortRuleToMap(m.ruleMap, ipNet, port, action, expiresAt)
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
		key.Prefixlen = uint32(96 + ones) // #nosec G115 // prefixlen is always 0-128
		key.Ip.In6U.U6Addr8[10] = 0xff
		key.Ip.In6U.U6Addr8[11] = 0xff
		copy(key.Ip.In6U.U6Addr8[12:], ip4)
	} else {
		// Native IPv6 / 原生 IPv6
		key.Prefixlen = uint32(ones) // #nosec G115 // prefixlen is always 0-128
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
	return RemoveIPPortRuleFromMap(m.ruleMap, ipNet, port)
}

/**
 * AllowPortToMap adds a port to the allowed ports map.
 * AllowPortToMap 向允许端口 Map 中添加一个端口。
 */
func AllowPortToMap(mapPtr *ebpf.Map, port uint16, expiresAt *time.Time) error {
	vals := acquireRuleValueSlice()
	defer releaseRuleValueSlice(vals)
	for i := range *vals {
		(*vals)[i].Counter = 1
		(*vals)[i].ExpiresAt = timeToBootNS(expiresAt)
	}
	return mapPtr.Update(&port, *vals, ebpf.UpdateAny)
}

/**
 * AllowPort adds a port to the allowed ports list.
 * AllowPort 向允许端口列表添加一个端口。
 * Note: allowed_ports is now merged into rule_map with port-only rules.
 * 注意：allowed_ports 现在已合并到 rule_map 中作为仅端口规则。
 */
func (m *Manager) AllowPort(port uint16, expiresAt *time.Time) error {
	// Use ruleMap with empty IP (0.0.0.0/0) for port-only rules
	// 使用 ruleMap 配合空 IP (0.0.0.0/0) 表示仅端口规则
	_, ipNet, _ := net.ParseCIDR("0.0.0.0/0")
	if ipNet == nil {
		return fmt.Errorf("failed to create default IP network")
	}
	return AddIPPortRuleToMap(m.ruleMap, ipNet, port, 1, expiresAt) // action=1 for allow
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
 * Note: allowed_ports is now merged into rule_map with port-only rules.
 * 注意：allowed_ports 现在已合并到 rule_map 中作为仅端口规则。
 */
func (m *Manager) RemovePort(port uint16) error {
	// Use ruleMap with empty IP (0.0.0.0/0) for port-only rules
	// 使用 ruleMap 配合空 IP (0.0.0.0/0) 表示仅端口规则
	_, ipNet, _ := net.ParseCIDR("0.0.0.0/0")
	if ipNet == nil {
		return fmt.Errorf("failed to create default IP network")
	}
	return RemoveIPPortRuleFromMap(m.ruleMap, ipNet, port)
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
			Action: uint8(val.Counter & 0xFF), // nolint:gosec // G115: Action is limited to 0-255
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
	rulesSlice, count, err := ListIPPortRulesFromMap(m.ruleMap, limit, search)
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

	vals := acquireRuleValueSlice()
	defer releaseRuleValueSlice(vals)

	iter := mapPtr.Iterate()
	for iter.Next(&port, vals) {
		ports = append(ports, port)
	}
	if err := iter.Err(); err != nil {
		return ports, nil
	}
	return ports, nil
}

/**
 * ListAllowedPorts retrieves all globally allowed ports.
 * ListAllowedPorts 获取所有全局允许的端口。
 * Note: allowed_ports is now merged into rule_map with port-only rules.
 * 注意：allowed_ports 现在已合并到 rule_map 中作为仅端口规则。
 */
func (m *Manager) ListAllowedPorts() ([]uint16, error) {
	// Port-only rules in ruleMap have IP=0.0.0.0/0
	// ruleMap 中的仅端口规则 IP=0.0.0.0/0
	var ports []uint16
	if m.ruleMap == nil {
		return ports, nil
	}

	iter := m.ruleMap.Iterate()
	var key NetXfwLpmIpPortKey
	var val NetXfwRuleValue

	for iter.Next(&key, &val) {
		// Check if this is a port-only rule (IP prefix = 0)
		// 检查是否为仅端口规则（IP 前缀 = 0）
		if key.Prefixlen == 0 || (key.Prefixlen == 96 && key.Ip.In6U.U6Addr8[10] == 0xff && key.Ip.In6U.U6Addr8[11] == 0xff) {
			// This is a port-only rule (0.0.0.0/0)
			// 这是仅端口规则 (0.0.0.0/0)
			if val.Counter == 1 { // action=allow
				ports = append(ports, key.Port)
			}
		}
	}
	return ports, iter.Err()
}

/**
 * AddRateLimitRuleToMap adds a rate limit rule to the unified ratelimit map.
 * AddRateLimitRuleToMap 向统一的速率限制 Map 添加规则。
 * Note: Uses unified ratelimit_map with NetXfwIn6Addr key and NetXfwRatelimitValue value.
 * 注意：使用统一的 ratelimit_map，键为 NetXfwIn6Addr，值为 NetXfwRatelimitValue。
 */
func AddRateLimitRuleToMap(ratelimitMap *ebpf.Map, ipNet *net.IPNet, rate, burst uint64) error {
	ip := ipNet.IP
	key := acquireIn6Addr()
	defer releaseIn6Addr(key)

	ip4 := ip.To4()
	if ip4 != nil {
		key.In6U.U6Addr8[10] = 0xff
		key.In6U.U6Addr8[11] = 0xff
		copy(key.In6U.U6Addr8[12:], ip4)
	} else {
		ip6 := ip.To16()
		if ip6 == nil {
			return fmt.Errorf("invalid IP address")
		}
		copy(key.In6U.U6Addr8[:], ip6)
	}

	rateScaled := (rate << 32) / 1000000000

	val := acquireRatelimitValue()
	defer releaseRatelimitValue(val)
	val.Rate = rate
	val.RateScaled = rateScaled
	val.Burst = burst
	val.ConfigVersion = 1
	val.LastTime = 0
	val.Tokens = burst
	return ratelimitMap.Update(key, val, ebpf.UpdateAny)
}

/**
 * AddRateLimitRuleToMapString adds a rate limit rule using CIDR string.
 */
func AddRateLimitRuleToMapString(ratelimitMap *ebpf.Map, cidr string, rate, burst uint64) error {
	ipNet, err := iputil.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %v", err)
	}
	return AddRateLimitRuleToMap(ratelimitMap, ipNet, rate, burst)
}

/**
 * AddRateLimitRule adds a rate limit rule for an IP.
 * AddRateLimitRule 为 IP 添加速率限制规则。
 * Note: Uses unified ratelimit_map (config + state combined).
 * 注意：使用统一的 ratelimit_map（配置 + 状态合并）。
 */
func (m *Manager) AddRateLimitRule(ipNet *net.IPNet, rate, burst uint64) error {
	if m.ratelimitMap == nil {
		return fmt.Errorf("ratelimit map not initialized")
	}
	return AddRateLimitRuleToMap(m.ratelimitMap, ipNet, rate, burst)
}

/**
 * RemoveRateLimitRuleFromMap removes a rate limit rule from the unified map.
 * RemoveRateLimitRuleFromMap 从统一的 Map 移除速率限制规则。
 */
func RemoveRateLimitRuleFromMap(ratelimitMap *ebpf.Map, ipNet *net.IPNet) error {
	ip := ipNet.IP
	var key NetXfwIn6Addr

	ip4 := ip.To4()
	if ip4 != nil {
		// IPv4-mapped IPv6: ::ffff:a.b.c.d
		// IPv4 映射的 IPv6：::ffff:a.b.c.d
		key.In6U.U6Addr8[10] = 0xff
		key.In6U.U6Addr8[11] = 0xff
		copy(key.In6U.U6Addr8[12:], ip4)
	} else {
		// Native IPv6
		// 原生 IPv6
		ip6 := ip.To16()
		if ip6 == nil {
			return fmt.Errorf("invalid IP address")
		}
		copy(key.In6U.U6Addr8[:], ip6)
	}

	return ratelimitMap.Delete(&key)
}

/**
 * RemoveRateLimitRuleFromMapString removes a rate limit rule using CIDR string.
 */
func RemoveRateLimitRuleFromMapString(ratelimitMap *ebpf.Map, cidr string) error {
	ipNet, err := iputil.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %v", err)
	}
	return RemoveRateLimitRuleFromMap(ratelimitMap, ipNet)
}

/**
 * RemoveRateLimitRule removes a rate limit rule.
 * RemoveRateLimitRule 移除速率限制规则。
 * Note: Uses unified ratelimit_map (config + state combined).
 * 注意：使用统一的 ratelimit_map（配置 + 状态合并）。
 */
func (m *Manager) RemoveRateLimitRule(ipNet *net.IPNet) error {
	if m.ratelimitMap == nil {
		return fmt.Errorf("ratelimit map not initialized")
	}
	return RemoveRateLimitRuleFromMap(m.ratelimitMap, ipNet)
}

/**
 * ListRateLimitRulesFromMap returns all configured rate limit rules from the unified map.
 * ListRateLimitRulesFromMap 从统一的 Map 返回所有配置的速率限制规则。
 */
func ListRateLimitRulesFromMap(mapPtr *ebpf.Map, limit int, search string) (map[string]RateLimitConf, int, error) {
	rules := make(map[string]RateLimitConf)
	count := 0

	if mapPtr == nil {
		return rules, 0, nil
	}

	iter := mapPtr.Iterate()
	var key NetXfwIn6Addr
	var val NetXfwRatelimitValue

	for iter.Next(&key, &val) {
		var ipStr string

		// Check for IPv4-mapped address
		// 检查是否为 IPv4 映射地址
		isMappedIPv4 := key.In6U.U6Addr8[10] == 0xff && key.In6U.U6Addr8[11] == 0xff

		if isMappedIPv4 {
			ip := net.IP(key.In6U.U6Addr8[12:])
			ipStr = ip.String()
		} else {
			ip := net.IP(key.In6U.U6Addr8[:])
			ipStr = ip.String()
		}

		if search != "" && !strings.Contains(ipStr, search) {
			continue
		}

		count++
		if limit > 0 && len(rules) >= limit {
			continue
		}

		rules[ipStr] = RateLimitConf{
			Rate:  val.Rate,
			Burst: val.Burst,
		}
	}

	return rules, count, nil
}

/**
 * ListRateLimitRules returns all configured rate limit rules.
 * ListRateLimitRules 返回所有配置的速率限制规则。
 * Note: Uses unified ratelimit_map (config + state combined).
 * 注意：使用统一的 ratelimit_map（配置 + 状态合并）。
 */
func (m *Manager) ListRateLimitRules(limit int, search string) (map[string]RateLimitConf, int, error) {
	if m.ratelimitMap == nil {
		return nil, 0, fmt.Errorf("ratelimit map not initialized")
	}
	return ListRateLimitRulesFromMap(m.ratelimitMap, limit, search)
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
func collectLpmKeys(m *ebpf.Map, value any) ([]NetXfwLpmKey, error) {
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
 * ClearRateLimitMap clears the rate limit map.
 * ClearRateLimitMap 清除速率限制 Map。
 */
func ClearRateLimitMap(m *ebpf.Map) error {
	if m == nil {
		return nil
	}
	var keys []NetXfwIn6Addr
	var key NetXfwIn6Addr
	var val NetXfwRatelimitValue
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
