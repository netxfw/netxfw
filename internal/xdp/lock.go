// internal/xdp/lock.go
package xdp

import (
	"fmt"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/livp123/netxfw/internal/utils/iputil"
	"github.com/livp123/netxfw/pkg/sdk"
)

/**
 * IsIPv6 checks if a string is a valid IPv6 address or CIDR.
 * IsIPv6 检查字符串是否为有效的 IPv6 地址或 CIDR。
 */
func IsIPv6(cidr string) bool {
	return iputil.IsIPv6(cidr)
}

/**
 * CheckConflict checks if a CIDR exists in the opposite map.
 * Returns true if conflict found, and a message describing it.
 * CheckConflict 检查 CIDR 是否存在于相反的 Map 中。
 * 如果发现冲突则返回 true，以及描述冲突的消息。
 */
func CheckConflict(mapPtr *ebpf.Map, cidrStr string, isWhitelistMap bool) (bool, string) {
	ipNet, err := iputil.ParseCIDR(cidrStr)
	if err != nil {
		return false, ""
	}
	ip := ipNet.IP
	ones, _ := ipNet.Mask.Size()

	var val NetXfwRuleValue
	found := false

	var key NetXfwLpmKey
	var keyData NetXfwIn6Addr

	if ip4 := ip.To4(); ip4 != nil {
		// Convert to IPv4-mapped IPv6 / 转换为 IPv4 映射的 IPv6
		key.Prefixlen = uint32(96 + ones)
		keyData.In6U.U6Addr8[10] = 0xff
		keyData.In6U.U6Addr8[11] = 0xff
		copy(keyData.In6U.U6Addr8[12:], ip4)
	} else {
		// IPv6 key / IPv6 键
		key.Prefixlen = uint32(ones)
		copy(keyData.In6U.U6Addr8[:], ip.To16())
	}
	key.Data = keyData

	if err := mapPtr.Lookup(key, &val); err == nil {
		found = true
	}

	if found {
		op := "blacklist"
		if isWhitelistMap {
			op = "whitelist"
		}
		return true, fmt.Sprintf("%s is already in %s", cidrStr, op)
	}
	return false, ""
}

// IsIPInMap checks if a CIDR exists in the map.
// IsIPInMap 检查 CIDR 是否存在于 Map 中。
func IsIPInMap(mapPtr *ebpf.Map, cidrStr string) (bool, error) {
	conflict, _ := CheckConflict(mapPtr, cidrStr, false)
	return conflict, nil
}

/**
 * LockIP adds an IPv4 or IPv6 address or CIDR to the BPF lock list.
 * LockIP 将 IPv4/IPv6 地址或 CIDR 网段添加到 BPF 锁定列表中。
 */
func LockIP(mapPtr *ebpf.Map, cidrStr string) error {
	// Parse as CIDR or fallback to single IP / 尝试解析为 CIDR，失败则回退到单个 IP
	ipNet, err := iputil.ParseCIDR(cidrStr)
	if err != nil {
		return fmt.Errorf("invalid IP or CIDR: %s", cidrStr)
	}
	ip := ipNet.IP
	ones, _ := ipNet.Mask.Size()

	val := NetXfwRuleValue{Counter: 0, ExpiresAt: 0} // Initial drop count and no expiration

	var key NetXfwLpmKey
	var keyData NetXfwIn6Addr

	if ip4 := ip.To4(); ip4 != nil {
		// IPv4-mapped IPv6 key
		key.Prefixlen = uint32(96 + ones)
		keyData.In6U.U6Addr8[10] = 0xff
		keyData.In6U.U6Addr8[11] = 0xff
		copy(keyData.In6U.U6Addr8[12:], ip4)
	} else {
		// IPv6 key
		key.Prefixlen = uint32(ones)
		copy(keyData.In6U.U6Addr8[:], ip.To16())
	}
	key.Data = keyData

	if err := mapPtr.Update(key, &val, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to update map: %v", err)
	}
	return nil
}

/**
 * AllowIP adds an IPv4 or IPv6 address or CIDR to the BPF whitelist.
 * Optionally specifies a port (if port > 0).
 * AllowIP 将 IPv4/IPv6 地址或 CIDR 网段添加到 BPF 白名单中。
 * 可选指定端口（如果 port > 0）。
 */
func AllowIP(mapPtr *ebpf.Map, cidrStr string, port uint16) error {
	ipNet, err := iputil.ParseCIDR(cidrStr)
	if err != nil {
		return fmt.Errorf("invalid IP or CIDR: %s", cidrStr)
	}
	ip := ipNet.IP
	ones, _ := ipNet.Mask.Size()

	counter := uint64(1)
	if port > 0 {
		counter = uint64(port)
	}

	val := NetXfwRuleValue{Counter: counter, ExpiresAt: 0} // Store port in Counter if > 0

	var key NetXfwLpmKey
	var keyData NetXfwIn6Addr

	if ip4 := ip.To4(); ip4 != nil {
		key.Prefixlen = uint32(96 + ones)
		keyData.In6U.U6Addr8[10] = 0xff
		keyData.In6U.U6Addr8[11] = 0xff
		copy(keyData.In6U.U6Addr8[12:], ip4)
	} else {
		key.Prefixlen = uint32(ones)
		copy(keyData.In6U.U6Addr8[:], ip.To16())
	}
	key.Data = keyData

	return mapPtr.Put(key, val)
}

/**
 * UnlockIP removes an IP or CIDR from the BPF lock list.
 * UnlockIP 从 BPF 锁定列表中移除 IP 或 CIDR。
 */
func UnlockIP(mapPtr *ebpf.Map, cidrStr string) error {
	ipNet, err := iputil.ParseCIDR(cidrStr)
	if err != nil {
		return fmt.Errorf("invalid IP or CIDR: %s", cidrStr)
	}
	ip := ipNet.IP
	ones, _ := ipNet.Mask.Size()

	var key NetXfwLpmKey
	var keyData NetXfwIn6Addr

	if ip4 := ip.To4(); ip4 != nil {
		// IPv4-mapped IPv6 key / IPv4 映射的 IPv6 键
		key.Prefixlen = uint32(96 + ones)
		keyData.In6U.U6Addr8[10] = 0xff
		keyData.In6U.U6Addr8[11] = 0xff
		copy(keyData.In6U.U6Addr8[12:], ip4)
	} else {
		// IPv6 key / IPv6 键
		key.Prefixlen = uint32(ones)
		copy(keyData.In6U.U6Addr8[:], ip.To16())
	}
	key.Data = keyData

	if err := mapPtr.Delete(key); err != nil {
		// Ignore if not found / 如果未找到则忽略
		if strings.Contains(err.Error(), "key does not exist") {
			return nil
		}
		return fmt.Errorf("failed to delete from map: %v", err)
	}
	return nil
}

/**
 * ListWhitelistIPs iterates over the BPF whitelist map and returns limited allowed ranges.
 * ListWhitelistIPs 遍历 BPF 白名单 Map 并返回有限数量的允许网段。
 */
func ListWhitelistIPs(mapPtr *ebpf.Map, limit int, search string) ([]string, int, error) {
	// isIPv6 is deprecated but kept for compatibility
	if mapPtr == nil {
		return nil, 0, nil
	}

	// Fast Path: Direct lookup if search is a valid CIDR or IP
	if search != "" {
		if ipNet, err := iputil.ParseCIDR(search); err == nil {
			ip := ipNet.IP
			ones, _ := ipNet.Mask.Size()

			if ip != nil {
				var val NetXfwRuleValue
				found := false

				var key NetXfwLpmKey
				var keyData NetXfwIn6Addr

				if ip4 := ip.To4(); ip4 != nil {
					key.Prefixlen = uint32(96 + ones)
					keyData.In6U.U6Addr8[10] = 0xff
					keyData.In6U.U6Addr8[11] = 0xff
					copy(keyData.In6U.U6Addr8[12:], ip4)
				} else {
					key.Prefixlen = uint32(ones)
					copy(keyData.In6U.U6Addr8[:], ip.To16())
				}
				key.Data = keyData

				if err := mapPtr.Lookup(key, &val); err == nil {
					found = true
				}

				if found {
					fullStr := fmt.Sprintf("%s/%d", ip.String(), ones)
					if val.Counter > 1 {
						fullStr = fmt.Sprintf("%s (port: %d)", fullStr, val.Counter)
					}
					return []string{fullStr}, 1, nil
				}
			}
		}
	}

	var ips []string
	count := 0
	iter := mapPtr.Iterate()

	var key NetXfwLpmKey
	var val NetXfwRuleValue
	for iter.Next(&key, &val) {
		// Convert unified key to string representation
		fullStr := FormatLpmKey(&key)
		if search != "" && !strings.Contains(fullStr, search) {
			continue
		}

		count++
		if val.Counter > 1 {
			fullStr = fmt.Sprintf("%s (port: %d)", fullStr, val.Counter)
		}
		ips = append(ips, fullStr)
		if limit > 0 && len(ips) >= limit {
			break
		}
	}

	return ips, count, iter.Err()
}

/**
 * CleanupExpiredRules iterates over the maps and removes expired entries.
 * Returns the number of removed entries.
 * CleanupExpiredRules 遍历 Map 并移除过期条目。
 * 返回移除的条目数量。
 */
func CleanupExpiredRules(mapPtr *ebpf.Map, isIPv6 bool) (int, error) {
	// isIPv6 param is now redundant but kept for signature compatibility
	// isIPv6 参数现在是多余的，但保留以保持签名兼容性
	if mapPtr == nil {
		return 0, nil
	}

	now := uint64(time.Now().UnixNano())
	removed := 0
	iter := mapPtr.Iterate()

	var key NetXfwLpmKey
	var val NetXfwRuleValue
	for iter.Next(&key, &val) {
		if val.ExpiresAt > 0 && now > val.ExpiresAt {
			if err := mapPtr.Delete(key); err == nil {
				removed++
			}
		}
	}

	return removed, iter.Err()
}

/**
 * ListBlockedIPs iterates over the BPF map and returns limited blocked ranges and stats.
 * ListBlockedIPs 遍历 BPF Map 并返回有限数量的封禁网段及其统计信息。
 */
func ListBlockedIPs(mapPtr *ebpf.Map, isIPv6 bool, limit int, search string) ([]sdk.BlockedIP, int, error) {
	// isIPv6 is deprecated/ignored for unified maps

	if search != "" {
		// If search term looks like an IP/CIDR, try direct lookup
		if ipNet, err := iputil.ParseCIDR(search); err == nil {
			ip := ipNet.IP
			ones, _ := ipNet.Mask.Size()

			if ip != nil {
				var val NetXfwRuleValue
				found := false

				var key NetXfwLpmKey
				var keyData NetXfwIn6Addr

				if ip4 := ip.To4(); ip4 != nil {
					key.Prefixlen = uint32(96 + ones)
					keyData.In6U.U6Addr8[10] = 0xff
					keyData.In6U.U6Addr8[11] = 0xff
					copy(keyData.In6U.U6Addr8[12:], ip4)
				} else {
					key.Prefixlen = uint32(ones)
					copy(keyData.In6U.U6Addr8[:], ip.To16())
				}
				key.Data = keyData

				if err := mapPtr.Lookup(key, &val); err == nil {
					found = true
				}

				if found {
					fullStr := fmt.Sprintf("%s/%d", ip.String(), ones)
					if val.Counter > 1 {
						fullStr = fmt.Sprintf("%s (port: %d)", fullStr, val.Counter)
					}
					return []sdk.BlockedIP{{IP: fullStr, ExpiresAt: val.ExpiresAt, Counter: val.Counter}}, 1, nil
				}
			}
		}
	}

	var ips []sdk.BlockedIP
	count := 0
	iter := mapPtr.Iterate()

	var key NetXfwLpmKey
	var val NetXfwRuleValue
	for iter.Next(&key, &val) {
		// Convert unified key to string representation
		fullStr := FormatLpmKey(&key)
		// Extract IP part for search comparison (FormatLpmKey returns IP/CIDR)
		ipStr := fullStr
		if idx := strings.Index(fullStr, "/"); idx != -1 {
			ipStr = fullStr[:idx]
		}

		if search != "" && !strings.Contains(ipStr, search) {
			continue
		}

		count++
		if val.Counter > 1 {
			fullStr = fmt.Sprintf("%s (port: %d)", fullStr, val.Counter)
		}
		ips = append(ips, sdk.BlockedIP{IP: fullStr, ExpiresAt: val.ExpiresAt, Counter: val.Counter})
		if limit > 0 && len(ips) >= limit {
			break
		}
	}

	return ips, count, iter.Err()
}
