// internal/xdp/lock.go
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
 * CheckConflict checks if a CIDR exists in the opposite map.
 * Returns true if conflict found, and a message describing it.
 */
func CheckConflict(mapPtr *ebpf.Map, cidrStr string, isWhitelistMap bool) (bool, string) {
	ip, ipNet, err := net.ParseCIDR(cidrStr)
	var ones int
	if err != nil {
		ip = net.ParseIP(cidrStr)
		if ip == nil {
			return false, ""
		}
		if ip4 := ip.To4(); ip4 != nil {
			ones = 32
		} else {
			ones = 128
		}
	} else {
		ones, _ = ipNet.Mask.Size()
	}

	var val RuleValue
	found := false
	if ip4 := ip.To4(); ip4 != nil {
		key := NetXfwLpmKey4{Prefixlen: uint32(ones), Data: binary.BigEndian.Uint32(ip4)}
		if err := mapPtr.Lookup(key, &val); err == nil {
			found = true
		}
	} else {
		var key NetXfwLpmKey6
		key.Prefixlen = uint32(ones)
		copy(key.Data.In6U.U6Addr8[:], ip.To16())
		if err := mapPtr.Lookup(key, &val); err == nil {
			found = true
		}
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

/**
 * LockIP adds an IPv4 or IPv6 address or CIDR to the BPF lock list.
 * LockIP 将 IPv4/IPv6 地址或 CIDR 网段添加到 BPF 锁定列表中。
 */
func LockIP(mapPtr *ebpf.Map, cidrStr string) error {
	// Parse as CIDR or fallback to single IP / 尝试解析为 CIDR，失败则回退到单个 IP
	ip, ipNet, err := net.ParseCIDR(cidrStr)
	var ones int
	if err != nil {
		ip = net.ParseIP(cidrStr)
		if ip == nil {
			return fmt.Errorf("invalid IP or CIDR: %s", cidrStr)
		}
		if ip4 := ip.To4(); ip4 != nil {
			ones = 32
		} else {
			ones = 128
		}
	} else {
		ones, _ = ipNet.Mask.Size()
	}

	val := RuleValue{Counter: 0, ExpiresAt: 0} // Initial drop count and no expiration
	if ip4 := ip.To4(); ip4 != nil {
		// IPv4 LPM key
		key := NetXfwLpmKey4{
			Prefixlen: uint32(ones),
			Data:      binary.BigEndian.Uint32(ip4),
		}
		return mapPtr.Put(key, val)
	}

	// IPv6 LPM key
	var key NetXfwLpmKey6
	key.Prefixlen = uint32(ones)
	copy(key.Data.In6U.U6Addr8[:], ip.To16())
	return mapPtr.Put(key, val)
}

/**
 * AllowIP adds an IPv4 or IPv6 address or CIDR to the BPF whitelist.
 * Optionally specifies a port (if port > 0).
 * AllowIP 将 IPv4/IPv6 地址或 CIDR 网段添加到 BPF 白名单中。
 * 可选指定端口（如果 port > 0）。
 */
func AllowIP(mapPtr *ebpf.Map, cidrStr string, port uint16) error {
	ip, ipNet, err := net.ParseCIDR(cidrStr)
	var ones int
	if err != nil {
		ip = net.ParseIP(cidrStr)
		if ip == nil {
			return fmt.Errorf("invalid IP or CIDR: %s", cidrStr)
		}
		if ip4 := ip.To4(); ip4 != nil {
			ones = 32
		} else {
			ones = 128
		}
	} else {
		ones, _ = ipNet.Mask.Size()
	}

	counter := uint64(1)
	if port > 0 {
		counter = uint64(port)
	}

	val := RuleValue{Counter: counter, ExpiresAt: 0} // Store port in Counter if > 0
	if ip4 := ip.To4(); ip4 != nil {
		key := NetXfwLpmKey4{
			Prefixlen: uint32(ones),
			Data:      binary.BigEndian.Uint32(ip4),
		}
		return mapPtr.Put(key, val)
	}

	var key NetXfwLpmKey6
	key.Prefixlen = uint32(ones)
	copy(key.Data.In6U.U6Addr8[:], ip.To16())
	return mapPtr.Put(key, val)
}

/**
 * UnlockIP removes an IPv4 or IPv6 address or CIDR from the BPF map.
 * UnlockIP 从 BPF Map 中移除 IPv4/IPv6 地址或 CIDR 网段。
 */
func UnlockIP(mapPtr *ebpf.Map, cidrStr string) error {
	ip, ipNet, err := net.ParseCIDR(cidrStr)
	var ones int
	if err != nil {
		ip = net.ParseIP(cidrStr)
		if ip == nil {
			return fmt.Errorf("invalid IP or CIDR: %s", cidrStr)
		}
		if ip4 := ip.To4(); ip4 != nil {
			ones = 32
		} else {
			ones = 128
		}
	} else {
		ones, _ = ipNet.Mask.Size()
	}

	if ip4 := ip.To4(); ip4 != nil {
		key := NetXfwLpmKey4{
			Prefixlen: uint32(ones),
			Data:      binary.BigEndian.Uint32(ip4),
		}
		return mapPtr.Delete(key)
	}

	var key NetXfwLpmKey6
	key.Prefixlen = uint32(ones)
	copy(key.Data.In6U.U6Addr8[:], ip.To16())
	return mapPtr.Delete(key)
}

/**
 * ListWhitelistedIPs iterates over the BPF whitelist map and returns limited allowed ranges.
 * ListWhitelistedIPs 遍历 BPF 白名单 Map 并返回有限数量的允许网段。
 */
func ListWhitelistedIPs(mapPtr *ebpf.Map, isIPv6 bool, limit int, search string) ([]string, int, error) {
	// Fast Path: Direct lookup if search is a valid CIDR or IP
	// 快路径：如果搜索内容是有效的 CIDR 或 IP，直接进行 Map 查找
	if search != "" {
		ip, ipNet, err := net.ParseCIDR(search)
		var ones int
		if err != nil {
			ip = net.ParseIP(search)
			if ip != nil {
				if ip.To4() != nil {
					ones = 32
				} else {
					ones = 128
				}
			}
		} else {
			ones, _ = ipNet.Mask.Size()
		}

		if ip != nil {
			// Perform direct lookup / 执行直接查找
			var val RuleValue
			found := false
			if ip4 := ip.To4(); ip4 != nil && !isIPv6 {
				key := NetXfwLpmKey4{Prefixlen: uint32(ones), Data: binary.BigEndian.Uint32(ip4)}
				if err := mapPtr.Lookup(key, &val); err == nil {
					found = true
				}
			} else if ip6 := ip.To16(); ip6 != nil && isIPv6 {
				var key NetXfwLpmKey6
				key.Prefixlen = uint32(ones)
				copy(key.Data.In6U.U6Addr8[:], ip6)
				if err := mapPtr.Lookup(key, &val); err == nil {
					found = true
				}
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

	var ips []string
	count := 0
	iter := mapPtr.Iterate()

	if isIPv6 {
		var key NetXfwLpmKey6
		var val RuleValue
		for iter.Next(&key, &val) {
			// Avoid expensive string formatting if possible
			// 尽可能避免昂贵的字符串格式化操作
			ip := net.IP(key.Data.In6U.U6Addr8[:])
			ipStr := ip.String()

			if search != "" && !strings.Contains(ipStr, search) {
				continue
			}

			count++
			fullStr := fmt.Sprintf("%s/%d", ipStr, key.Prefixlen)
			if val.Counter > 1 {
				fullStr = fmt.Sprintf("%s (port: %d)", fullStr, val.Counter)
			}
			ips = append(ips, fullStr)
			if limit > 0 && len(ips) >= limit {
				break
			}
		}
	} else {
		var key NetXfwLpmKey4
		var val RuleValue
		ipBuf := make(net.IP, 4)
		for iter.Next(&key, &val) {
			binary.BigEndian.PutUint32(ipBuf, key.Data)
			ipStr := ipBuf.String()

			if search != "" && !strings.Contains(ipStr, search) {
				continue
			}

			count++
			fullStr := fmt.Sprintf("%s/%d", ipStr, key.Prefixlen)
			if val.Counter > 1 {
				fullStr = fmt.Sprintf("%s (port: %d)", fullStr, val.Counter)
			}
			ips = append(ips, fullStr)
			if limit > 0 && len(ips) >= limit {
				break
			}
		}
	}

	return ips, count, iter.Err()
}

/**
 * CleanupExpiredRules iterates over the maps and removes expired entries.
 * Returns the number of removed entries.
 */
func CleanupExpiredRules(mapPtr *ebpf.Map, isIPv6 bool) (int, error) {
	now := uint64(time.Now().UnixNano())
	removed := 0
	iter := mapPtr.Iterate()

	if isIPv6 {
		var key NetXfwLpmKey6
		var val RuleValue
		for iter.Next(&key, &val) {
			if val.ExpiresAt > 0 && now > val.ExpiresAt {
				if err := mapPtr.Delete(key); err == nil {
					removed++
				}
			}
		}
	} else {
		var key NetXfwLpmKey4
		var val RuleValue
		for iter.Next(&key, &val) {
			if val.ExpiresAt > 0 && now > val.ExpiresAt {
				if err := mapPtr.Delete(key); err == nil {
					removed++
				}
			}
		}
	}

	return removed, iter.Err()
}

/**
 * ListBlockedIPs iterates over the BPF map and returns limited blocked ranges and stats.
 * ListBlockedIPs 遍历 BPF Map 并返回有限数量的封禁网段及其统计信息。
 */
func ListBlockedIPs(mapPtr *ebpf.Map, isIPv6 bool, limit int, search string) (map[string]uint64, int, error) {
	// Fast Path: Direct lookup if search is a valid CIDR or IP
	if search != "" {
		ip, ipNet, err := net.ParseCIDR(search)
		var ones int
		if err != nil {
			ip = net.ParseIP(search)
			if ip != nil {
				if ip.To4() != nil {
					ones = 32
				} else {
					ones = 128
				}
			}
		} else {
			ones, _ = ipNet.Mask.Size()
		}

		if ip != nil {
			var val RuleValue
			found := false
			if ip4 := ip.To4(); ip4 != nil && !isIPv6 {
				key := NetXfwLpmKey4{Prefixlen: uint32(ones), Data: binary.BigEndian.Uint32(ip4)}
				if err := mapPtr.Lookup(key, &val); err == nil {
					found = true
				}
			} else if ip6 := ip.To16(); ip6 != nil && isIPv6 {
				var key NetXfwLpmKey6
				key.Prefixlen = uint32(ones)
				copy(key.Data.In6U.U6Addr8[:], ip6)
				if err := mapPtr.Lookup(key, &val); err == nil {
					found = true
				}
			}

			if found {
				fullStr := fmt.Sprintf("%s/%d", ip.String(), ones)
				return map[string]uint64{fullStr: val.Counter}, 1, nil
			}
		}
	}

	ips := make(map[string]uint64)
	count := 0
	iter := mapPtr.Iterate()

	if isIPv6 {
		var key NetXfwLpmKey6
		var val RuleValue
		for iter.Next(&key, &val) {
			ip := net.IP(key.Data.In6U.U6Addr8[:])
			ipStr := ip.String()

			if search != "" && !strings.Contains(ipStr, search) {
				continue
			}

			count++
			fullStr := fmt.Sprintf("%s/%d", ipStr, key.Prefixlen)
			ips[fullStr] = val.Counter
			if limit > 0 && len(ips) >= limit {
				break
			}
		}
	} else {
		var key NetXfwLpmKey4
		var val RuleValue
		ipBuf := make(net.IP, 4)
		for iter.Next(&key, &val) {
			binary.BigEndian.PutUint32(ipBuf, key.Data)
			ipStr := ipBuf.String()

			if search != "" && !strings.Contains(ipStr, search) {
				continue
			}

			count++
			fullStr := fmt.Sprintf("%s/%d", ipStr, key.Prefixlen)
			ips[fullStr] = val.Counter
			if limit > 0 && len(ips) >= limit {
				break
			}
		}
	}

	return ips, count, iter.Err()
}
