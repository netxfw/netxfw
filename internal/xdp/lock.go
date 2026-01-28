// internal/xdp/lock.go
package xdp

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/cilium/ebpf"
)

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
 * LockIP adds an IPv4 or IPv6 address or CIDR to the BPF lock list.
 * LockIP 将 IPv4/IPv6 地址或 CIDR 网段添加到 BPF 锁定列表中。
 */
func LockIP(mapPtr *ebpf.Map, cidrStr string, expiresAt *time.Time) error {
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

	val := RuleValue{
		Counter:   0,
		ExpiresAt: timeToBootNS(expiresAt),
	}
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
 * AllowIP 将 IPv4/IPv6 地址或 CIDR 网段添加到 BPF 白名单中。
 */
func AllowIP(mapPtr *ebpf.Map, cidrStr string, expiresAt *time.Time) error {
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

	val := RuleValue{
		Counter:   1,
		ExpiresAt: timeToBootNS(expiresAt),
	}
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
 * ListWhitelistedIPs iterates over the BPF whitelist map and returns all allowed ranges.
 * ListWhitelistedIPs 遍历 BPF 白名单 Map 并返回所有允许的网段。
 */
func ListWhitelistedIPs(mapPtr *ebpf.Map, isIPv6 bool) ([]string, error) {
	var ips []string

	iter := mapPtr.Iterate()
	if isIPv6 {
		var key NetXfwLpmKey6
		var val RuleValue
		for iter.Next(&key, &val) {
			ip := net.IP(key.Data.In6U.U6Addr8[:]).String()
			ips = append(ips, fmt.Sprintf("%s/%d", ip, key.Prefixlen))
		}
	} else {
		var key NetXfwLpmKey4
		var val RuleValue
		for iter.Next(&key, &val) {
			ip := make(net.IP, 4)
			binary.BigEndian.PutUint32(ip, key.Data)
			ips = append(ips, fmt.Sprintf("%s/%d", ip, key.Prefixlen))
		}
	}

	return ips, iter.Err()
}

/**
 * ListBlockedIPs iterates over the BPF map and returns all blocked ranges and stats.
 * ListBlockedIPs 遍历 BPF Map 并返回所有封禁的网段及其统计信息。
 */
func ListBlockedIPs(mapPtr *ebpf.Map, isIPv6 bool) (map[string]uint64, error) {
	ips := make(map[string]uint64)

	iter := mapPtr.Iterate()
	if isIPv6 {
		var key NetXfwLpmKey6
		var val RuleValue
		for iter.Next(&key, &val) {
			ip := net.IP(key.Data.In6U.U6Addr8[:]).String()
			ips[fmt.Sprintf("%s/%d", ip, key.Prefixlen)] = val.Counter
		}
	} else {
		var key NetXfwLpmKey4
		var val RuleValue
		for iter.Next(&key, &val) {
			ip := make(net.IP, 4)
			binary.BigEndian.PutUint32(ip, key.Data)
			ips[fmt.Sprintf("%s/%d", ip, key.Prefixlen)] = val.Counter
		}
	}

	return ips, iter.Err()
}
