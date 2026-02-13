package xdp

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf"
)

// Helper functions for updating maps directly (for one-shot tools)

// AddIPPortRule adds a rule for a specific IP and Port combination to a given map
func AddIPPortRule(m *ebpf.Map, ipStr string, port uint16, action uint8) error {
	ip := net.ParseIP(ipStr)
	var ipNet *net.IPNet
	if ip == nil {
		var err error
		_, ipNet, err = net.ParseCIDR(ipStr)
		if err != nil {
			return fmt.Errorf("invalid IP or CIDR: %s", ipStr)
		}
	} else {
		mask := net.CIDRMask(32, 32)
		if ip.To4() == nil {
			mask = net.CIDRMask(128, 128)
		}
		ipNet = &net.IPNet{IP: ip, Mask: mask}
	}

	val := NetXfwRuleValue{
		Counter:   uint64(action),
		ExpiresAt: 0,
	}

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

	return m.Update(&key, &val, ebpf.UpdateAny)
}

// FormatIn6Addr formats the unified IPv6 address to string
func FormatIn6Addr(in6 *NetXfwIn6Addr) string {
	// Check for IPv4-mapped
	isIPv4Mapped := true
	for i := 0; i < 10; i++ {
		if in6.In6U.U6Addr8[i] != 0 {
			isIPv4Mapped = false
			break
		}
	}
	if isIPv4Mapped && in6.In6U.U6Addr8[10] == 0xff && in6.In6U.U6Addr8[11] == 0xff {
		ip := net.IPv4(
			in6.In6U.U6Addr8[12],
			in6.In6U.U6Addr8[13],
			in6.In6U.U6Addr8[14],
			in6.In6U.U6Addr8[15],
		)
		return ip.String()
	}
	ip := net.IP(in6.In6U.U6Addr8[:])
	return ip.String()
}

// FormatLpmKey formats the unified LPM key to CIDR string
func FormatLpmKey(key *NetXfwLpmKey) string {
	ipStr := FormatIn6Addr(&key.Data)
	// Adjust prefix len
	prefixLen := key.Prefixlen
	isIPv4Mapped := true
	for i := 0; i < 10; i++ {
		if key.Data.In6U.U6Addr8[i] != 0 {
			isIPv4Mapped = false
			break
		}
	}
	if isIPv4Mapped && key.Data.In6U.U6Addr8[10] == 0xff && key.Data.In6U.U6Addr8[11] == 0xff {
		if prefixLen >= 96 {
			prefixLen -= 96
		}
	}
	return fmt.Sprintf("%s/%d", ipStr, prefixLen)
}

// RemoveIPPortRule removes a rule for a specific IP and Port combination
func RemoveIPPortRule(m *ebpf.Map, ipStr string, port uint16) error {
	ip := net.ParseIP(ipStr)
	var ipNet *net.IPNet
	if ip == nil {
		var err error
		_, ipNet, err = net.ParseCIDR(ipStr)
		if err != nil {
			return fmt.Errorf("invalid IP or CIDR: %s", ipStr)
		}
	} else {
		mask := net.CIDRMask(32, 32)
		if ip.To4() == nil {
			mask = net.CIDRMask(128, 128)
		}
		ipNet = &net.IPNet{IP: ip, Mask: mask}
	}

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

	return m.Delete(&key)
}

// AllowPort adds a port to the allowed ports list
func AllowPort(m *ebpf.Map, port uint16) error {
	// BPF_MAP_TYPE_PERCPU_HASH requires a slice of values
	numCPU, err := ebpf.PossibleCPU()
	if err != nil {
		return fmt.Errorf("get possible CPUs: %w", err)
	}
	val := NetXfwRuleValue{
		Counter:   1,
		ExpiresAt: 0,
	}
	vals := make([]NetXfwRuleValue, numCPU)
	for i := 0; i < numCPU; i++ {
		vals[i] = val
	}
	return m.Update(&port, vals, ebpf.UpdateAny)
}

// RemoveAllowedPort removes a port from the allowed ports list
func RemoveAllowedPort(m *ebpf.Map, port uint16) error {
	return m.Delete(&port)
}

// AddRateLimitRule adds a rate limit rule
func AddRateLimitRule(m *ebpf.Map, cidrStr string, rate, burst uint64) error {
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

	val := NetXfwRatelimitConf{
		Rate:  rate,
		Burst: burst,
	}

	var key NetXfwLpmKey
	if ip4 := ip.To4(); ip4 != nil {
		key.Prefixlen = uint32(96 + ones)
		key.Data.In6U.U6Addr8[10] = 0xff
		key.Data.In6U.U6Addr8[11] = 0xff
		copy(key.Data.In6U.U6Addr8[12:], ip4)
	} else {
		key.Prefixlen = uint32(ones)
		copy(key.Data.In6U.U6Addr8[:], ip.To16())
	}

	return m.Update(&key, &val, ebpf.UpdateAny)
}

// RemoveRateLimitRule removes a rate limit rule
func RemoveRateLimitRule(m *ebpf.Map, cidrStr string) error {
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

	var key NetXfwLpmKey
	if ip4 := ip.To4(); ip4 != nil {
		key.Prefixlen = uint32(96 + ones)
		key.Data.In6U.U6Addr8[10] = 0xff
		key.Data.In6U.U6Addr8[11] = 0xff
		copy(key.Data.In6U.U6Addr8[12:], ip4)
	} else {
		key.Prefixlen = uint32(ones)
		copy(key.Data.In6U.U6Addr8[:], ip.To16())
	}

	return m.Delete(&key)
}
