package xdp

import (
	"encoding/binary"
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
	ip4 := ipNet.IP.To4()
	if ip4 != nil {
		key := NetXfwLpmIp4PortKey{
			Prefixlen: uint32(32 + ones),
			Port:      port,
			Pad:       0,
			Ip:        binary.LittleEndian.Uint32(ip4),
		}
		return m.Update(key, val, ebpf.UpdateAny)
	}

	ip6 := ipNet.IP.To16()
	if ip6 != nil {
		key := NetXfwLpmIp6PortKey{
			Port: port,
			Pad:  0,
		}
		copy(key.Ip.In6U.U6Addr8[:], ip6)
		key.Prefixlen = uint32(32 + ones)
		return m.Update(key, val, ebpf.UpdateAny)
	}

	return fmt.Errorf("invalid IP address")
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
	ip4 := ipNet.IP.To4()
	if ip4 != nil {
		key := NetXfwLpmIp4PortKey{
			Prefixlen: uint32(32 + ones),
			Port:      port,
			Pad:       0,
			Ip:        binary.LittleEndian.Uint32(ip4),
		}
		return m.Delete(key)
	}

	ip6 := ipNet.IP.To16()
	if ip6 != nil {
		key := NetXfwLpmIp6PortKey{
			Prefixlen: uint32(32 + ones),
			Port:      port,
			Pad:       0,
		}
		copy(key.Ip.In6U.U6Addr8[:], ip6)
		return m.Delete(key)
	}

	return fmt.Errorf("invalid IP address")
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

	if ip4 := ip.To4(); ip4 != nil {
		key := NetXfwLpmKey4{
			Prefixlen: uint32(ones),
			Data:      binary.LittleEndian.Uint32(ip4),
		}
		return m.Update(key, val, ebpf.UpdateAny)
	} else {
		key := NetXfwLpmKey6{
			Prefixlen: uint32(ones),
			Data:      NetXfwIn6Addr{},
		}
		copy(key.Data.In6U.U6Addr8[:], ip.To16())
		return m.Update(key, val, ebpf.UpdateAny)
	}
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

	if ip4 := ip.To4(); ip4 != nil {
		key := NetXfwLpmKey4{
			Prefixlen: uint32(ones),
			Data:      binary.LittleEndian.Uint32(ip4),
		}
		return m.Delete(key)
	} else {
		key := NetXfwLpmKey6{
			Prefixlen: uint32(ones),
			Data:      NetXfwIn6Addr{},
		}
		copy(key.Data.In6U.U6Addr8[:], ip.To16())
		return m.Delete(key)
	}
}
