package xdp

import (
	"fmt"
	"net"

	"github.com/livp123/netxfw/internal/utils/iputil"
)

// NewLpmKey creates a NetXfwLpmKey from a CIDR string.
// NewLpmKey 从 CIDR 字符串创建一个 NetXfwLpmKey。
func NewLpmKey(cidr string) (NetXfwLpmKey, error) {
	ipNet, err := iputil.ParseCIDR(cidr)
	if err != nil {
		return NetXfwLpmKey{}, err
	}
	ip := ipNet.IP

	ones, _ := ipNet.Mask.Size()
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

	return key, nil
}

// NewLpmIpPortKey creates a NetXfwLpmIpPortKey from a CIDR string and port.
// NewLpmIpPortKey 从 CIDR 字符串和端口创建一个 NetXfwLpmIpPortKey。
func NewLpmIpPortKey(cidr string, port uint16) (NetXfwLpmIpPortKey, error) {
	ipNet, err := iputil.ParseCIDR(cidr)
	if err != nil {
		return NetXfwLpmIpPortKey{}, err
	}
	ip := ipNet.IP

	ones, _ := ipNet.Mask.Size()
	var key NetXfwLpmIpPortKey
	key.Port = port

	if ip4 := ip.To4(); ip4 != nil {
		key.Prefixlen = uint32(96 + ones)
		key.Ip.In6U.U6Addr8[10] = 0xff
		key.Ip.In6U.U6Addr8[11] = 0xff
		copy(key.Ip.In6U.U6Addr8[12:], ip4)
	} else {
		key.Prefixlen = uint32(ones)
		copy(key.Ip.In6U.U6Addr8[:], ip.To16())
	}

	return key, nil
}

// FormatIn6Addr formats the unified IPv6 address to string
// FormatIn6Addr 将统一的 IPv6 地址格式化为字符串
func FormatIn6Addr(in6 *NetXfwIn6Addr) string {
	// Check for IPv4-mapped / 检查是否为 IPv4 映射
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
// FormatLpmKey 将统一的 LPM 键格式化为 CIDR 字符串
func FormatLpmKey(key *NetXfwLpmKey) string {
	ipStr := FormatIn6Addr(&key.Data)
	// Adjust prefix len / 调整前缀长度
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

// NewIPv6Key creates a NetXfwIn6Addr from an IP string (IPv4 or IPv6).
// IPv4 addresses are converted to IPv4-mapped IPv6 addresses.
// NewIPv6Key 从 IP 字符串（IPv4 或 IPv6）创建一个 NetXfwIn6Addr。
// IPv4 地址被转换为 IPv4 映射的 IPv6 地址。
func NewIPv6Key(ipStr string) (NetXfwIn6Addr, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return NetXfwIn6Addr{}, fmt.Errorf("invalid IP address: %s", ipStr)
	}

	var key NetXfwIn6Addr

	if ip4 := ip.To4(); ip4 != nil {
		// IPv4-mapped IPv6 address: ::ffff:a.b.c.d
		// IPv4 映射的 IPv6 地址：::ffff:a.b.c.d
		key.In6U.U6Addr8[10] = 0xff
		key.In6U.U6Addr8[11] = 0xff
		copy(key.In6U.U6Addr8[12:], ip4)
	} else {
		// Native IPv6 address
		// 原生 IPv6 地址
		copy(key.In6U.U6Addr8[:], ip.To16())
	}

	return key, nil
}
