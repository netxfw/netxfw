package xdp

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/netxfw/netxfw/internal/utils/iputil"
)

// IPToIn6Addr converts a net.IP to NetXfwIn6Addr.
// IPv4 addresses are converted to IPv4-mapped IPv6 addresses (::ffff:a.b.c.d).
// IPToIn6Addr 将 net.IP 转换为 NetXfwIn6Addr。
// IPv4 地址被转换为 IPv4 映射的 IPv6 地址 (::ffff:a.b.c.d)。
func IPToIn6Addr(ip net.IP) NetXfwIn6Addr {
	var key NetXfwIn6Addr
	if ip4 := ip.To4(); ip4 != nil {
		key.In6U.U6Addr8[10] = 0xff
		key.In6U.U6Addr8[11] = 0xff
		copy(key.In6U.U6Addr8[12:], ip4)
	} else {
		copy(key.In6U.U6Addr8[:], ip.To16())
	}
	return key
}

// NetipAddrToIn6Addr converts a netip.Addr to NetXfwIn6Addr.
// IPv4 addresses are converted to IPv4-mapped IPv6 addresses.
// NetipAddrToIn6Addr 将 netip.Addr 转换为 NetXfwIn6Addr。
// IPv4 地址被转换为 IPv4 映射的 IPv6 地址。
func NetipAddrToIn6Addr(addr netip.Addr) NetXfwIn6Addr {
	var key NetXfwIn6Addr
	if addr.Is4() {
		b := addr.As4()
		key.In6U.U6Addr8[10] = 0xff
		key.In6U.U6Addr8[11] = 0xff
		copy(key.In6U.U6Addr8[12:], b[:])
	} else {
		b := addr.As16()
		copy(key.In6U.U6Addr8[:], b[:])
	}
	return key
}

// IPNetToLpmKey creates a NetXfwLpmKey from a net.IPNet.
// IPNetToLpmKey 从 net.IPNet 创建一个 NetXfwLpmKey。
func IPNetToLpmKey(ipNet *net.IPNet) NetXfwLpmKey {
	ones, _ := ipNet.Mask.Size()
	var key NetXfwLpmKey
	key.Prefixlen = uint32(ones) // #nosec G115 // prefixlen is always 0-128
	key.Data = IPToIn6Addr(ipNet.IP)

	if ipNet.IP.To4() != nil {
		key.Prefixlen = uint32(96 + ones) // #nosec G115 // prefixlen is always 0-128
	}
	return key
}

// IPNetToLpmIPPortKey creates a NetXfwLpmIpPortKey from a net.IPNet and port.
// IPNetToLpmIPPortKey 从 net.IPNet 和端口创建一个 NetXfwLpmIpPortKey。
func IPNetToLpmIPPortKey(ipNet *net.IPNet, port uint16) NetXfwLpmIpPortKey {
	ones, _ := ipNet.Mask.Size()
	var key NetXfwLpmIpPortKey
	key.Port = port
	key.Pad = 0
	key.Ip = IPToIn6Addr(ipNet.IP)

	// Prefixlen must account for Pad (16 bits) and Port (16 bits) which precede the IP in the key structure.
	// Prefixlen 必须包含键结构中位于 IP 之前的填充 (16 位) 和端口 (16 位)。
	const keyHeaderLen = 32

	if ipNet.IP.To4() != nil {
		key.Prefixlen = uint32(keyHeaderLen + 96 + ones) // #nosec G115 // prefixlen is always 0-160
	} else {
		key.Prefixlen = uint32(keyHeaderLen + ones) // #nosec G115 // prefixlen is always 0-160
	}
	return key
}

// IsIPv4Mapped checks if a NetXfwIn6Addr is an IPv4-mapped IPv6 address.
// IsIPv4Mapped 检查 NetXfwIn6Addr 是否为 IPv4 映射的 IPv6 地址。
func IsIPv4Mapped(in6 *NetXfwIn6Addr) bool {
	for i := 0; i < 10; i++ {
		if in6.In6U.U6Addr8[i] != 0 {
			return false
		}
	}
	return in6.In6U.U6Addr8[10] == 0xff && in6.In6U.U6Addr8[11] == 0xff
}

// ExtractIPv4 extracts the IPv4 address from an IPv4-mapped IPv6 address.
// Returns nil if not an IPv4-mapped address.
// ExtractIPv4 从 IPv4 映射的 IPv6 地址中提取 IPv4 地址。
// 如果不是 IPv4 映射地址则返回 nil。
func ExtractIPv4(in6 *NetXfwIn6Addr) net.IP {
	if !IsIPv4Mapped(in6) {
		return nil
	}
	return net.IPv4(
		in6.In6U.U6Addr8[12],
		in6.In6U.U6Addr8[13],
		in6.In6U.U6Addr8[14],
		in6.In6U.U6Addr8[15],
	)
}

// AdjustPrefixLen adjusts the prefix length for IPv4-mapped addresses.
// For IPv4-mapped addresses, subtracts 96 from the prefix length.
// AdjustPrefixLen 调整 IPv4 映射地址的前缀长度。
// 对于 IPv4 映射地址，从 prefixlen 中减去 96。
func AdjustPrefixLen(in6 *NetXfwIn6Addr, prefixLen uint32) uint32 {
	if IsIPv4Mapped(in6) && prefixLen >= 96 {
		return prefixLen - 96
	}
	return prefixLen
}

// NewLpmKey creates a NetXfwLpmKey from a CIDR string.
// NewLpmKey 从 CIDR 字符串创建一个 NetXfwLpmKey。
func NewLpmKey(cidr string) (NetXfwLpmKey, error) {
	ipNet, err := iputil.ParseCIDR(cidr)
	if err != nil {
		return NetXfwLpmKey{}, err
	}
	return IPNetToLpmKey(ipNet), nil
}

// NewLpmIPPortKey creates a NetXfwLpmIpPortKey from a CIDR string and port.
// NewLpmIPPortKey 从 CIDR 字符串和端口创建一个 NetXfwLpmIpPortKey。
func NewLpmIPPortKey(cidr string, port uint16) (NetXfwLpmIpPortKey, error) {
	ipNet, err := iputil.ParseCIDR(cidr)
	if err != nil {
		return NetXfwLpmIpPortKey{}, err
	}
	return IPNetToLpmIPPortKey(ipNet, port), nil
}

// FormatIn6Addr formats the unified IPv6 address to string.
// FormatIn6Addr 将统一的 IPv6 地址格式化为字符串。
func FormatIn6Addr(in6 *NetXfwIn6Addr) string {
	if ip4 := ExtractIPv4(in6); ip4 != nil {
		return ip4.String()
	}
	ip := net.IP(in6.In6U.U6Addr8[:])
	return ip.String()
}

// FormatLpmKey formats the unified LPM key to CIDR string.
// FormatLpmKey 将统一的 LPM 键格式化为 CIDR 字符串。
func FormatLpmKey(key *NetXfwLpmKey) string {
	ipStr := FormatIn6Addr(&key.Data)
	prefixLen := AdjustPrefixLen(&key.Data, key.Prefixlen)
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
	return IPToIn6Addr(ip), nil
}
