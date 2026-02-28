package iputil

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// IsIPv6 checks if the given IP string (or CIDR) is IPv6.
// IsIPv6 检查给定的 IP 字符串（或 CIDR）是否为 IPv6。
func IsIPv6(ipStr string) bool {
	ip, _, err := net.ParseCIDR(ipStr)
	if err != nil {
		ip = net.ParseIP(ipStr)
	}
	return ip != nil && ip.To4() == nil
}

// NormalizeCIDR ensures the IP string is in CIDR format.
// It parses the string to ensure it is a valid CIDR or IP.
// If it's a single IP, it appends /32 (IPv4) or /128 (IPv6).
// If it's already a CIDR, it returns the canonical form (e.g. 1.2.3.4/32 -> 1.2.3.4/32).
// Returns the original string if parsing fails.
// NormalizeCIDR 确保 IP 字符串采用 CIDR 格式。
// 它解析字符串以确保其为有效的 CIDR 或 IP。
// 如果是单个 IP，则追加 /32 (IPv4) 或 /128 (IPv6)。
// 如果已经是 CIDR，则返回规范形式（例如 1.2.3.4/32 -> 1.2.3.4/32）。
// 如果解析失败，则返回原始字符串。
func NormalizeCIDR(ipStr string) string {
	ipNet, err := ParseCIDR(ipStr)
	if err == nil {
		return ipNet.String()
	}
	return ipStr
}

// ParseCIDR parses a CIDR string or a single IP.
// If single IP, returns the corresponding /32 or /128 subnet.
// ParseCIDR 解析 CIDR 字符串或单个 IP。如果是单个 IP，则返回相应的 /32 或 /128 子网。
func ParseCIDR(s string) (*net.IPNet, error) {
	_, ipNet, err := net.ParseCIDR(s)
	if err == nil {
		return ipNet, nil
	}

	ip := net.ParseIP(s)
	if ip == nil {
		return nil, fmt.Errorf("invalid CIDR or IP")
	}

	maskBits := 32
	if ip.To4() == nil {
		maskBits = 128
	}
	return &net.IPNet{
		IP:   ip,
		Mask: net.CIDRMask(maskBits, maskBits),
	}, nil
}

// ParseIPPort parses an input string like "1.2.3.4:80" or "[::1]:80" into IP and port.
// ParseIPPort 将输入字符串（如 "1.2.3.4:80" 或 "[::1]:80"）解析为 IP 和端口。
func ParseIPPort(input string) (string, uint16, error) {
	// First check if it's an ip:port format with brackets (e.g., [::1]:80)
	// 首先检查是否是带方括号的 ip:port 格式（例如 [::1]:80）
	if strings.HasPrefix(input, "[") {
		closeBracket := strings.Index(input, "]")
		if closeBracket > 0 && closeBracket < len(input)-1 && input[closeBracket+1] == ':' {
			// It's [ipv6]:port format
			// 是 [ipv6]:port 格式
			ipPart := input[1:closeBracket]
			portStr := input[closeBracket+2:]

			port, err := strconv.Atoi(portStr)
			if err != nil {
				return "", 0, fmt.Errorf("invalid port: %w", err)
			}

			if port < 0 || port > 65535 {
				return "", 0, fmt.Errorf("port out of range: %d", port)
			}

			if !IsValidCIDR(ipPart) {
				return "", 0, fmt.Errorf("invalid IP address or CIDR: %s", ipPart)
			}

			return ipPart, uint16(port), nil // nolint:gosec // G115: port is always 0-65535
		}
	}

	// Try to parse as ip:port first (without brackets)
	// 首先尝试解析为 ip:port 格式（不带方括号）
	host, portStr, err := net.SplitHostPort(input)
	if err == nil {
		ip := host

		port, err := strconv.Atoi(portStr)
		if err != nil {
			return "", 0, fmt.Errorf("invalid port: %w", err)
		}

		if port < 0 || port > 65535 {
			return "", 0, fmt.Errorf("port out of range: %d", port)
		}

		if !IsValidCIDR(host) {
			return "", 0, fmt.Errorf("invalid IP address or CIDR: %s", host)
		}

		return ip, uint16(port), nil // nolint:gosec // G115: port is always 0-65535
	}

	// If ip:port parsing fails, try to parse as just IP
	// 如果 ip:port 解析失败，尝试解析为纯 IP
	// For pure IP validation, also remove brackets if present
	// 对于纯 IP 验证，如果有的话也移除方括号
	validateInput := input
	if strings.HasPrefix(input, "[") {
		closeBracket := strings.Index(input, "]")
		if closeBracket > 0 {
			validateInput = input[1:closeBracket]
		}
	}
	if IsValidCIDR(validateInput) {
		return validateInput, 0, nil
	}

	// Return the original error
	// 返回原始错误
	return "", 0, fmt.Errorf("invalid format, expected ip:port or ip")
}

// IsValidIP checks if the string is a valid IP address.
// IsValidIP 检查字符串是否为有效的 IP 地址。
func IsValidIP(s string) bool {
	return net.ParseIP(s) != nil
}

// IsValidCIDR checks if the string is a valid CIDR.
// IsValidCIDR 检查字符串是否为有效的 CIDR。
func IsValidCIDR(s string) bool {
	_, err := ParseCIDR(s)
	return err == nil
}
