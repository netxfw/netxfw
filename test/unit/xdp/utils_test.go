package xdp_test

import (
	"encoding/hex"
	"net"
	"testing"

	"github.com/livp123/netxfw/internal/xdp"
)

// TestNewLpmKey tests LPM key creation
// TestNewLpmKey 测试 LPM 键创建
func TestNewLpmKey(t *testing.T) {
	tests := []struct {
		name      string
		cidr      string
		wantLen   uint32
		wantBytes string // Last 4 bytes as hex string for simplicity
	}{
		{"IPv4 /24", "1.2.3.0/24", 120, "01020300"},  // 96 + 24 = 120
		{"IPv4 /16", "10.1.0.0/16", 112, "0a010000"}, // 96 + 16 = 112
		{"IPv4 /8", "10.0.0.0/8", 104, "0a000000"},   // 96 + 8 = 104
		{"IPv4 /32", "1.2.3.4", 128, "01020304"},     // 96 + 32 = 128
		{"IPv6 /64", "2001:db8::/64", 64, "00000000"},
		{"IPv6 /48", "2001:db8:cafe::/48", 48, "00000000"},
		{"IPv6 /32", "2001:db8::/32", 32, "00000000"},
		{"IPv6 /128", "::1", 128, "00000001"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := xdp.NewLpmKey(tt.cidr)
			if err != nil {
				t.Fatalf("NewLpmKey(%q) failed: %v", tt.cidr, err)
			}
			if key.Prefixlen != tt.wantLen {
				t.Errorf("NewLpmKey(%q) Prefixlen = %d, want %d", tt.cidr, key.Prefixlen, tt.wantLen)
			}

			// Check last 4 bytes for IPv4 conversion
			// 检查 IPv4 转换的最后 4 个字节
			data := key.Data.In6U.U6Addr8
			last4 := data[12:]
			if tt.wantLen > 64 && tt.wantLen < 129 && len(tt.wantBytes) == 8 {
				gotHex := hex.EncodeToString(last4)
				if gotHex != tt.wantBytes {
					t.Errorf("NewLpmKey(%q) last 4 bytes = %s, want %s", tt.cidr, gotHex, tt.wantBytes)
				}
			}

			// Check IPv4-mapped prefix
			// Only for IPv4 addresses (determined by checking if input is IPv4)
			// 检查 IPv4 映射前缀
			// 仅适用于 IPv4 地址（通过检查输入是否为 IPv4 来确定）
			isIPv4 := false
			if net.ParseIP(tt.cidr) != nil {
				isIPv4 = net.ParseIP(tt.cidr).To4() != nil
			} else {
				// Try parsing as CIDR
				// 尝试解析为 CIDR
				ip, _, _ := net.ParseCIDR(tt.cidr)
				isIPv4 = ip.To4() != nil
			}

			if isIPv4 {
				if data[10] != 0xff || data[11] != 0xff {
					t.Errorf("NewLpmKey(%q) missing IPv4-mapped prefix ::ffff:...", tt.cidr)
				}
			}
		})
	}
}

// TestNewLpmIpPortKey tests LPM IP port key creation
// TestNewLpmIpPortKey 测试 LPM IP 端口键创建
func TestNewLpmIpPortKey(t *testing.T) {
	tests := []struct {
		name     string
		cidr     string
		port     uint16
		wantLen  uint32
		wantPort uint16
	}{
		{"IPv4 Port", "1.2.3.4", 80, 128, 80},
		{"IPv6 Port", "::1", 443, 128, 443},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := xdp.NewLpmIpPortKey(tt.cidr, tt.port)
			if err != nil {
				t.Fatalf("NewLpmIpPortKey(%q) failed: %v", tt.cidr, err)
			}
			if key.Prefixlen != tt.wantLen {
				t.Errorf("NewLpmIpPortKey(%q) Prefixlen = %d, want %d", tt.cidr, key.Prefixlen, tt.wantLen)
			}
			if key.Port != tt.wantPort {
				t.Errorf("NewLpmIpPortKey(%q) Port = %d, want %d", tt.cidr, key.Port, tt.wantPort)
			}
		})
	}
}
