package utils

import (
	"testing"

	"github.com/netxfw/netxfw/internal/utils/iputil"
)

// TestParseCIDR tests CIDR parsing
// TestParseCIDR 测试 CIDR 解析
func TestParseCIDR(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantIP  string
		wantErr bool
	}{
		{"Valid IPv4 CIDR", "192.168.1.0/24", "192.168.1.0", false},
		{"Valid IPv4 CIDR /16", "10.1.0.0/16", "10.1.0.0", false},
		{"Valid IPv4 CIDR /8", "10.0.0.0/8", "10.0.0.0", false},
		{"Valid IPv4 Single", "1.2.3.4", "1.2.3.4", false},
		{"Valid IPv6 CIDR", "2001:db8::/32", "2001:db8::", false},
		{"Valid IPv6 CIDR /48", "2001:db8:cafe::/48", "2001:db8:cafe::", false},
		{"Valid IPv6 Single", "2001:db8::1", "2001:db8::1", false},
		{"Invalid IP", "999.999.999.999", "", true},
		{"Invalid CIDR", "1.2.3.4/500", "", true},
		{"Empty", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ipNet, err := iputil.ParseCIDR(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCIDR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if ipNet.IP.String() != tt.wantIP {
					t.Errorf("ParseCIDR() IP = %v, want %v", ipNet.IP.String(), tt.wantIP)
				}
				// Verify mask implied by single IP
				// 验证单个 IP 隐含的掩码
				if tt.input == "1.2.3.4" {
					ones, _ := ipNet.Mask.Size()
					if ones != 32 {
						t.Errorf("ParseCIDR() single IPv4 mask size = %d, want 32", ones)
					}
				}
			}
		})
	}
}

// TestParseIPPort tests IP port parsing
// TestParseIPPort 测试 IP 端口解析
func TestParseIPPort(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantIP   string
		wantPort uint16
		wantErr  bool
	}{
		{"IPv4 with Port", "192.168.1.1:8080", "192.168.1.1", 8080, false},
		{"IPv6 with Port", "[::1]:8080", "::1", 8080, false},
		{"Invalid Port", "192.168.1.1:abc", "", 0, true},
		{"Invalid IP", "999.999.999.999:80", "", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, port, err := iputil.ParseIPPort(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseIPPort() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if ip != tt.wantIP {
					t.Errorf("ParseIPPort() IP = %v, want %v", ip, tt.wantIP)
				}
				if port != tt.wantPort {
					t.Errorf("ParseIPPort() Port = %v, want %v", port, tt.wantPort)
				}
			}
		})
	}
}

// TestIsIPv6 tests IPv6 detection
// TestIsIPv6 测试 IPv6 检测
func TestIsIPv6(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"IPv4", "192.168.1.1", false},
		{"IPv6", "2001:db8::1", true},
		{"IPv6 Full", "2001:0db8:0000:0000:0000:0000:0000:0001", true},
		{"IPv6 Loopback", "::1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := iputil.IsIPv6(tt.input); got != tt.want {
				t.Errorf("IsIPv6() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestNormalizeCIDR tests CIDR normalization
// TestNormalizeCIDR 测试 CIDR 规范化
func TestNormalizeCIDR(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"IPv4 Single", "192.168.1.1", "192.168.1.1/32"},
		{"IPv4 CIDR", "192.168.1.0/24", "192.168.1.0/24"},
		{"IPv6 Single", "2001:db8::1", "2001:db8::1/128"},
		{"IPv6 CIDR", "2001:db8::/32", "2001:db8::/32"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := iputil.NormalizeCIDR(tt.input)
			if got != tt.want {
				t.Errorf("NormalizeCIDR() = %v, want %v", got, tt.want)
			}
		})
	}
}
