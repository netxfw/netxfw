package unit

import (
	"testing"

	"github.com/livp123/netxfw/internal/utils/iputil"
)

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

func TestParseIPPort(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantIP   string
		wantPort uint16
		wantErr  bool
	}{
		{"IPv4 with Port", "1.2.3.4:80", "1.2.3.4", 80, false},
		{"IPv6 with Port", "[::1]:8080", "::1", 8080, false},
		{"IPv4 without Port", "1.2.3.4", "", 0, true}, // Function expects ip:port
		{"Invalid Port", "1.2.3.4:99999", "", 0, true},
		{"Invalid IP", "999.9.9.9:80", "", 0, true},
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

func TestIsIPv6(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"1.2.3.4", false},
		{"192.168.0.0/24", false},
		{"::1", true},
		{"2001:db8::/32", true},
	}
	for _, tt := range tests {
		if got := iputil.IsIPv6(tt.input); got != tt.want {
			t.Errorf("IsIPv6(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestNormalizeCIDR(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"1.2.3.4", "1.2.3.4/32"},
		{"1.2.3.4/32", "1.2.3.4/32"},
		{"192.168.1.1/24", "192.168.1.0/24"}, // Canonicalization
		{"::1", "::1/128"},
		{"invalid", "invalid"},
	}
	for _, tt := range tests {
		if got := iputil.NormalizeCIDR(tt.input); got != tt.want {
			t.Errorf("NormalizeCIDR(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}
