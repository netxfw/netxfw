package xdp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestIsIPv6 tests the IsIPv6 function
// TestIsIPv6 测试 IsIPv6 函数
func TestIsIPv6(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"IPv4 address", "192.168.1.1", false},
		{"IPv4 CIDR", "192.168.1.0/24", false},
		{"IPv6 address", "2001:db8::1", true},
		{"IPv6 CIDR", "2001:db8::/32", true},
		{"IPv6 loopback", "::1", true},
		{"IPv6 full", "2001:0db8:0000:0000:0000:0000:0000:0001", true},
		{"IPv6 link-local", "fe80::1", true},
		{"Invalid", "invalid", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsIPv6(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
