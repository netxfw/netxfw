package logengine

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestIPExtractor_ExtractIPs tests ExtractIPs method
// TestIPExtractor_ExtractIPs 测试 ExtractIPs 方法
func TestIPExtractor_ExtractIPs(t *testing.T) {
	extractor := NewIPExtractor()

	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{
			name:     "Single IPv4",
			input:    "192.168.1.1",
			expected: 1,
		},
		{
			name:     "Multiple IPv4",
			input:    "192.168.1.1 and 10.0.0.1",
			expected: 2,
		},
		{
			name:     "IPv6 address",
			input:    "2001:db8::1",
			expected: 1,
		},
		{
			name:     "Mixed IPv4 and IPv6",
			input:    "192.168.1.1 and 2001:db8::1",
			expected: 2,
		},
		{
			name:     "No IP",
			input:    "hello world",
			expected: 0,
		},
		{
			name:     "Duplicate IPs",
			input:    "192.168.1.1 and 192.168.1.1",
			expected: 1,
		},
		{
			name:     "Invalid IP",
			input:    "999.999.999.999",
			expected: 0,
		},
		{
			name:     "IP with port (not extracted as single IP)",
			input:    "192.168.1.1:8080",
			expected: 0,
		},
		{
			name:     "IP with port separated",
			input:    "192.168.1.1 :8080",
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ips := extractor.ExtractIPs(tt.input)
			assert.Equal(t, tt.expected, len(ips))
		})
	}
}

// TestIPExtractor_ExtractIPsWithBuf tests ExtractIPsWithBuf method
// TestIPExtractor_ExtractIPsWithBuf 测试 ExtractIPsWithBuf 方法
func TestIPExtractor_ExtractIPsWithBuf(t *testing.T) {
	extractor := NewIPExtractor()

	t.Run("With buffer", func(t *testing.T) {
		buf := make([]netip.Addr, 10)
		ips := extractor.ExtractIPsWithBuf("192.168.1.1", buf)
		assert.Equal(t, 1, len(ips))
		assert.Equal(t, "192.168.1.1", ips[0].String())
	})

	t.Run("With nil buffer", func(t *testing.T) {
		ips := extractor.ExtractIPsWithBuf("192.168.1.1", nil)
		assert.Equal(t, 1, len(ips))
		assert.Equal(t, "192.168.1.1", ips[0].String())
	})

	t.Run("Multiple IPs with buffer", func(t *testing.T) {
		buf := make([]netip.Addr, 10)
		ips := extractor.ExtractIPsWithBuf("192.168.1.1 10.0.0.1 172.16.0.1", buf)
		assert.Equal(t, 3, len(ips))
	})
}

// TestIsIPChar tests isIPChar function
// TestIsIPChar 测试 isIPChar 函数
func TestIsIPChar(t *testing.T) {
	tests := []struct {
		char     byte
		expected bool
	}{
		{'0', true},
		{'9', true},
		{'a', true},
		{'f', true},
		{'A', true},
		{'F', true},
		{'.', true},
		{':', true},
		{'g', false},
		{'z', false},
		{' ', false},
		{'-', false},
	}

	for _, tt := range tests {
		t.Run(string(tt.char), func(t *testing.T) {
			result := isIPChar(tt.char)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestUniqueIPs tests uniqueIPs function
// TestUniqueIPs 测试 uniqueIPs 函数
func TestUniqueIPs(t *testing.T) {
	ip1, _ := netip.ParseAddr("192.168.1.1")
	ip2, _ := netip.ParseAddr("10.0.0.1")
	ip3, _ := netip.ParseAddr("172.16.0.1")

	tests := []struct {
		name     string
		input    []netip.Addr
		expected int
	}{
		{
			name:     "Empty slice",
			input:    []netip.Addr{},
			expected: 0,
		},
		{
			name:     "Single IP",
			input:    []netip.Addr{ip1},
			expected: 1,
		},
		{
			name:     "Duplicate IPs",
			input:    []netip.Addr{ip1, ip1, ip1},
			expected: 1,
		},
		{
			name:     "Mixed unique and duplicate",
			input:    []netip.Addr{ip1, ip2, ip1, ip3, ip2},
			expected: 3,
		},
		{
			name:     "All unique",
			input:    []netip.Addr{ip1, ip2, ip3},
			expected: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := uniqueIPs(tt.input)
			assert.Equal(t, tt.expected, len(result))
		})
	}
}

// TestIPExtractor_RealWorldScenarios tests real-world log scenarios
// TestIPExtractor_RealWorldScenarios 测试真实日志场景
func TestIPExtractor_RealWorldScenarios(t *testing.T) {
	extractor := NewIPExtractor()

	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{
			name:     "Apache log format",
			input:    `192.168.1.1 - - [10/Oct/2023:13:55:36 +0000] "GET / HTTP/1.1" 200 1234`,
			expected: 1,
		},
		{
			name:     "Nginx log format",
			input:    `10.0.0.1 - - [10/Oct/2023:13:55:36 +0000] "POST /api HTTP/1.1" 404 567`,
			expected: 1,
		},
		{
			name:     "Multiple IPs in log",
			input:    `Connection from 192.168.1.1 to 10.0.0.1 port 8080`,
			expected: 2,
		},
		{
			name:     "IPv6 in brackets",
			input:    `[2001:db8::1] - - [10/Oct/2023:13:55:36 +0000] "GET / HTTP/1.1" 200`,
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ips := extractor.ExtractIPs(tt.input)
			assert.Equal(t, tt.expected, len(ips))
		})
	}
}
