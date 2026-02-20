package iputil

import (
	"net"
	"strings"
	"testing"
)

// FuzzParseCIDR tests ParseCIDR with random inputs
// FuzzParseCIDR 使用随机输入测试 ParseCIDR
func FuzzParseCIDR(f *testing.F) {
	// Add seed corpus
	// 添加种子语料库
	seedCorpus := []string{
		"192.168.1.1",
		"192.168.1.0/24",
		"10.0.0.1",
		"10.0.0.0/8",
		"172.16.0.1",
		"172.16.0.0/12",
		"::1",
		"2001:db8::1",
		"2001:db8::/32",
		"fe80::1",
		"fe80::/10",
		"0.0.0.0",
		"0.0.0.0/0",
		"::",
		"::/0",
		"255.255.255.255",
		"255.255.255.255/32",
		"",
		"invalid",
		"192.168.1.1/33",
		"192.168.1.1/-1",
		"192.168.1.1/abc",
	}

	for _, seed := range seedCorpus {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// ParseCIDR should not panic on any input
		// ParseCIDR 不应在任何输入上发生 panic
		ipNet, err := ParseCIDR(input)

		if err != nil {
			// If error, ipNet should be nil
			// 如果出错，ipNet 应为 nil
			if ipNet != nil {
				t.Errorf("ParseCIDR(%q) returned non-nil with error: %v", input, err)
			}
			return
		}

		// If no error, ipNet should be valid
		// 如果没有错误，ipNet 应有效
		if ipNet == nil {
			t.Errorf("ParseCIDR(%q) returned nil without error", input)
			return
		}

		// Verify the IP is valid
		// 验证 IP 有效
		if ipNet.IP == nil {
			t.Errorf("ParseCIDR(%q) returned nil IP", input)
			return
		}

		// Verify the mask is valid
		// 验证掩码有效
		if ipNet.Mask == nil {
			t.Errorf("ParseCIDR(%q) returned nil Mask", input)
			return
		}

		// Verify the result can be parsed again
		// 验证结果可以再次解析
		_, err = ParseCIDR(ipNet.String())
		if err != nil {
			t.Errorf("ParseCIDR(%q) result %q cannot be re-parsed: %v", input, ipNet.String(), err)
		}
	})
}

// FuzzNormalizeCIDR tests NormalizeCIDR with random inputs
// FuzzNormalizeCIDR 使用随机输入测试 NormalizeCIDR
func FuzzNormalizeCIDR(f *testing.F) {
	seedCorpus := []string{
		"192.168.1.1",
		"192.168.1.0/24",
		"10.0.0.1",
		"::1",
		"2001:db8::1",
		"invalid",
		"",
		"0.0.0.0",
		"255.255.255.255",
	}

	for _, seed := range seedCorpus {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// NormalizeCIDR should not panic on any input
		// NormalizeCIDR 不应在任何输入上发生 panic
		result := NormalizeCIDR(input)

		// Result should be a string (may be empty for invalid input)
		// 结果应为字符串（无效输入可能为空）
		_ = result
	})
}

// FuzzParseIPPort tests ParseIPPort with random inputs
// FuzzParseIPPort 使用随机输入测试 ParseIPPort
func FuzzParseIPPort(f *testing.F) {
	seedCorpus := []string{
		"192.168.1.1:80",
		"192.168.1.1:443",
		"[::1]:80",
		"[2001:db8::1]:443",
		"10.0.0.1:0",
		"10.0.0.1:65535",
		"invalid",
		"",
		"192.168.1.1",
		":80",
		"192.168.1.1:-1",
		"192.168.1.1:65536",
		"192.168.1.1:abc",
		"192.168.1.1:999999",
	}

	for _, seed := range seedCorpus {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// ParseIPPort should not panic on any input
		// ParseIPPort 不应在任何输入上发生 panic
		ip, port, err := ParseIPPort(input)

		if err != nil {
			// If error, ip and port should be zero values
			// 如果出错，ip 和 port 应为零值
			if ip != "" || port != 0 {
				t.Errorf("ParseIPPort(%q) returned non-zero values with error: ip=%q, port=%d, err=%v", input, ip, port, err)
			}
			return
		}

		// If no error, ip and port should be valid
		// 如果没有错误，ip 和 port 应有效
		if ip == "" {
			t.Errorf("ParseIPPort(%q) returned empty IP without error", input)
			return
		}

		// Port should be in valid range (uint16 max is 65535, so always valid)
		// 端口应在有效范围内（uint16 最大值为 65535，因此始终有效）
	})
}

// FuzzIsIPv6 tests IsIPv6 with random inputs
// FuzzIsIPv6 使用随机输入测试 IsIPv6
func FuzzIsIPv6(f *testing.F) {
	seedCorpus := []string{
		"192.168.1.1",
		"::1",
		"2001:db8::1",
		"fe80::1",
		"invalid",
		"",
		"0.0.0.0",
		"::",
	}

	for _, seed := range seedCorpus {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// IsIPv6 should not panic on any input
		// IsIPv6 不应在任何输入上发生 panic
		result := IsIPv6(input)

		// Result should be a boolean
		// 结果应为布尔值
		_ = result
	})
}

// FuzzIsValidIP tests IsValidIP with random inputs
// FuzzIsValidIP 使用随机输入测试 IsValidIP
func FuzzIsValidIP(f *testing.F) {
	seedCorpus := []string{
		"192.168.1.1",
		"10.0.0.1",
		"::1",
		"2001:db8::1",
		"invalid",
		"",
		"0.0.0.0",
		"255.255.255.255",
		"256.256.256.256",
	}

	for _, seed := range seedCorpus {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// IsValidIP should not panic on any input
		// IsValidIP 不应在任何输入上发生 panic
		result := IsValidIP(input)

		// Result should be a boolean
		// 结果应为布尔值
		_ = result
	})
}

// FuzzIsValidCIDR tests IsValidCIDR with random inputs
// FuzzIsValidCIDR 使用随机输入测试 IsValidCIDR
func FuzzIsValidCIDR(f *testing.F) {
	seedCorpus := []string{
		"192.168.1.1",
		"192.168.1.0/24",
		"10.0.0.1",
		"::1",
		"2001:db8::/32",
		"invalid",
		"",
		"0.0.0.0/0",
		"::/0",
	}

	for _, seed := range seedCorpus {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// IsValidCIDR should not panic on any input
		// IsValidCIDR 不应在任何输入上发生 panic
		result := IsValidCIDR(input)

		// Result should be a boolean
		// 结果应为布尔值
		_ = result
	})
}

// FuzzIPNetContains tests IP containment with random inputs
// FuzzIPNetContains 使用随机输入测试 IP 包含关系
func FuzzIPNetContains(f *testing.F) {
	// Seed corpus: CIDR, IP pairs
	// 种子语料库：CIDR, IP 对
	seedCorpus := [][2]string{
		{"192.168.1.0/24", "192.168.1.1"},
		{"192.168.1.0/24", "192.168.2.1"},
		{"10.0.0.0/8", "10.1.2.3"},
		{"10.0.0.0/8", "192.168.1.1"},
		{"::/0", "::1"},
		{"2001:db8::/32", "2001:db8::1"},
	}

	for _, seed := range seedCorpus {
		f.Add(seed[0], seed[1])
	}

	f.Fuzz(func(t *testing.T, cidrStr, ipStr string) {
		// Parse CIDR
		// 解析 CIDR
		_, ipNet, err := net.ParseCIDR(cidrStr)
		if err != nil {
			// Invalid CIDR, skip
			// 无效 CIDR，跳过
			return
		}

		// Parse IP
		// 解析 IP
		ip := net.ParseIP(ipStr)
		if ip == nil {
			// Invalid IP, skip
			// 无效 IP，跳过
			return
		}

		// Contains should not panic
		// Contains 不应发生 panic
		contains := ipNet.Contains(ip)
		_ = contains
	})
}

// FuzzIPRange tests IP range operations with random inputs
// FuzzIPRange 使用随机输入测试 IP 范围操作
func FuzzIPRange(f *testing.F) {
	seedCorpus := [][2]string{
		{"192.168.1.1", "192.168.1.10"},
		{"10.0.0.1", "10.0.0.255"},
		{"::1", "::10"},
		{"2001:db8::1", "2001:db8::100"},
	}

	for _, seed := range seedCorpus {
		f.Add(seed[0], seed[1])
	}

	f.Fuzz(func(t *testing.T, startIP, endIP string) {
		// Parse IPs
		// 解析 IP
		start := net.ParseIP(startIP)
		end := net.ParseIP(endIP)

		if start == nil || end == nil {
			// Invalid IPs, skip
			// 无效 IP，跳过
			return
		}

		// Compare IPs - should not panic
		// 比较 IP - 不应发生 panic
		_ = start.Equal(end)
		_ = strings.Compare(start.String(), end.String())
	})
}
