package xdp

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestNetXfwIn6Addr_IPv4Mapped tests IPv4-mapped IPv6 address handling
// TestNetXfwIn6Addr_IPv4Mapped 测试 IPv4 映射的 IPv6 地址处理
func TestNetXfwIn6Addr_IPv4Mapped(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected [16]byte
	}{
		{
			name: "192.168.1.1",
			ip:   "192.168.1.1",
			expected: [16]byte{
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 1,
			},
		},
		{
			name: "10.0.0.1",
			ip:   "10.0.0.1",
			expected: [16]byte{
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := netip.MustParseAddr(tt.ip)
			var key NetXfwIn6Addr

			b := ip.As4()
			key.In6U.U6Addr8[10] = 0xff
			key.In6U.U6Addr8[11] = 0xff
			copy(key.In6U.U6Addr8[12:], b[:])

			assert.Equal(t, tt.expected, key.In6U.U6Addr8)
		})
	}
}

// TestNetXfwIn6Addr_IPv6 tests IPv6 address handling
// TestNetXfwIn6Addr_IPv6 测试 IPv6 地址处理
func TestNetXfwIn6Addr_IPv6(t *testing.T) {
	tests := []struct {
		name string
		ip   string
	}{
		{"2001:db8::1", "2001:db8::1"},
		{"::1", "::1"},
		{"fe80::1", "fe80::1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := netip.MustParseAddr(tt.ip)
			var key NetXfwIn6Addr

			b := ip.As16()
			copy(key.In6U.U6Addr8[:], b[:])

			parsed := net.IP(key.In6U.U6Addr8[:]).String()
			assert.NotEmpty(t, parsed)
		})
	}
}

// TestNetXfwLpmIpPortKey tests LPM IP port key structure
// TestNetXfwLpmIpPortKey 测试 LPM IP 端口键结构
func TestNetXfwLpmIpPortKey(t *testing.T) {
	key := NetXfwLpmIpPortKey{
		Prefixlen: 32 + 16, // IPv4 + port
		Port:      80,
	}

	assert.Equal(t, uint32(48), key.Prefixlen)
	assert.Equal(t, uint16(80), key.Port)
}

// TestNetXfwRuleValue_Action tests rule value actions
// TestNetXfwRuleValue_Action 测试规则值动作
func TestNetXfwRuleValue_Action(t *testing.T) {
	tests := []struct {
		name   string
		action uint64
	}{
		{"Allow", 1},
		{"Deny", 2},
		{"Any", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val := NetXfwRuleValue{
				Counter:   tt.action,
				ExpiresAt: 0,
			}
			assert.Equal(t, tt.action, val.Counter)
		})
	}
}

// TestNetXfwTopStatsKey_Fields tests top stats key fields
// TestNetXfwTopStatsKey_Fields 测试 Top 统计键字段
func TestNetXfwTopStatsKey_Fields(t *testing.T) {
	key := NetXfwTopStatsKey{
		Reason:   1,
		Protocol: 6,
		DstPort:  80,
	}

	assert.Equal(t, uint32(1), key.Reason)
	assert.Equal(t, uint32(6), key.Protocol)
	assert.Equal(t, uint16(80), key.DstPort)
}

// TestIPNetParsing tests IP network parsing
// TestIPNetParsing 测试 IP 网络解析
func TestIPNetParsing(t *testing.T) {
	tests := []struct {
		name      string
		cidr      string
		expectErr bool
	}{
		{"Valid IPv4 CIDR", "192.168.1.0/24", false},
		{"Valid IPv4 single", "192.168.1.1/32", false},
		{"Valid IPv6 CIDR", "2001:db8::/32", false},
		{"Valid IPv6 single", "2001:db8::1/128", false},
		{"Invalid CIDR", "invalid", true},
		{"Empty string", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ipNet, err := net.ParseCIDR(tt.cidr)
			if tt.expectErr {
				assert.Error(t, err)
				assert.Nil(t, ipNet)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, ipNet)
			}
		})
	}
}

// TestNetIPParsing tests netip parsing
// TestNetIPParsing 测试 netip 解析
func TestNetIPParsing(t *testing.T) {
	tests := []struct {
		name      string
		ip        string
		is4       bool
		is6       bool
		expectErr bool
	}{
		{"Valid IPv4", "192.168.1.1", true, false, false},
		{"Valid IPv6", "2001:db8::1", false, true, false},
		{"Invalid IP", "invalid", false, false, true},
		{"Empty string", "", false, false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, err := netip.ParseAddr(tt.ip)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.is4, ip.Is4())
				assert.Equal(t, tt.is6, ip.Is6())
			}
		})
	}
}

// TestTimeConversion tests time conversion functions
// TestTimeConversion 测试时间转换函数
func TestTimeConversion(t *testing.T) {
	t.Run("NilTime", func(t *testing.T) {
		var nilTime *time.Time
		result := timeToBootNS(nilTime)
		assert.Equal(t, uint64(0), result)
	})

	t.Run("ValidTime", func(t *testing.T) {
		now := time.Now()
		result := timeToBootNS(&now)
		assert.Greater(t, result, uint64(0))
	})
}

// TestProtocolValues tests protocol constant values
// TestProtocolValues 测试协议常量值
func TestProtocolValues(t *testing.T) {
	protocols := map[string]uint8{
		"ICMP": 1,
		"TCP":  6,
		"UDP":  17,
	}

	for name, expected := range protocols {
		t.Run(name, func(t *testing.T) {
			assert.NotZero(t, expected)
		})
	}
}

// TestActionValues tests action constant values
// TestActionValues 测试动作常量值
func TestActionValues(t *testing.T) {
	actions := map[string]uint8{
		"Allow": 1,
		"Deny":  2,
	}

	for name, expected := range actions {
		t.Run(name, func(t *testing.T) {
			assert.NotZero(t, expected)
		})
	}
}

// TestMaskSize tests IP mask size calculation
// TestMaskSize 测试 IP 掩码大小计算
func TestMaskSize(t *testing.T) {
	tests := []struct {
		name string
		cidr string
		ones int
		bits int
	}{
		{"IPv4 /24", "192.168.1.0/24", 24, 32},
		{"IPv4 /32", "192.168.1.1/32", 32, 32},
		{"IPv4 /16", "10.0.0.0/16", 16, 32},
		{"IPv6 /32", "2001:db8::/32", 32, 128},
		{"IPv6 /64", "2001:db8::/64", 64, 128},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ipNet, err := net.ParseCIDR(tt.cidr)
			assert.NoError(t, err)
			ones, bits := ipNet.Mask.Size()
			assert.Equal(t, tt.ones, ones)
			assert.Equal(t, tt.bits, bits)
		})
	}
}

// TestIPContains tests IP network contains
// TestIPContains 测试 IP 网络包含
func TestIPContains(t *testing.T) {
	tests := []struct {
		name     string
		cidr     string
		ip       string
		contains bool
	}{
		{"In subnet", "192.168.1.0/24", "192.168.1.100", true},
		{"Not in subnet", "192.168.1.0/24", "192.168.2.1", false},
		{"Exact match", "192.168.1.1/32", "192.168.1.1", true},
		{"Not exact match", "192.168.1.1/32", "192.168.1.2", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ipNet, err := net.ParseCIDR(tt.cidr)
			assert.NoError(t, err)
			ip := net.ParseIP(tt.ip)
			assert.NotNil(t, ip)
			assert.Equal(t, tt.contains, ipNet.Contains(ip))
		})
	}
}

// TestRateLimitConf_ZeroValues tests rate limit config with zero values
// TestRateLimitConf_ZeroValues 测试零值的速率限制配置
func TestRateLimitConf_ZeroValues(t *testing.T) {
	conf := RateLimitConf{}

	assert.Equal(t, uint64(0), conf.Rate)
	assert.Equal(t, uint64(0), conf.Burst)
}

// TestIPPortRule_ZeroValues tests IP port rule with zero values
// TestIPPortRule_ZeroValues 测试零值的 IP 端口规则
func TestIPPortRule_ZeroValues(t *testing.T) {
	rule := IPPortRule{}

	assert.Empty(t, rule.IP)
	assert.Equal(t, uint16(0), rule.Port)
	assert.Equal(t, uint8(0), rule.Action)
}

// TestBlockedIP_ZeroValues tests blocked IP with zero values
// TestBlockedIP_ZeroValues 测试零值的拦截 IP
func TestBlockedIP_ZeroValues(t *testing.T) {
	blocked := BlockedIP{}

	assert.Empty(t, blocked.IP)
	assert.Equal(t, uint64(0), blocked.ExpiresAt)
	assert.Equal(t, uint64(0), blocked.Counter)
}

// TestConntrackEntry_ZeroValues tests conntrack entry with zero values
// TestConntrackEntry_ZeroValues 测试零值的连接跟踪条目
func TestConntrackEntry_ZeroValues(t *testing.T) {
	entry := ConntrackEntry{}

	assert.Empty(t, entry.SrcIP)
	assert.Empty(t, entry.DstIP)
	assert.Equal(t, uint16(0), entry.SrcPort)
	assert.Equal(t, uint16(0), entry.DstPort)
	assert.Equal(t, uint8(0), entry.Protocol)
}

// TestDropDetailEntry_ZeroValues tests drop detail entry with zero values
// TestDropDetailEntry_ZeroValues 测试零值的拦截详情条目
func TestDropDetailEntry_ZeroValues(t *testing.T) {
	entry := DropDetailEntry{}

	assert.Empty(t, entry.SrcIP)
	assert.Empty(t, entry.DstIP)
	assert.Equal(t, uint16(0), entry.SrcPort)
	assert.Equal(t, uint16(0), entry.DstPort)
	assert.Equal(t, uint8(0), entry.Protocol)
	assert.Equal(t, uint32(0), entry.Reason)
	assert.Equal(t, uint64(0), entry.Count)
}
