package agent

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestDropReasonToString tests the dropReasonToString function
// TestDropReasonToString 测试 dropReasonToString 函数
func TestDropReasonToString(t *testing.T) {
	tests := []struct {
		name     string
		reason   uint32
		expected string
	}{
		{"BLACKLIST", DropReasonBlacklist, "BLACKLIST"},
		{"RATELIMIT", DropReasonRatelimit, "RATELIMIT"},
		{"DEFAULT", DropReasonDefault, "DEFAULT_DENY"},
		{"INVALID", DropReasonInvalid, "INVALID"},
		{"PROTOCOL", DropReasonProtocol, "PROTOCOL"},
		{"STRICT_TCP", DropReasonStrictTCP, "STRICT_TCP"},
		{"LAND_ATTACK", DropReasonLandAttack, "LAND_ATTACK"},
		{"BOGON", DropReasonBogon, "BOGON"},
		{"FRAGMENT", DropReasonFragment, "FRAGMENT"},
		{"BAD_HEADER", DropReasonBadHeader, "BAD_HEADER"},
		{"TCP_FLAGS", DropReasonTCPFlags, "TCP_FLAGS"},
		{"SPOOF", DropReasonSpoof, "SPOOF"},
		{"UNKNOWN", DropReasonUnknown, "UNKNOWN"},
		{"Unknown reason", 999, "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := dropReasonToString(tt.reason)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestPassReasonToString tests the passReasonToString function
// TestPassReasonToString 测试 passReasonToString 函数
func TestPassReasonToString(t *testing.T) {
	tests := []struct {
		name     string
		reason   uint32
		expected string
	}{
		{"WHITELIST", PassReasonWhitelist, "WHITELIST"},
		{"RETURN", PassReasonReturn, "RETURN"},
		{"CONNTRACK", PassReasonConntrack, "CONNTRACK"},
		{"DEFAULT", PassReasonDefault, "DEFAULT"},
		{"UNKNOWN", PassReasonUnknown, "UNKNOWN"},
		{"Unknown reason", 999, "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := passReasonToString(tt.reason)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestProtocolToString tests the protocolToString function
// TestProtocolToString 测试 protocolToString 函数
func TestProtocolToString(t *testing.T) {
	tests := []struct {
		name     string
		proto    uint8
		expected string
	}{
		{"TCP", 6, "TCP"},
		{"UDP", 17, "UDP"},
		{"ICMP", 1, "ICMP"},
		{"ICMPv6", 58, "ICMPv6"},
		{"Unknown protocol", 99, "99"},
		{"Zero", 0, "OTHER"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := protocolToString(tt.proto)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestDropReasonConstants tests that drop reason constants have expected values
// TestDropReasonConstants 测试丢弃原因常量具有预期值
func TestDropReasonConstants(t *testing.T) {
	assert.Equal(t, 0, DropReasonUnknown)
	assert.Equal(t, 1, DropReasonInvalid)
	assert.Equal(t, 2, DropReasonProtocol)
	assert.Equal(t, 3, DropReasonBlacklist)
	assert.Equal(t, 4, DropReasonRatelimit)
	assert.Equal(t, 5, DropReasonStrictTCP)
	assert.Equal(t, 6, DropReasonDefault)
	assert.Equal(t, 7, DropReasonLandAttack)
	assert.Equal(t, 8, DropReasonBogon)
	assert.Equal(t, 9, DropReasonFragment)
	assert.Equal(t, 10, DropReasonBadHeader)
	assert.Equal(t, 11, DropReasonTCPFlags)
	assert.Equal(t, 12, DropReasonSpoof)
}

// TestPassReasonConstants tests that pass reason constants have expected values
// TestPassReasonConstants 测试通过原因常量具有预期值
func TestPassReasonConstants(t *testing.T) {
	assert.Equal(t, 100, PassReasonUnknown)
	assert.Equal(t, 101, PassReasonWhitelist)
	assert.Equal(t, 102, PassReasonReturn)
	assert.Equal(t, 103, PassReasonConntrack)
	assert.Equal(t, 104, PassReasonDefault)
}
