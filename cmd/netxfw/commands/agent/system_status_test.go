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
		{"BLACKLIST", DROP_REASON_BLACKLIST, "BLACKLIST"},
		{"RATELIMIT", DROP_REASON_RATELIMIT, "RATELIMIT"},
		{"DEFAULT", DROP_REASON_DEFAULT, "DEFAULT_DENY"},
		{"INVALID", DROP_REASON_INVALID, "INVALID"},
		{"PROTOCOL", DROP_REASON_PROTOCOL, "PROTOCOL"},
		{"STRICT_TCP", DROP_REASON_STRICT_TCP, "STRICT_TCP"},
		{"LAND_ATTACK", DROP_REASON_LAND_ATTACK, "LAND_ATTACK"},
		{"BOGON", DROP_REASON_BOGON, "BOGON"},
		{"FRAGMENT", DROP_REASON_FRAGMENT, "FRAGMENT"},
		{"BAD_HEADER", DROP_REASON_BAD_HEADER, "BAD_HEADER"},
		{"TCP_FLAGS", DROP_REASON_TCP_FLAGS, "TCP_FLAGS"},
		{"SPOOF", DROP_REASON_SPOOF, "SPOOF"},
		{"UNKNOWN", DROP_REASON_UNKNOWN, "UNKNOWN"},
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
		{"WHITELIST", PASS_REASON_WHITELIST, "WHITELIST"},
		{"RETURN", PASS_REASON_RETURN, "RETURN"},
		{"CONNTRACK", PASS_REASON_CONNTRACK, "CONNTRACK"},
		{"DEFAULT", PASS_REASON_DEFAULT, "DEFAULT"},
		{"UNKNOWN", PASS_REASON_UNKNOWN, "UNKNOWN"},
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
	assert.Equal(t, 0, DROP_REASON_UNKNOWN)
	assert.Equal(t, 1, DROP_REASON_INVALID)
	assert.Equal(t, 2, DROP_REASON_PROTOCOL)
	assert.Equal(t, 3, DROP_REASON_BLACKLIST)
	assert.Equal(t, 4, DROP_REASON_RATELIMIT)
	assert.Equal(t, 5, DROP_REASON_STRICT_TCP)
	assert.Equal(t, 6, DROP_REASON_DEFAULT)
	assert.Equal(t, 7, DROP_REASON_LAND_ATTACK)
	assert.Equal(t, 8, DROP_REASON_BOGON)
	assert.Equal(t, 9, DROP_REASON_FRAGMENT)
	assert.Equal(t, 10, DROP_REASON_BAD_HEADER)
	assert.Equal(t, 11, DROP_REASON_TCP_FLAGS)
	assert.Equal(t, 12, DROP_REASON_SPOOF)
}

// TestPassReasonConstants tests that pass reason constants have expected values
// TestPassReasonConstants 测试通过原因常量具有预期值
func TestPassReasonConstants(t *testing.T) {
	assert.Equal(t, 100, PASS_REASON_UNKNOWN)
	assert.Equal(t, 101, PASS_REASON_WHITELIST)
	assert.Equal(t, 102, PASS_REASON_RETURN)
	assert.Equal(t, 103, PASS_REASON_CONNTRACK)
	assert.Equal(t, 104, PASS_REASON_DEFAULT)
}
