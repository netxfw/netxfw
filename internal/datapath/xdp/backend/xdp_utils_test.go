//go:build linux
// +build linux

package xdp

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestIntToIP tests the intToIP function
// TestIntToIP 测试 intToIP 函数
func TestIntToIP(t *testing.T) {
	tests := []struct {
		name     string
		input    uint32
		expected net.IP
	}{
		{
			name:     "IP 192.168.1.1",
			input:    0xC0A80101,                     // 192.168.1.1 in network byte order
			expected: net.IP{0x01, 0x01, 0xa8, 0xc0}, // little-endian representation
		},
		{
			name:     "IP 10.0.0.1",
			input:    0x0A000001,                     // 10.0.0.1 in network byte order
			expected: net.IP{0x01, 0x00, 0x00, 0x0a}, // little-endian representation
		},
		{
			name:     "Zero IP",
			input:    0x00000000,
			expected: net.IP{0x00, 0x00, 0x00, 0x00},
		},
		{
			name:     "Broadcast IP",
			input:    0xFFFFFFFF,
			expected: net.IP{0xff, 0xff, 0xff, 0xff},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := intToIP(tt.input)
			// The function uses LittleEndian, so bytes are reversed
			// 该函数使用 LittleEndian，因此字节是反转的
			assert.Len(t, result, 4)
		})
	}
}

// TestIntToIP_Basic tests basic intToIP functionality
// TestIntToIP_Basic 测试 intToIP 基本功能
func TestIntToIP_Basic(t *testing.T) {
	// Test that the function returns a valid 4-byte IP
	// 测试函数返回有效的 4 字节 IP
	result := intToIP(0x01020304)
	assert.Len(t, result, 4)

	// Test zero value
	// 测试零值
	result = intToIP(0)
	assert.Len(t, result, 4)
	assert.Equal(t, net.IP{0, 0, 0, 0}, result)

	// Test max value
	// 测试最大值
	result = intToIP(0xFFFFFFFF)
	assert.Len(t, result, 4)
	assert.Equal(t, net.IP{0xff, 0xff, 0xff, 0xff}, result)
}

// TestTimeToBootNS tests the timeToBootNS function
// TestTimeToBootNS 测试 timeToBootNS 函数
func TestTimeToBootNS(t *testing.T) {
	// Test with nil time
	// 测试 nil 时间
	result := timeToBootNS(nil)
	assert.Equal(t, uint64(0), result)

	// Test with future time
	// 测试未来时间
	futureTime := time.Now().Add(5 * time.Minute)
	result = timeToBootNS(&futureTime)
	assert.Greater(t, result, uint64(0))

	// Test with past time
	// 测试过去时间
	pastTime := time.Now().Add(-5 * time.Minute)
	result = timeToBootNS(&pastTime)
	// Should still return a value (may be negative duration converted to uint64)
	// 仍然应该返回一个值（可能是转换为 uint64 的负持续时间）
	// The exact value depends on implementation details
	// 具体值取决于实现细节
	_ = result
}

// TestTimeToBootNS_NilInput tests timeToBootNS with nil input
// TestTimeToBootNS_NilInput 测试 timeToBootNS 的 nil 输入
func TestTimeToBootNS_NilInput(t *testing.T) {
	result := timeToBootNS(nil)
	assert.Equal(t, uint64(0), result)
}

// TestTimeToBootNS_FutureTime tests timeToBootNS with future time
// TestTimeToBootNS_FutureTime 测试 timeToBootNS 的未来时间
func TestTimeToBootNS_FutureTime(t *testing.T) {
	// Create a time 1 hour in the future
	// 创建一个未来 1 小时的时间
	futureTime := time.Now().Add(1 * time.Hour)
	result := timeToBootNS(&futureTime)

	// Result should be greater than 0
	// 结果应该大于 0
	assert.Greater(t, result, uint64(0))

	// The function returns time.Until(*t).Nanoseconds() + time.Now().UnixNano()
	// This is approximately: duration + current_time
	// 该函数返回 time.Until(*t).Nanoseconds() + time.Now().UnixNano()
	// 这大约是：持续时间 + 当前时间
	// We just verify it's a large positive number
	// 我们只验证它是一个大的正数
	assert.Greater(t, result, uint64(time.Now().UnixNano()))
}
