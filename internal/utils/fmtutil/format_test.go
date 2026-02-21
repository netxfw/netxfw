package fmtutil

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestFormatNumber tests FormatNumber function
// TestFormatNumber 测试 FormatNumber 函数
func TestFormatNumber(t *testing.T) {
	tests := []struct {
		input    uint64
		expected string
	}{
		{0, "0"},
		{999, "999"},
		{1000, "1.00K"},
		{1500, "1.50K"},
		{1000000, "1.00M"},
		{1500000, "1.50M"},
		{1000000000, "1.00G"},
		{1500000000, "1.50G"},
	}

	for _, tt := range tests {
		result := FormatNumber(tt.input)
		assert.Equal(t, tt.expected, result, "FormatNumber(%d) = %s, want %s", tt.input, result, tt.expected)
	}
}

// TestFormatNumberWithComma tests FormatNumberWithComma function
// TestFormatNumberWithComma 测试 FormatNumberWithComma 函数
func TestFormatNumberWithComma(t *testing.T) {
	tests := []struct {
		input    uint64
		expected string
	}{
		{0, "0"},
		{100, "100"},
		{1000, "1,000"},
		{10000, "10,000"},
		{100000, "100,000"},
		{1000000, "1,000,000"},
		{1234567890, "1,234,567,890"},
	}

	for _, tt := range tests {
		result := FormatNumberWithComma(tt.input)
		assert.Equal(t, tt.expected, result, "FormatNumberWithComma(%d) = %s, want %s", tt.input, result, tt.expected)
	}
}

// TestFormatBytes tests FormatBytes function
// TestFormatBytes 测试 FormatBytes 函数
func TestFormatBytes(t *testing.T) {
	tests := []struct {
		input    uint64
		expected string
	}{
		{0, "0B"},
		{512, "512B"},
		{1023, "1023B"},
		{1024, "1.00KB"},
		{1536, "1.50KB"},
		{1048576, "1.00MB"},
		{1073741824, "1.00GB"},
	}

	for _, tt := range tests {
		result := FormatBytes(tt.input)
		assert.Equal(t, tt.expected, result, "FormatBytes(%d) = %s, want %s", tt.input, result, tt.expected)
	}
}

// TestFormatLatency tests FormatLatency function
// TestFormatLatency 测试 FormatLatency 函数
func TestFormatLatency(t *testing.T) {
	tests := []struct {
		input    uint64
		expected string
	}{
		{0, "0ns"},
		{100, "100ns"},
		{999, "999ns"},
		{1000, "1.00µs"},
		{1500, "1.50µs"},
		{1000000, "1.00ms"},
		{1000000000, "1.00s"},
	}

	for _, tt := range tests {
		result := FormatLatency(tt.input)
		assert.Equal(t, tt.expected, result, "FormatLatency(%d) = %s, want %s", tt.input, result, tt.expected)
	}
}

// TestFormatDuration tests FormatDuration function
// TestFormatDuration 测试 FormatDuration 函数
func TestFormatDuration(t *testing.T) {
	tests := []struct {
		input    time.Duration
		contains string
	}{
		{time.Millisecond, "ms"},
		{time.Second, "1s"},
		{time.Minute, "1m"},
		{time.Hour, "1h"},
		{24 * time.Hour, "1d"},
		{25 * time.Hour, "1d 1h"},
		{90 * time.Second, "1m 30s"},
	}

	for _, tt := range tests {
		result := FormatDuration(tt.input)
		assert.Contains(t, result, tt.contains, "FormatDuration(%v) = %s, should contain %s", tt.input, result, tt.contains)
	}
}

// TestFormatPercent tests FormatPercent function
// TestFormatPercent 测试 FormatPercent 函数
func TestFormatPercent(t *testing.T) {
	tests := []struct {
		input    float64
		expected string
	}{
		{0, "0.00%"},
		{50, "50.00%"},
		{99.99, "99.99%"},
		{100, "100.00%"},
	}

	for _, tt := range tests {
		result := FormatPercent(tt.input)
		assert.Equal(t, tt.expected, result, "FormatPercent(%f) = %s, want %s", tt.input, result, tt.expected)
	}
}

// TestFormatBPS tests FormatBPS function
// TestFormatBPS 测试 FormatBPS 函数
func TestFormatBPS(t *testing.T) {
	tests := []struct {
		input    uint64
		expected string
	}{
		{0, "0 bps"},
		{1000, "8000 bps"},
		{125000, "122.1 Kbps"},
		{125000000, "119.2 Mbps"},
	}

	for _, tt := range tests {
		result := FormatBPS(tt.input)
		assert.Equal(t, tt.expected, result, "FormatBPS(%d) = %s, want %s", tt.input, result, tt.expected)
	}
}
