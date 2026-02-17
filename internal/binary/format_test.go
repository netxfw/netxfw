package binary

import (
	"bytes"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestEncode tests the Encode function
// TestEncode 测试 Encode 函数
func TestEncode(t *testing.T) {
	records := []Record{
		{IP: net.ParseIP("192.168.1.1"), PrefixLen: 32, IsIPv6: false},
		{IP: net.ParseIP("10.0.0.0"), PrefixLen: 8, IsIPv6: false},
		{IP: net.ParseIP("2001:db8::1"), PrefixLen: 128, IsIPv6: true},
	}

	var buf bytes.Buffer
	err := Encode(&buf, records)
	assert.NoError(t, err)

	// Verify the buffer has content
	// 验证缓冲区有内容
	assert.Greater(t, buf.Len(), 0)

	// Verify magic header
	// 验证魔数头
	assert.Equal(t, Magic, string(buf.Bytes()[:4]))
}

// TestEncode_EmptyRecords tests Encode with empty records
// TestEncode_EmptyRecords 测试空记录的 Encode
func TestEncode_EmptyRecords(t *testing.T) {
	records := []Record{}

	var buf bytes.Buffer
	err := Encode(&buf, records)
	assert.NoError(t, err)

	// Should still have header
	// 仍然应该有头
	assert.Greater(t, buf.Len(), 0)
}

// TestEncode_IPv4Only tests Encode with IPv4 only
// TestEncode_IPv4Only 测试仅 IPv4 的 Encode
func TestEncode_IPv4Only(t *testing.T) {
	records := []Record{
		{IP: net.ParseIP("192.168.1.1"), PrefixLen: 32, IsIPv6: false},
		{IP: net.ParseIP("10.0.0.0"), PrefixLen: 8, IsIPv6: false},
	}

	var buf bytes.Buffer
	err := Encode(&buf, records)
	assert.NoError(t, err)
	assert.Greater(t, buf.Len(), 0)
}

// TestEncode_IPv6Only tests Encode with IPv6 only
// TestEncode_IPv6Only 测试仅 IPv6 的 Encode
func TestEncode_IPv6Only(t *testing.T) {
	records := []Record{
		{IP: net.ParseIP("2001:db8::1"), PrefixLen: 128, IsIPv6: true},
		{IP: net.ParseIP("fe80::1"), PrefixLen: 64, IsIPv6: true},
	}

	var buf bytes.Buffer
	err := Encode(&buf, records)
	assert.NoError(t, err)
	assert.Greater(t, buf.Len(), 0)
}

// TestDecode tests the Decode function
// TestDecode 测试 Decode 函数
func TestDecode(t *testing.T) {
	records := []Record{
		{IP: net.ParseIP("192.168.1.1"), PrefixLen: 32, IsIPv6: false},
		{IP: net.ParseIP("10.0.0.0"), PrefixLen: 8, IsIPv6: false},
		{IP: net.ParseIP("2001:db8::1"), PrefixLen: 128, IsIPv6: true},
	}

	var buf bytes.Buffer
	err := Encode(&buf, records)
	assert.NoError(t, err)

	decoded, err := Decode(&buf)
	assert.NoError(t, err)
	assert.Len(t, decoded, len(records))

	// Verify the decoded records
	// 验证解码的记录
	for i, r := range decoded {
		assert.Equal(t, records[i].PrefixLen, r.PrefixLen)
		assert.Equal(t, records[i].IsIPv6, r.IsIPv6)
	}
}

// TestDecode_InvalidMagic tests Decode with invalid magic
// TestDecode_InvalidMagic 测试魔数无效的 Decode
func TestDecode_InvalidMagic(t *testing.T) {
	data := []byte("XXXX\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
	reader := bytes.NewReader(data)

	_, err := Decode(reader)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "magic")
}

// TestDecode_InvalidVersion tests Decode with invalid version
// TestDecode_InvalidVersion 测试版本无效的 Decode
func TestDecode_InvalidVersion(t *testing.T) {
	data := []byte(Magic + "\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
	reader := bytes.NewReader(data)

	_, err := Decode(reader)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "version")
}

// TestDecode_EmptyData tests Decode with empty data
// TestDecode_EmptyData 测试空数据的 Decode
func TestDecode_EmptyData(t *testing.T) {
	reader := bytes.NewReader([]byte{})

	_, err := Decode(reader)
	assert.Error(t, err)
}

// TestDecode_TruncatedData tests Decode with truncated data
// TestDecode_TruncatedData 测试截断数据的 Decode
func TestDecode_TruncatedData(t *testing.T) {
	// Only magic, no version
	// 只有魔数，没有版本
	data := []byte(Magic)
	reader := bytes.NewReader(data)

	_, err := Decode(reader)
	assert.Error(t, err)
}

// TestEncodeDecodeRoundTrip tests the full encode and decode cycle
// TestEncodeDecodeRoundTrip 测试完整的编码和解码周期
func TestEncodeDecodeRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		records []Record
	}{
		{
			name: "Single IPv4",
			records: []Record{
				{IP: net.ParseIP("192.168.1.1"), PrefixLen: 32, IsIPv6: false},
			},
		},
		{
			name: "Single IPv6",
			records: []Record{
				{IP: net.ParseIP("2001:db8::1"), PrefixLen: 128, IsIPv6: true},
			},
		},
		{
			name: "Mixed records",
			records: []Record{
				{IP: net.ParseIP("192.168.1.0"), PrefixLen: 24, IsIPv6: false},
				{IP: net.ParseIP("10.0.0.1"), PrefixLen: 32, IsIPv6: false},
				{IP: net.ParseIP("2001:db8::"), PrefixLen: 32, IsIPv6: true},
				{IP: net.ParseIP("fe80::1"), PrefixLen: 128, IsIPv6: true},
			},
		},
		{
			name:    "Empty records",
			records: []Record{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := Encode(&buf, tt.records)
			assert.NoError(t, err)

			decoded, err := Decode(&buf)
			assert.NoError(t, err)
			assert.Len(t, decoded, len(tt.records))

			// Verify each record
			// 验证每条记录
			for i, r := range decoded {
				assert.Equal(t, tt.records[i].PrefixLen, r.PrefixLen)
				assert.Equal(t, tt.records[i].IsIPv6, r.IsIPv6)
			}
		})
	}
}

// TestRecord tests Record struct
// TestRecord 测试 Record 结构体
func TestRecord(t *testing.T) {
	record := Record{
		IP:        net.ParseIP("192.168.1.1"),
		PrefixLen: 32,
		IsIPv6:    false,
	}

	assert.NotNil(t, record.IP)
	assert.Equal(t, uint8(32), record.PrefixLen)
	assert.False(t, record.IsIPv6)

	record6 := Record{
		IP:        net.ParseIP("2001:db8::1"),
		PrefixLen: 128,
		IsIPv6:    true,
	}

	assert.NotNil(t, record6.IP)
	assert.Equal(t, uint8(128), record6.PrefixLen)
	assert.True(t, record6.IsIPv6)
}

// TestConstants tests the package constants
// TestConstants 测试包常量
func TestConstants(t *testing.T) {
	assert.Equal(t, "NXFW", Magic)
	assert.Equal(t, 1, Version)
}
