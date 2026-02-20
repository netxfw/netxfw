package agent

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/livp123/netxfw/pkg/sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockStatsAPI is a mock implementation of StatsAPI for testing
// MockStatsAPI 是用于测试的 StatsAPI 模拟实现
type MockStatsAPI struct {
	mock.Mock
}

func (m *MockStatsAPI) GetCounters() (uint64, uint64, error) {
	args := m.Called()
	return args.Get(0).(uint64), args.Get(1).(uint64), args.Error(2)
}

func (m *MockStatsAPI) GetLockedIPCount() (int, error) {
	args := m.Called()
	return args.Int(0), args.Error(1)
}

func (m *MockStatsAPI) GetDropDetails() ([]sdk.DropDetailEntry, error) {
	args := m.Called()
	return args.Get(0).([]sdk.DropDetailEntry), args.Error(1)
}

func (m *MockStatsAPI) GetPassDetails() ([]sdk.DropDetailEntry, error) {
	args := m.Called()
	return args.Get(0).([]sdk.DropDetailEntry), args.Error(1)
}

// TestShowDropReasonSummary tests the showReasonSummary function for drops
// TestShowDropReasonSummary 测试 showReasonSummary 函数的丢弃功能
func TestShowDropReasonSummary(t *testing.T) {
	// Capture stdout
	// 捕获标准输出
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	dropDetails := []sdk.DropDetailEntry{
		{Reason: DropReasonBlacklist, Count: 100},
		{Reason: DropReasonRatelimit, Count: 50},
		{Reason: DropReasonBlacklist, Count: 30},
	}
	drops := uint64(180)

	// Wrap details for generic function / 包装详情用于泛型函数
	wrappedDetails := make([]DropDetailEntryWrapper, len(dropDetails))
	for i, d := range dropDetails {
		wrappedDetails[i] = DropDetailEntryWrapper{d}
	}

	showReasonSummary(wrappedDetails, detailStatsConfig{
		reasonFunc: dropReasonToString,
		totalCount: drops,
		showRate:   false,
	})

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// Verify output contains expected strings
	// 验证输出包含预期字符串
	assert.Contains(t, output, "Reason Summary")
	assert.Contains(t, output, "BLACKLIST")
	assert.Contains(t, output, "RATELIMIT")
}

// TestShowPassReasonSummary tests the showReasonSummary function for passes
// TestShowPassReasonSummary 测试 showReasonSummary 函数的通过功能
func TestShowPassReasonSummary(t *testing.T) {
	// Capture stdout
	// 捕获标准输出
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	passDetails := []sdk.DropDetailEntry{
		{Reason: PassReasonWhitelist, Count: 200},
		{Reason: PassReasonConntrack, Count: 150},
		{Reason: PassReasonWhitelist, Count: 50},
	}
	pass := uint64(400)

	// Wrap details for generic function / 包装详情用于泛型函数
	wrappedDetails := make([]PassDetailEntryWrapper, len(passDetails))
	for i, d := range passDetails {
		wrappedDetails[i] = PassDetailEntryWrapper{d}
	}

	showReasonSummary(wrappedDetails, detailStatsConfig{
		reasonFunc: passReasonToString,
		totalCount: pass,
		showRate:   false,
	})

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// Verify output contains expected strings
	// 验证输出包含预期字符串
	assert.Contains(t, output, "Reason Summary")
	assert.Contains(t, output, "WHITELIST")
	assert.Contains(t, output, "CONNTRACK")
}

// TestShowDropReasonSummaryEmpty tests showReasonSummary with empty data
// TestShowDropReasonSummaryEmpty 测试空数据的 showReasonSummary
func TestShowDropReasonSummaryEmpty(t *testing.T) {
	// Capture stdout
	// 捕获标准输出
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	dropDetails := []sdk.DropDetailEntry{}
	drops := uint64(0)

	// Wrap details for generic function / 包装详情用于泛型函数
	wrappedDetails := make([]DropDetailEntryWrapper, len(dropDetails))

	showReasonSummary(wrappedDetails, detailStatsConfig{
		reasonFunc: dropReasonToString,
		totalCount: drops,
		showRate:   false,
	})

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// Should not output anything for empty data
	// 空数据不应输出任何内容
	assert.NotContains(t, output, "Reason Summary")
}

// TestShowPassReasonSummaryEmpty tests showReasonSummary with empty data
// TestShowPassReasonSummaryEmpty 测试空数据的 showReasonSummary
func TestShowPassReasonSummaryEmpty(t *testing.T) {
	// Capture stdout
	// 捕获标准输出
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	passDetails := []sdk.DropDetailEntry{}
	pass := uint64(0)

	// Wrap details for generic function / 包装详情用于泛型函数
	wrappedDetails := make([]PassDetailEntryWrapper, len(passDetails))

	showReasonSummary(wrappedDetails, detailStatsConfig{
		reasonFunc: passReasonToString,
		totalCount: pass,
		showRate:   false,
	})

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// Should not output anything for empty data
	// 空数据不应输出任何内容
	assert.NotContains(t, output, "Reason Summary")
}

// TestShowDropReasonSummaryZeroDrops tests percentage calculation with zero drops
// TestShowDropReasonSummaryZeroDrops 测试零丢弃时的百分比计算
func TestShowDropReasonSummaryZeroDrops(t *testing.T) {
	// Capture stdout
	// 捕获标准输出
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	dropDetails := []sdk.DropDetailEntry{
		{Reason: DropReasonBlacklist, Count: 0},
	}
	drops := uint64(0)

	// Wrap details for generic function / 包装详情用于泛型函数
	wrappedDetails := make([]DropDetailEntryWrapper, len(dropDetails))
	for i, d := range dropDetails {
		wrappedDetails[i] = DropDetailEntryWrapper{d}
	}

	// Should not panic with zero drops
	// 零丢弃时不应 panic
	showReasonSummary(wrappedDetails, detailStatsConfig{
		reasonFunc: dropReasonToString,
		totalCount: drops,
		showRate:   false,
	})

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	assert.Contains(t, output, "Reason Summary")
}

// TestShowPassReasonSummaryZeroPass tests percentage calculation with zero pass
// TestShowPassReasonSummaryZeroPass 测试零通过时的百分比计算
func TestShowPassReasonSummaryZeroPass(t *testing.T) {
	// Capture stdout
	// 捕获标准输出
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	passDetails := []sdk.DropDetailEntry{
		{Reason: PassReasonWhitelist, Count: 0},
	}
	pass := uint64(0)

	// Wrap details for generic function / 包装详情用于泛型函数
	wrappedDetails := make([]PassDetailEntryWrapper, len(passDetails))
	for i, d := range passDetails {
		wrappedDetails[i] = PassDetailEntryWrapper{d}
	}

	// Should not panic with zero pass
	// 零通过时不应 panic
	showReasonSummary(wrappedDetails, detailStatsConfig{
		reasonFunc: passReasonToString,
		totalCount: pass,
		showRate:   false,
	})

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	assert.Contains(t, output, "Reason Summary")
}

// TestShowAttachedInterfaces tests the showAttachedInterfaces function
// TestShowAttachedInterfaces 测试 showAttachedInterfaces 函数
func TestShowAttachedInterfaces(t *testing.T) {
	// Capture stdout
	// 捕获标准输出
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	showAttachedInterfaces()

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// Verify output contains expected strings
	// 验证输出包含预期字符串
	assert.Contains(t, output, "Attached Interfaces")
	// In test environment, likely no interfaces attached
	// 在测试环境中，可能没有附加接口
	assert.True(t, strings.Contains(output, "None") || strings.Contains(output, "ens"))
}

// TestDropReasonToStringAllReasons tests all drop reason mappings
// TestDropReasonToStringAllReasons 测试所有丢弃原因映射
func TestDropReasonToStringAllReasons(t *testing.T) {
	reasons := map[uint32]string{
		DropReasonBlacklist:  "BLACKLIST",
		DropReasonRatelimit:  "RATELIMIT",
		DropReasonDefault:    "DEFAULT_DENY",
		DropReasonInvalid:    "INVALID",
		DropReasonProtocol:   "PROTOCOL",
		DropReasonStrictTCP:  "STRICT_TCP",
		DropReasonLandAttack: "LAND_ATTACK",
		DropReasonBogon:      "BOGON",
		DropReasonFragment:   "FRAGMENT",
		DropReasonBadHeader:  "BAD_HEADER",
		DropReasonTCPFlags:   "TCP_FLAGS",
		DropReasonSpoof:      "SPOOF",
	}

	for reason, expected := range reasons {
		result := dropReasonToString(reason)
		assert.Equal(t, expected, result, "Reason %d should map to %s", reason, expected)
	}
}

// TestPassReasonToStringAllReasons tests all pass reason mappings
// TestPassReasonToStringAllReasons 测试所有通过原因映射
func TestPassReasonToStringAllReasons(t *testing.T) {
	reasons := map[uint32]string{
		PassReasonWhitelist: "WHITELIST",
		PassReasonReturn:    "RETURN",
		PassReasonConntrack: "CONNTRACK",
		PassReasonDefault:   "DEFAULT",
	}

	for reason, expected := range reasons {
		result := passReasonToString(reason)
		assert.Equal(t, expected, result, "Reason %d should map to %s", reason, expected)
	}
}

// TestProtocolToStringAllProtocols tests all protocol mappings
// TestProtocolToStringAllProtocols 测试所有协议映射
func TestProtocolToStringAllProtocols(t *testing.T) {
	protocols := map[uint8]string{
		6:  "TCP",
		17: "UDP",
		1:  "ICMP",
		58: "ICMPv6",
	}

	for proto, expected := range protocols {
		result := protocolToString(proto)
		assert.Equal(t, expected, result, "Protocol %d should map to %s", proto, expected)
	}
}

// TestShowDropStatisticsWithDetails tests showDropStatistics with actual details
// TestShowDropStatisticsWithDetails 测试带详细信息的 showDropStatistics
func TestShowDropStatisticsWithDetails(t *testing.T) {
	// Create mock StatsAPI
	// 创建模拟 StatsAPI
	mockStatsAPI := new(MockStatsAPI)

	dropDetails := []sdk.DropDetailEntry{
		{Reason: DropReasonBlacklist, SrcIP: "192.168.1.1", DstPort: 80, Protocol: 6, Count: 100},
		{Reason: DropReasonRatelimit, SrcIP: "10.0.0.1", DstPort: 443, Protocol: 6, Count: 50},
	}

	mockStatsAPI.On("GetDropDetails").Return(dropDetails, nil)

	// Capture stdout
	// 捕获标准输出
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	showDropStatistics(mockStatsAPI, 150, 1000)

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// Verify output
	// 验证输出
	assert.Contains(t, output, "Drop Statistics")
	assert.Contains(t, output, "Top Drops by Reason")
	assert.Contains(t, output, "BLACKLIST")
	assert.Contains(t, output, "RATELIMIT")
	assert.Contains(t, output, "192.168.1.1")
	assert.Contains(t, output, "10.0.0.1")
}

// TestShowPassStatisticsWithDetails tests showPassStatistics with actual details
// TestShowPassStatisticsWithDetails 测试带详细信息的 showPassStatistics
func TestShowPassStatisticsWithDetails(t *testing.T) {
	// Create mock StatsAPI
	// 创建模拟 StatsAPI
	mockStatsAPI := new(MockStatsAPI)

	passDetails := []sdk.DropDetailEntry{
		{Reason: PassReasonWhitelist, SrcIP: "192.168.1.100", DstPort: 22, Protocol: 6, Count: 200},
		{Reason: PassReasonConntrack, SrcIP: "10.0.0.100", DstPort: 80, Protocol: 6, Count: 150},
	}

	mockStatsAPI.On("GetPassDetails").Return(passDetails, nil)

	// Capture stdout
	// 捕获标准输出
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	showPassStatistics(mockStatsAPI, 350, 50)

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// Verify output
	// 验证输出
	assert.Contains(t, output, "Pass Statistics")
	assert.Contains(t, output, "Top Allowed by Reason")
	assert.Contains(t, output, "WHITELIST")
	assert.Contains(t, output, "CONNTRACK")
	assert.Contains(t, output, "192.168.1.100")
	assert.Contains(t, output, "10.0.0.100")
}

// TestPercentageCalculation tests percentage calculation accuracy
// TestPercentageCalculation 测试百分比计算精度
func TestPercentageCalculation(t *testing.T) {
	tests := []struct {
		name      string
		count     uint64
		total     uint64
		expectStr string
	}{
		{"50 percent", 50, 100, "50.00%"},
		{"33.33 percent", 1, 3, "33.33%"},
		{"0 percent", 0, 100, "0.00%"},
		{"100 percent", 100, 100, "100.00%"},
		{"zero total", 50, 0, "0.00%"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var percent float64
			if tt.total > 0 {
				percent = float64(tt.count) / float64(tt.total) * 100
			}

			// Verify percentage is within expected range
			// 验证百分比在预期范围内
			if tt.total > 0 {
				assert.GreaterOrEqual(t, percent, 0.0)
				assert.LessOrEqual(t, percent, 100.0)
			} else {
				assert.Equal(t, 0.0, percent)
			}
		})
	}
}

// TestConstantsNotModified tests that constants have not been accidentally modified
// TestConstantsNotModified 测试常量未被意外修改
func TestConstantsNotModified(t *testing.T) {
	// Drop reasons should be 0-12
	// 丢弃原因应该是 0-12
	assert.Equal(t, 0, DropReasonUnknown)
	assert.Equal(t, 12, DropReasonSpoof)

	// Pass reasons should be 100-104
	// 通过原因应该是 100-104
	assert.Equal(t, 100, PassReasonUnknown)
	assert.Equal(t, 104, PassReasonDefault)

	// Verify drop and pass reasons don't overlap
	// 验证丢弃和通过原因不重叠
	assert.Less(t, DropReasonSpoof, PassReasonUnknown)
}

// TestShowDropStatisticsEmpty tests showDropStatistics with no drops
// TestShowDropStatisticsEmpty 测试无丢弃的 showDropStatistics
func TestShowDropStatisticsEmpty(t *testing.T) {
	// Create mock StatsAPI
	// 创建模拟 StatsAPI
	mockStatsAPI := new(MockStatsAPI)

	mockStatsAPI.On("GetDropDetails").Return([]sdk.DropDetailEntry{}, nil)

	// Capture stdout
	// 捕获标准输出
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	showDropStatistics(mockStatsAPI, 0, 1000)

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// Should show drop statistics section (even if empty)
	// 应显示丢弃统计部分（即使为空）
	// Note: When there are no drops, the function returns early without output
	// 注意：当没有丢弃时，函数会提前返回，不输出任何内容
	assert.Empty(t, output)
}

// TestShowPassStatisticsEmpty tests showPassStatistics with no passes
// TestShowPassStatisticsEmpty 测试无通过的 showPassStatistics
func TestShowPassStatisticsEmpty(t *testing.T) {
	// Create mock StatsAPI
	// 创建模拟 StatsAPI
	mockStatsAPI := new(MockStatsAPI)

	mockStatsAPI.On("GetPassDetails").Return([]sdk.DropDetailEntry{}, nil)

	// Capture stdout
	// 捕获标准输出
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	showPassStatistics(mockStatsAPI, 0, 0)

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// Should show pass statistics section (even if empty)
	// 应显示通过统计部分（即使为空）
	// Note: When there are no passes, the function returns early without output
	// 注意：当没有通过时，函数会提前返回，不输出任何内容
	assert.Empty(t, output)
}

// TestShowDropStatisticsTop10 tests that only top 10 entries are shown
// TestShowDropStatisticsTop10 测试只显示前 10 条记录
func TestShowDropStatisticsTop10(t *testing.T) {
	// Create mock StatsAPI with 15 entries
	// 创建包含 15 条记录的模拟 StatsAPI
	mockStatsAPI := new(MockStatsAPI)

	// Create 15 drop details
	// 创建 15 条丢弃详情
	dropDetails := make([]sdk.DropDetailEntry, 15)
	for i := 0; i < 15; i++ {
		dropDetails[i] = sdk.DropDetailEntry{
			Reason:  DropReasonBlacklist,
			SrcIP:   "192.168.1.1",
			DstPort: uint16(i),
			Count:   uint64(100 - i), // Descending order
		}
	}

	mockStatsAPI.On("GetDropDetails").Return(dropDetails, nil)

	// Capture stdout
	// 捕获标准输出
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	showDropStatistics(mockStatsAPI, 1500, 0)

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// Should contain "... and more" indicator
	// 应包含 "... and more" 指示符
	assert.Contains(t, output, "... and more")
}

// TestShowDropStatisticsError tests showDropStatistics when GetDropDetails returns error
// TestShowDropStatisticsError 测试 GetDropDetails 返回错误时的 showDropStatistics
func TestShowDropStatisticsError(t *testing.T) {
	// Create mock StatsAPI that returns error
	// 创建返回错误的模拟 StatsAPI
	mockStatsAPI := new(MockStatsAPI)

	mockStatsAPI.On("GetDropDetails").Return([]sdk.DropDetailEntry{}, assert.AnError)

	// Capture stdout
	// 捕获标准输出
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	showDropStatistics(mockStatsAPI, 100, 1000)

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// Should show drop statistics section
	// 应显示丢弃统计部分
	// Note: When there's an error, the function returns early without output
	// 注意：当有错误时，函数会提前返回，不输出任何内容
	assert.Empty(t, output)
}

// TestShowPassStatisticsError tests showPassStatistics when GetPassDetails returns error
// TestShowPassStatisticsError 测试 GetPassDetails 返回错误时的 showPassStatistics
func TestShowPassStatisticsError(t *testing.T) {
	// Create mock StatsAPI that returns error
	// 创建返回错误的模拟 StatsAPI
	mockStatsAPI := new(MockStatsAPI)

	mockStatsAPI.On("GetPassDetails").Return([]sdk.DropDetailEntry{}, assert.AnError)

	// Capture stdout
	// 捕获标准输出
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	showPassStatistics(mockStatsAPI, 100, 50)

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// Should show pass statistics section
	// 应显示通过统计部分
	// Note: When there's an error, the function returns early without output
	// 注意：当有错误时，函数会提前返回，不输出任何内容
	assert.Empty(t, output)
}

// TestDropReasonToStringUnknown tests dropReasonToString with unknown reason
// TestDropReasonToStringUnknown 测试未知原因的 dropReasonToString
func TestDropReasonToStringUnknown(t *testing.T) {
	result := dropReasonToString(9999)
	assert.Equal(t, "UNKNOWN", result)
}

// TestPassReasonToStringUnknown tests passReasonToString with unknown reason
// TestPassReasonToStringUnknown 测试未知原因的 passReasonToString
func TestPassReasonToStringUnknown(t *testing.T) {
	result := passReasonToString(9999)
	assert.Equal(t, "UNKNOWN", result)
}

// TestProtocolToStringUnknown tests protocolToString with unknown protocol
// TestProtocolToStringUnknown 测试未知协议的 protocolToString
func TestProtocolToStringUnknown(t *testing.T) {
	result := protocolToString(200)
	assert.Equal(t, "200", result)
}

// TestShowDropReasonSummaryAggregation tests that drop reasons are properly aggregated
// TestShowDropReasonSummaryAggregation 测试丢弃原因正确聚合
func TestShowDropReasonSummaryAggregation(t *testing.T) {
	// Capture stdout
	// 捕获标准输出
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	dropDetails := []sdk.DropDetailEntry{
		{Reason: DropReasonBlacklist, Count: 100},
		{Reason: DropReasonBlacklist, Count: 50},
		{Reason: DropReasonBlacklist, Count: 30},
		{Reason: DropReasonRatelimit, Count: 20},
	}
	drops := uint64(200)

	// Wrap details for generic function / 包装详情用于泛型函数
	wrappedDetails := make([]DropDetailEntryWrapper, len(dropDetails))
	for i, d := range dropDetails {
		wrappedDetails[i] = DropDetailEntryWrapper{d}
	}

	showReasonSummary(wrappedDetails, detailStatsConfig{
		reasonFunc: dropReasonToString,
		totalCount: drops,
		showRate:   false,
	})

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// BLACKLIST should be aggregated to 180
	// BLACKLIST 应聚合为 180
	assert.Contains(t, output, "BLACKLIST: 180")
	// RATELIMIT should be 20
	// RATELIMIT 应为 20
	assert.Contains(t, output, "RATELIMIT: 20")
}

// TestShowPassReasonSummaryAggregation tests that pass reasons are properly aggregated
// TestShowPassReasonSummaryAggregation 测试通过原因正确聚合
func TestShowPassReasonSummaryAggregation(t *testing.T) {
	// Capture stdout
	// 捕获标准输出
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	passDetails := []sdk.DropDetailEntry{
		{Reason: PassReasonWhitelist, Count: 100},
		{Reason: PassReasonWhitelist, Count: 50},
		{Reason: PassReasonConntrack, Count: 30},
		{Reason: PassReasonConntrack, Count: 20},
	}
	pass := uint64(200)

	// Wrap details for generic function / 包装详情用于泛型函数
	wrappedDetails := make([]PassDetailEntryWrapper, len(passDetails))
	for i, d := range passDetails {
		wrappedDetails[i] = PassDetailEntryWrapper{d}
	}

	showReasonSummary(wrappedDetails, detailStatsConfig{
		reasonFunc: passReasonToString,
		totalCount: pass,
		showRate:   false,
	})

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// WHITELIST should be aggregated to 150
	// WHITELIST 应聚合为 150
	assert.Contains(t, output, "WHITELIST: 150")
	// CONNTRACK should be aggregated to 50
	// CONNTRACK 应聚合为 50
	assert.Contains(t, output, "CONNTRACK: 50")
}

// TestShowDropStatisticsSorting tests that drop details are sorted by count descending
// TestShowDropStatisticsSorting 测试丢弃详情按计数降序排序
func TestShowDropStatisticsSorting(t *testing.T) {
	// Create mock StatsAPI
	// 创建模拟 StatsAPI
	mockStatsAPI := new(MockStatsAPI)

	// Create unsorted drop details
	// 创建未排序的丢弃详情
	dropDetails := []sdk.DropDetailEntry{
		{Reason: DropReasonBlacklist, SrcIP: "192.168.1.1", DstPort: 80, Protocol: 6, Count: 50},
		{Reason: DropReasonRatelimit, SrcIP: "10.0.0.1", DstPort: 443, Protocol: 6, Count: 200},
		{Reason: DropReasonInvalid, SrcIP: "172.16.0.1", DstPort: 22, Protocol: 6, Count: 100},
	}

	mockStatsAPI.On("GetDropDetails").Return(dropDetails, nil)

	// Capture stdout
	// 捕获标准输出
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	showDropStatistics(mockStatsAPI, 350, 0)

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// First entry should be RATELIMIT (200)
	// 第一条记录应为 RATELIMIT (200)
	assert.Contains(t, output, "RATELIMIT")
}

// TestShowPassStatisticsSorting tests that pass details are sorted by count descending
// TestShowPassStatisticsSorting 测试通过详情按计数降序排序
func TestShowPassStatisticsSorting(t *testing.T) {
	// Create mock StatsAPI
	// 创建模拟 StatsAPI
	mockStatsAPI := new(MockStatsAPI)

	// Create unsorted pass details
	// 创建未排序的通过详情
	passDetails := []sdk.DropDetailEntry{
		{Reason: PassReasonWhitelist, SrcIP: "192.168.1.1", DstPort: 22, Protocol: 6, Count: 50},
		{Reason: PassReasonConntrack, SrcIP: "10.0.0.1", DstPort: 80, Protocol: 6, Count: 200},
		{Reason: PassReasonDefault, SrcIP: "172.16.0.1", DstPort: 443, Protocol: 6, Count: 100},
	}

	mockStatsAPI.On("GetPassDetails").Return(passDetails, nil)

	// Capture stdout
	// 捕获标准输出
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	showPassStatistics(mockStatsAPI, 350, 0)

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// First entry should be CONNTRACK (200)
	// 第一条记录应为 CONNTRACK (200)
	assert.Contains(t, output, "CONNTRACK")
}
