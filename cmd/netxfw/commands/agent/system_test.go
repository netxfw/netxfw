package agent

import (
	"testing"

	"github.com/livp123/netxfw/cmd/netxfw/commands/common"
	"github.com/livp123/netxfw/pkg/sdk"
	"github.com/stretchr/testify/assert"
)

// TestSystemCmd tests the system command
// TestSystemCmd 测试 system 命令
func TestSystemCmd(t *testing.T) {
	mockBlacklist := new(MockBlacklist)
	mockWhitelist := new(MockWhitelist)
	mockRule := new(MockRule)
	mockSecurity := new(MockSecurity)
	mockStats := new(MockStats)
	mockSync := new(MockSync)

	common.MockSDK = &sdk.SDK{
		Blacklist: mockBlacklist,
		Whitelist: mockWhitelist,
		Rule:      mockRule,
		Security:  mockSecurity,
		Stats:     mockStats,
		Sync:      mockSync,
	}

	// Test system command (should show help)
	// 测试 system 命令（应显示帮助）
	_, err := executeCommand(SystemCmd)
	assert.NoError(t, err)
}

// TestSystemStatusCmd tests the system status command
// TestSystemStatusCmd 测试 system status 命令
func TestSystemStatusCmd(t *testing.T) {
	mockBlacklist := new(MockBlacklist)
	mockWhitelist := new(MockWhitelist)
	mockRule := new(MockRule)
	mockSecurity := new(MockSecurity)
	mockStats := new(MockStats)
	mockSync := new(MockSync)

	common.MockSDK = &sdk.SDK{
		Blacklist: mockBlacklist,
		Whitelist: mockWhitelist,
		Rule:      mockRule,
		Security:  mockSecurity,
		Stats:     mockStats,
		Sync:      mockSync,
	}

	// Test system status command
	// 测试 system status 命令
	mockStats.On("GetCounters").Return(uint64(100), uint64(50), nil)
	mockStats.On("GetDropDetails").Return([]sdk.DropDetailEntry{}, nil)
	_, err := executeCommand(SystemCmd, "status")
	assert.NoError(t, err)
}

// TestSystemStatusWithHighValues tests system status with high values
// TestSystemStatusWithHighValues 测试高值的 system status 命令
func TestSystemStatusWithHighValues(t *testing.T) {
	mockBlacklist := new(MockBlacklist)
	mockWhitelist := new(MockWhitelist)
	mockRule := new(MockRule)
	mockSecurity := new(MockSecurity)
	mockStats := new(MockStats)
	mockSync := new(MockSync)

	common.MockSDK = &sdk.SDK{
		Blacklist: mockBlacklist,
		Whitelist: mockWhitelist,
		Rule:      mockRule,
		Security:  mockSecurity,
		Stats:     mockStats,
		Sync:      mockSync,
	}

	// Test with high counter values
	// 测试高计数器值
	mockStats.On("GetCounters").Return(uint64(1000000), uint64(500000), nil)
	mockStats.On("GetDropDetails").Return([]sdk.DropDetailEntry{}, nil)
	_, err := executeCommand(SystemCmd, "status")
	assert.NoError(t, err)
}

// TestSystemStatusZeroCounters tests system status with zero counters
// TestSystemStatusZeroCounters 测试零计数器的 system status 命令
func TestSystemStatusZeroCounters(t *testing.T) {
	mockBlacklist := new(MockBlacklist)
	mockWhitelist := new(MockWhitelist)
	mockRule := new(MockRule)
	mockSecurity := new(MockSecurity)
	mockStats := new(MockStats)
	mockSync := new(MockSync)

	common.MockSDK = &sdk.SDK{
		Blacklist: mockBlacklist,
		Whitelist: mockWhitelist,
		Rule:      mockRule,
		Security:  mockSecurity,
		Stats:     mockStats,
		Sync:      mockSync,
	}

	// Test with zero counters
	// 测试零计数器
	mockStats.On("GetCounters").Return(uint64(0), uint64(0), nil)
	mockStats.On("GetDropDetails").Return([]sdk.DropDetailEntry{}, nil)
	_, err := executeCommand(SystemCmd, "status")
	assert.NoError(t, err)
}
