package agent

import (
	"testing"

	"github.com/livp123/netxfw/cmd/netxfw/commands/common"
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/pkg/sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockStats implements the Stats interface for testing
// MockStats 实现用于测试的 Stats 接口
type MockStats struct {
	mock.Mock
}

func (m *MockStats) GetCounters() (uint64, uint64, error) {
	args := m.Called()
	return args.Get(0).(uint64), args.Get(1).(uint64), args.Error(2)
}

func (m *MockStats) GetDropDetails() ([]sdk.DropDetailEntry, error) {
	args := m.Called()
	return args.Get(0).([]sdk.DropDetailEntry), args.Error(1)
}

func (m *MockStats) GetPassDetails() ([]sdk.DropDetailEntry, error) {
	args := m.Called()
	return args.Get(0).([]sdk.DropDetailEntry), args.Error(1)
}

func (m *MockStats) GetLockedIPCount() (int, error) {
	args := m.Called()
	return args.Get(0).(int), args.Error(1)
}

// MockSync implements the Sync interface for testing
// MockSync 实现用于测试的 Sync 接口
type MockSync struct {
	mock.Mock
}

func (m *MockSync) ToConfig(cfg *types.GlobalConfig) error {
	args := m.Called(cfg)
	return args.Error(0)
}

func (m *MockSync) ToMap(cfg *types.GlobalConfig, force bool) error {
	args := m.Called(cfg, force)
	return args.Error(0)
}

func (m *MockSync) VerifyAndRepair(cfg *types.GlobalConfig) error {
	args := m.Called(cfg)
	return args.Error(0)
}

// TestVersionCmd tests the version command
// TestVersionCmd 测试 version 命令
func TestVersionCmd(t *testing.T) {
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

	// Test version command
	// 测试 version 命令
	mockStats.On("GetCounters").Return(uint64(100), uint64(50), nil)
	_, err := executeCommand(VersionCmd)
	assert.NoError(t, err)
	mockStats.AssertExpectations(t)
}

// TestVersionCmdWithStats tests version command with stats
// TestVersionCmdWithStats 测试带统计信息的 version 命令
func TestVersionCmdWithStats(t *testing.T) {
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

	// Test version with specific stats
	// 测试带特定统计信息的 version
	mockStats.On("GetCounters").Return(uint64(1000), uint64(500), nil)
	_, err := executeCommand(VersionCmd)
	assert.NoError(t, err)
	mockStats.AssertExpectations(t)
}

// TestVersionCmdHighCounters tests version with high counter values
// TestVersionCmdHighCounters 测试高计数器值的 version 命令
func TestVersionCmdHighCounters(t *testing.T) {
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
	mockStats.On("GetCounters").Return(uint64(999999), uint64(888888), nil)
	_, err := executeCommand(VersionCmd)
	assert.NoError(t, err)
	mockStats.AssertExpectations(t)
}
