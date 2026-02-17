package agent

import (
	"testing"
	"time"

	"github.com/livp123/netxfw/cmd/netxfw/commands/common"
	"github.com/livp123/netxfw/pkg/sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockSecurity implements the Security interface for testing
// MockSecurity 实现用于测试的 Security 接口
type MockSecurity struct {
	mock.Mock
}

func (m *MockSecurity) SetDropFragments(enable bool) error {
	args := m.Called(enable)
	return args.Error(0)
}

func (m *MockSecurity) SetStrictTCP(enable bool) error {
	args := m.Called(enable)
	return args.Error(0)
}

func (m *MockSecurity) SetSYNLimit(enable bool) error {
	args := m.Called(enable)
	return args.Error(0)
}

func (m *MockSecurity) SetBogonFilter(enable bool) error {
	args := m.Called(enable)
	return args.Error(0)
}

func (m *MockSecurity) SetAutoBlock(enable bool) error {
	args := m.Called(enable)
	return args.Error(0)
}

func (m *MockSecurity) SetAutoBlockExpiry(duration time.Duration) error {
	args := m.Called(duration)
	return args.Error(0)
}

func (m *MockSecurity) SetStrictProtocol(enable bool) error {
	args := m.Called(enable)
	return args.Error(0)
}

func (m *MockSecurity) SetDefaultDeny(enable bool) error {
	args := m.Called(enable)
	return args.Error(0)
}

func (m *MockSecurity) SetEnableAFXDP(enable bool) error {
	args := m.Called(enable)
	return args.Error(0)
}

func (m *MockSecurity) SetConntrack(enable bool) error {
	args := m.Called(enable)
	return args.Error(0)
}

func (m *MockSecurity) SetConntrackTimeout(duration time.Duration) error {
	args := m.Called(duration)
	return args.Error(0)
}

// TestSecurityFragmentsCmd tests the security fragments command
// TestSecurityFragmentsCmd 测试 security fragments 命令
func TestSecurityFragmentsCmd(t *testing.T) {
	mockSecurity := new(MockSecurity)
	mockBlacklist := new(MockBlacklist)
	mockWhitelist := new(MockWhitelist)
	mockRule := new(MockRule)

	common.MockSDK = &sdk.SDK{
		Security:  mockSecurity,
		Blacklist: mockBlacklist,
		Whitelist: mockWhitelist,
		Rule:      mockRule,
	}

	// Test enable fragments drop
	// 测试启用分片丢弃
	mockSecurity.On("SetDropFragments", true).Return(nil)
	_, err := executeCommand(SecurityCmd, "fragments", "true")
	assert.NoError(t, err)
	mockSecurity.AssertExpectations(t)

	// Test disable fragments drop
	// 测试禁用分片丢弃
	mockSecurity.On("SetDropFragments", false).Return(nil)
	_, err = executeCommand(SecurityCmd, "fragments", "false")
	assert.NoError(t, err)
	mockSecurity.AssertExpectations(t)
}

// TestSecurityStrictTCPCmd tests the security strict-tcp command
// TestSecurityStrictTCPCmd 测试 security strict-tcp 命令
func TestSecurityStrictTCPCmd(t *testing.T) {
	mockSecurity := new(MockSecurity)
	mockBlacklist := new(MockBlacklist)
	mockWhitelist := new(MockWhitelist)
	mockRule := new(MockRule)

	common.MockSDK = &sdk.SDK{
		Security:  mockSecurity,
		Blacklist: mockBlacklist,
		Whitelist: mockWhitelist,
		Rule:      mockRule,
	}

	// Test enable strict TCP
	// 测试启用严格 TCP
	mockSecurity.On("SetStrictTCP", true).Return(nil)
	_, err := executeCommand(SecurityCmd, "strict-tcp", "true")
	assert.NoError(t, err)
	mockSecurity.AssertExpectations(t)

	// Test disable strict TCP
	// 测试禁用严格 TCP
	mockSecurity.On("SetStrictTCP", false).Return(nil)
	_, err = executeCommand(SecurityCmd, "strict-tcp", "false")
	assert.NoError(t, err)
	mockSecurity.AssertExpectations(t)
}

// TestSecuritySYNLimitCmd tests the security syn-limit command
// TestSecuritySYNLimitCmd 测试 security syn-limit 命令
func TestSecuritySYNLimitCmd(t *testing.T) {
	mockSecurity := new(MockSecurity)
	mockBlacklist := new(MockBlacklist)
	mockWhitelist := new(MockWhitelist)
	mockRule := new(MockRule)

	common.MockSDK = &sdk.SDK{
		Security:  mockSecurity,
		Blacklist: mockBlacklist,
		Whitelist: mockWhitelist,
		Rule:      mockRule,
	}

	// Test enable SYN limit
	// 测试启用 SYN 限制
	mockSecurity.On("SetSYNLimit", true).Return(nil)
	_, err := executeCommand(SecurityCmd, "syn-limit", "true")
	assert.NoError(t, err)
	mockSecurity.AssertExpectations(t)

	// Test disable SYN limit
	// 测试禁用 SYN 限制
	mockSecurity.On("SetSYNLimit", false).Return(nil)
	_, err = executeCommand(SecurityCmd, "syn-limit", "false")
	assert.NoError(t, err)
	mockSecurity.AssertExpectations(t)
}

// TestSecurityBogonCmd tests the security bogon command
// TestSecurityBogonCmd 测试 security bogon 命令
func TestSecurityBogonCmd(t *testing.T) {
	mockSecurity := new(MockSecurity)
	mockBlacklist := new(MockBlacklist)
	mockWhitelist := new(MockWhitelist)
	mockRule := new(MockRule)

	common.MockSDK = &sdk.SDK{
		Security:  mockSecurity,
		Blacklist: mockBlacklist,
		Whitelist: mockWhitelist,
		Rule:      mockRule,
	}

	// Test enable bogon filter
	// 测试启用 Bogon 过滤
	mockSecurity.On("SetBogonFilter", true).Return(nil)
	_, err := executeCommand(SecurityCmd, "bogon", "true")
	assert.NoError(t, err)
	mockSecurity.AssertExpectations(t)

	// Test disable bogon filter
	// 测试禁用 Bogon 过滤
	mockSecurity.On("SetBogonFilter", false).Return(nil)
	_, err = executeCommand(SecurityCmd, "bogon", "false")
	assert.NoError(t, err)
	mockSecurity.AssertExpectations(t)
}

// TestSecurityAutoBlockCmd tests the security auto-block command
// TestSecurityAutoBlockCmd 测试 security auto-block 命令
func TestSecurityAutoBlockCmd(t *testing.T) {
	mockSecurity := new(MockSecurity)
	mockBlacklist := new(MockBlacklist)
	mockWhitelist := new(MockWhitelist)
	mockRule := new(MockRule)

	common.MockSDK = &sdk.SDK{
		Security:  mockSecurity,
		Blacklist: mockBlacklist,
		Whitelist: mockWhitelist,
		Rule:      mockRule,
	}

	// Test enable auto-block
	// 测试启用自动封锁
	mockSecurity.On("SetAutoBlock", true).Return(nil)
	_, err := executeCommand(SecurityCmd, "auto-block", "true")
	assert.NoError(t, err)
	mockSecurity.AssertExpectations(t)

	// Test disable auto-block
	// 测试禁用自动封锁
	mockSecurity.On("SetAutoBlock", false).Return(nil)
	_, err = executeCommand(SecurityCmd, "auto-block", "false")
	assert.NoError(t, err)
	mockSecurity.AssertExpectations(t)
}

// TestSecurityAutoBlockExpiryCmd tests the security auto-block-expiry command
// TestSecurityAutoBlockExpiryCmd 测试 security auto-block-expiry 命令
func TestSecurityAutoBlockExpiryCmd(t *testing.T) {
	mockSecurity := new(MockSecurity)
	mockBlacklist := new(MockBlacklist)
	mockWhitelist := new(MockWhitelist)
	mockRule := new(MockRule)

	common.MockSDK = &sdk.SDK{
		Security:  mockSecurity,
		Blacklist: mockBlacklist,
		Whitelist: mockWhitelist,
		Rule:      mockRule,
	}

	// Test set auto-block expiry
	// 测试设置自动封锁过期时间
	mockSecurity.On("SetAutoBlockExpiry", 3600*time.Second).Return(nil)
	_, err := executeCommand(SecurityCmd, "auto-block-expiry", "3600")
	assert.NoError(t, err)
	mockSecurity.AssertExpectations(t)
}

// TestSecurityBooleanFormats tests various boolean input formats
// TestSecurityBooleanFormats 测试各种布尔输入格式
func TestSecurityBooleanFormats(t *testing.T) {
	mockSecurity := new(MockSecurity)
	mockBlacklist := new(MockBlacklist)
	mockWhitelist := new(MockWhitelist)
	mockRule := new(MockRule)

	common.MockSDK = &sdk.SDK{
		Security:  mockSecurity,
		Blacklist: mockBlacklist,
		Whitelist: mockWhitelist,
		Rule:      mockRule,
	}

	// Test "1" format
	// 测试 "1" 格式
	mockSecurity.On("SetDropFragments", true).Return(nil)
	_, err := executeCommand(SecurityCmd, "fragments", "1")
	assert.NoError(t, err)
	mockSecurity.AssertExpectations(t)

	// Test "0" format
	// 测试 "0" 格式
	mockSecurity.On("SetDropFragments", false).Return(nil)
	_, err = executeCommand(SecurityCmd, "fragments", "0")
	assert.NoError(t, err)
	mockSecurity.AssertExpectations(t)
}

// TestSecurityAutoBlockExpiryValues tests various expiry values
// TestSecurityAutoBlockExpiryValues 测试各种过期时间值
func TestSecurityAutoBlockExpiryValues(t *testing.T) {
	mockSecurity := new(MockSecurity)
	mockBlacklist := new(MockBlacklist)
	mockWhitelist := new(MockWhitelist)
	mockRule := new(MockRule)

	common.MockSDK = &sdk.SDK{
		Security:  mockSecurity,
		Blacklist: mockBlacklist,
		Whitelist: mockWhitelist,
		Rule:      mockRule,
	}

	// Test 1 hour
	// 测试 1 小时
	mockSecurity.On("SetAutoBlockExpiry", 3600*time.Second).Return(nil)
	_, err := executeCommand(SecurityCmd, "auto-block-expiry", "3600")
	assert.NoError(t, err)
	mockSecurity.AssertExpectations(t)

	// Test 24 hours
	// 测试 24 小时
	mockSecurity.On("SetAutoBlockExpiry", 86400*time.Second).Return(nil)
	_, err = executeCommand(SecurityCmd, "auto-block-expiry", "86400")
	assert.NoError(t, err)
	mockSecurity.AssertExpectations(t)

	// Test 7 days
	// 测试 7 天
	mockSecurity.On("SetAutoBlockExpiry", 604800*time.Second).Return(nil)
	_, err = executeCommand(SecurityCmd, "auto-block-expiry", "604800")
	assert.NoError(t, err)
	mockSecurity.AssertExpectations(t)
}

// TestSecurityFragmentsEnable tests enabling fragments drop
// TestSecurityFragmentsEnable 测试启用分片丢弃
func TestSecurityFragmentsEnable(t *testing.T) {
	mockSecurity := new(MockSecurity)
	mockBlacklist := new(MockBlacklist)
	mockWhitelist := new(MockWhitelist)
	mockRule := new(MockRule)

	common.MockSDK = &sdk.SDK{
		Security:  mockSecurity,
		Blacklist: mockBlacklist,
		Whitelist: mockWhitelist,
		Rule:      mockRule,
	}

	mockSecurity.On("SetDropFragments", true).Return(nil)
	_, err := executeCommand(SecurityCmd, "fragments", "true")
	assert.NoError(t, err)
	mockSecurity.AssertExpectations(t)
}

// TestSecurityStrictTCPEnable tests enabling strict TCP
// TestSecurityStrictTCPEnable 测试启用严格 TCP
func TestSecurityStrictTCPEnable(t *testing.T) {
	mockSecurity := new(MockSecurity)
	mockBlacklist := new(MockBlacklist)
	mockWhitelist := new(MockWhitelist)
	mockRule := new(MockRule)

	common.MockSDK = &sdk.SDK{
		Security:  mockSecurity,
		Blacklist: mockBlacklist,
		Whitelist: mockWhitelist,
		Rule:      mockRule,
	}

	mockSecurity.On("SetStrictTCP", true).Return(nil)
	_, err := executeCommand(SecurityCmd, "strict-tcp", "true")
	assert.NoError(t, err)
	mockSecurity.AssertExpectations(t)
}

// TestSecuritySYNLimitEnable tests enabling SYN limit
// TestSecuritySYNLimitEnable 测试启用 SYN 限制
func TestSecuritySYNLimitEnable(t *testing.T) {
	mockSecurity := new(MockSecurity)
	mockBlacklist := new(MockBlacklist)
	mockWhitelist := new(MockWhitelist)
	mockRule := new(MockRule)

	common.MockSDK = &sdk.SDK{
		Security:  mockSecurity,
		Blacklist: mockBlacklist,
		Whitelist: mockWhitelist,
		Rule:      mockRule,
	}

	mockSecurity.On("SetSYNLimit", true).Return(nil)
	_, err := executeCommand(SecurityCmd, "syn-limit", "true")
	assert.NoError(t, err)
	mockSecurity.AssertExpectations(t)
}

// TestSecurityBogonEnable tests enabling bogon filter
// TestSecurityBogonEnable 测试启用 Bogon 过滤
func TestSecurityBogonEnable(t *testing.T) {
	mockSecurity := new(MockSecurity)
	mockBlacklist := new(MockBlacklist)
	mockWhitelist := new(MockWhitelist)
	mockRule := new(MockRule)

	common.MockSDK = &sdk.SDK{
		Security:  mockSecurity,
		Blacklist: mockBlacklist,
		Whitelist: mockWhitelist,
		Rule:      mockRule,
	}

	mockSecurity.On("SetBogonFilter", true).Return(nil)
	_, err := executeCommand(SecurityCmd, "bogon", "true")
	assert.NoError(t, err)
	mockSecurity.AssertExpectations(t)
}

// TestSecurityAutoBlockEnable tests enabling auto-block
// TestSecurityAutoBlockEnable 测试启用自动封锁
func TestSecurityAutoBlockEnable(t *testing.T) {
	mockSecurity := new(MockSecurity)
	mockBlacklist := new(MockBlacklist)
	mockWhitelist := new(MockWhitelist)
	mockRule := new(MockRule)

	common.MockSDK = &sdk.SDK{
		Security:  mockSecurity,
		Blacklist: mockBlacklist,
		Whitelist: mockWhitelist,
		Rule:      mockRule,
	}

	mockSecurity.On("SetAutoBlock", true).Return(nil)
	_, err := executeCommand(SecurityCmd, "auto-block", "true")
	assert.NoError(t, err)
	mockSecurity.AssertExpectations(t)
}
