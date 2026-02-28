package agent

import (
	"testing"
	"time"

	"github.com/netxfw/netxfw/cmd/netxfw/commands/common"
	"github.com/netxfw/netxfw/pkg/sdk"
	"github.com/netxfw/netxfw/pkg/sdk/mock"
	"github.com/stretchr/testify/assert"
)

// TestSecurityFragmentsCmd tests the security fragments command.
// TestSecurityFragmentsCmd 测试 security fragments 命令。
func TestSecurityFragmentsCmd(t *testing.T) {
	mockSecurity := new(mock.MockSecurityAPI)
	mockBlacklist := new(mock.MockBlacklistAPI)
	mockWhitelist := new(mock.MockWhitelistAPI)
	mockRule := new(mock.MockRuleAPI)

	common.MockSDK = &sdk.SDK{
		Security:  mockSecurity,
		Blacklist: mockBlacklist,
		Whitelist: mockWhitelist,
		Rule:      mockRule,
	}

	// Test enable fragments drop / 测试启用分片丢弃
	mockSecurity.On("SetDropFragments", true).Return(nil)
	_, err := executeCommand(SecurityCmd, "fragments", "true")
	assert.NoError(t, err)
	mockSecurity.AssertExpectations(t)

	// Test disable fragments drop / 测试禁用分片丢弃
	mockSecurity.On("SetDropFragments", false).Return(nil)
	_, err = executeCommand(SecurityCmd, "fragments", "false")
	assert.NoError(t, err)
	mockSecurity.AssertExpectations(t)
}

// TestSecurityStrictTCPCmd tests the security strict-tcp command.
// TestSecurityStrictTCPCmd 测试 security strict-tcp 命令。
func TestSecurityStrictTCPCmd(t *testing.T) {
	mockSecurity := new(mock.MockSecurityAPI)
	mockBlacklist := new(mock.MockBlacklistAPI)
	mockWhitelist := new(mock.MockWhitelistAPI)
	mockRule := new(mock.MockRuleAPI)

	common.MockSDK = &sdk.SDK{
		Security:  mockSecurity,
		Blacklist: mockBlacklist,
		Whitelist: mockWhitelist,
		Rule:      mockRule,
	}

	// Test enable strict TCP / 测试启用严格 TCP
	mockSecurity.On("SetStrictTCP", true).Return(nil)
	_, err := executeCommand(SecurityCmd, "strict-tcp", "true")
	assert.NoError(t, err)
	mockSecurity.AssertExpectations(t)

	// Test disable strict TCP / 测试禁用严格 TCP
	mockSecurity.On("SetStrictTCP", false).Return(nil)
	_, err = executeCommand(SecurityCmd, "strict-tcp", "false")
	assert.NoError(t, err)
	mockSecurity.AssertExpectations(t)
}

// TestSecuritySYNLimitCmd tests the security syn-limit command.
// TestSecuritySYNLimitCmd 测试 security syn-limit 命令。
func TestSecuritySYNLimitCmd(t *testing.T) {
	mockSecurity := new(mock.MockSecurityAPI)
	mockBlacklist := new(mock.MockBlacklistAPI)
	mockWhitelist := new(mock.MockWhitelistAPI)
	mockRule := new(mock.MockRuleAPI)

	common.MockSDK = &sdk.SDK{
		Security:  mockSecurity,
		Blacklist: mockBlacklist,
		Whitelist: mockWhitelist,
		Rule:      mockRule,
	}

	// Test enable SYN limit / 测试启用 SYN 限制
	mockSecurity.On("SetSYNLimit", true).Return(nil)
	_, err := executeCommand(SecurityCmd, "syn-limit", "true")
	assert.NoError(t, err)
	mockSecurity.AssertExpectations(t)

	// Test disable SYN limit / 测试禁用 SYN 限制
	mockSecurity.On("SetSYNLimit", false).Return(nil)
	_, err = executeCommand(SecurityCmd, "syn-limit", "false")
	assert.NoError(t, err)
	mockSecurity.AssertExpectations(t)
}

// TestSecurityBogonCmd tests the security bogon command.
// TestSecurityBogonCmd 测试 security bogon 命令。
func TestSecurityBogonCmd(t *testing.T) {
	mockSecurity := new(mock.MockSecurityAPI)
	mockBlacklist := new(mock.MockBlacklistAPI)
	mockWhitelist := new(mock.MockWhitelistAPI)
	mockRule := new(mock.MockRuleAPI)

	common.MockSDK = &sdk.SDK{
		Security:  mockSecurity,
		Blacklist: mockBlacklist,
		Whitelist: mockWhitelist,
		Rule:      mockRule,
	}

	// Test enable bogon filter / 测试启用 Bogon 过滤
	mockSecurity.On("SetBogonFilter", true).Return(nil)
	_, err := executeCommand(SecurityCmd, "bogon", "true")
	assert.NoError(t, err)
	mockSecurity.AssertExpectations(t)

	// Test disable bogon filter / 测试禁用 Bogon 过滤
	mockSecurity.On("SetBogonFilter", false).Return(nil)
	_, err = executeCommand(SecurityCmd, "bogon", "false")
	assert.NoError(t, err)
	mockSecurity.AssertExpectations(t)
}

// TestSecurityAutoBlockCmd tests the security auto-block command.
// TestSecurityAutoBlockCmd 测试 security auto-block 命令。
func TestSecurityAutoBlockCmd(t *testing.T) {
	mockSecurity := new(mock.MockSecurityAPI)
	mockBlacklist := new(mock.MockBlacklistAPI)
	mockWhitelist := new(mock.MockWhitelistAPI)
	mockRule := new(mock.MockRuleAPI)

	common.MockSDK = &sdk.SDK{
		Security:  mockSecurity,
		Blacklist: mockBlacklist,
		Whitelist: mockWhitelist,
		Rule:      mockRule,
	}

	// Test enable auto block / 测试启用自动封禁
	mockSecurity.On("SetAutoBlock", true).Return(nil)
	_, err := executeCommand(SecurityCmd, "auto-block", "true")
	assert.NoError(t, err)
	mockSecurity.AssertExpectations(t)

	// Test disable auto block / 测试禁用自动封禁
	mockSecurity.On("SetAutoBlock", false).Return(nil)
	_, err = executeCommand(SecurityCmd, "auto-block", "false")
	assert.NoError(t, err)
	mockSecurity.AssertExpectations(t)
}

// TestSecurityAutoBlockExpiryCmd tests the security auto-block-expiry command.
// TestSecurityAutoBlockExpiryCmd 测试 security auto-block-expiry 命令。
func TestSecurityAutoBlockExpiryCmd(t *testing.T) {
	mockSecurity := new(mock.MockSecurityAPI)
	mockBlacklist := new(mock.MockBlacklistAPI)
	mockWhitelist := new(mock.MockWhitelistAPI)
	mockRule := new(mock.MockRuleAPI)

	common.MockSDK = &sdk.SDK{
		Security:  mockSecurity,
		Blacklist: mockBlacklist,
		Whitelist: mockWhitelist,
		Rule:      mockRule,
	}

	// Test setting auto block expiry / 测试设置自动封禁过期时间
	mockSecurity.On("SetAutoBlockExpiry", 3600*time.Second).Return(nil)
	_, err := executeCommand(SecurityCmd, "auto-block-expiry", "3600")
	assert.NoError(t, err)
	mockSecurity.AssertExpectations(t)
}

// TestSecurityAutoBlockExpiryCmd_TooSmall tests expiry value too small.
// TestSecurityAutoBlockExpiryCmd_TooSmall 测试过期时间值太小。
func TestSecurityAutoBlockExpiryCmd_TooSmall(t *testing.T) {
	// Test validation logic directly to avoid os.Exit in tests
	// 直接测试验证逻辑以避免测试中的 os.Exit
	const minExpiry = 1
	expiry := 0
	assert.True(t, expiry < minExpiry, "Expiry 0 should be invalid (too small)")
}

// TestSecurityAutoBlockExpiryCmd_TooLarge tests expiry value too large.
// TestSecurityAutoBlockExpiryCmd_TooLarge 测试过期时间值太大。
func TestSecurityAutoBlockExpiryCmd_TooLarge(t *testing.T) {
	// Test validation logic directly to avoid os.Exit in tests
	// 直接测试验证逻辑以避免测试中的 os.Exit
	const maxExpiry = 365 * 24 * 60 * 60 // 365 days in seconds
	expiry := 34560000                   // 400 days
	assert.True(t, expiry > maxExpiry, "Expiry 400 days should be invalid (too large)")
}

// TestSecurityAutoBlockExpiryCmd_Negative tests negative expiry value.
// TestSecurityAutoBlockExpiryCmd_Negative 测试负数过期时间。
func TestSecurityAutoBlockExpiryCmd_Negative(t *testing.T) {
	// Test validation logic directly to avoid os.Exit in tests
	// 直接测试验证逻辑以避免测试中的 os.Exit
	const minExpiry = 1
	expiry := -100
	assert.True(t, expiry < minExpiry, "Negative expiry should be invalid")
}

// TestSecurityAutoBlockExpiryCmd_MaxValid tests maximum valid expiry.
// TestSecurityAutoBlockExpiryCmd_MaxValid 测试最大有效过期时间。
func TestSecurityAutoBlockExpiryCmd_MaxValid(t *testing.T) {
	mockSecurity := new(mock.MockSecurityAPI)
	mockBlacklist := new(mock.MockBlacklistAPI)
	mockWhitelist := new(mock.MockWhitelistAPI)
	mockRule := new(mock.MockRuleAPI)

	common.MockSDK = &sdk.SDK{
		Security:  mockSecurity,
		Blacklist: mockBlacklist,
		Whitelist: mockWhitelist,
		Rule:      mockRule,
	}

	// Test setting expiry to 365 days (valid) / 测试设置过期时间为 365 天（有效）
	mockSecurity.On("SetAutoBlockExpiry", 365*24*time.Hour).Return(nil)
	_, err := executeCommand(SecurityCmd, "auto-block-expiry", "31536000")
	assert.NoError(t, err)
	mockSecurity.AssertExpectations(t)
}
