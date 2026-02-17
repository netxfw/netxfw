package agent

import (
	"testing"

	"github.com/livp123/netxfw/cmd/netxfw/commands/common"
	"github.com/livp123/netxfw/pkg/sdk"
	"github.com/stretchr/testify/assert"
)

// TestLimitAddCmd tests the limit add command
// TestLimitAddCmd 测试 limit add 命令
func TestLimitAddCmd(t *testing.T) {
	mockBlacklist := new(MockBlacklist)
	mockWhitelist := new(MockWhitelist)
	mockRule := new(MockRule)
	mockSecurity := new(MockSecurity)

	common.MockSDK = &sdk.SDK{
		Blacklist: mockBlacklist,
		Whitelist: mockWhitelist,
		Rule:      mockRule,
		Security:  mockSecurity,
	}

	// Test adding rate limit rule
	// 测试添加限速规则
	mockRule.On("AddRateLimitRule", "192.168.1.1", uint64(100), uint64(200)).Return(nil)
	_, err := executeCommand(LimitCmd, "add", "192.168.1.1", "100", "200")
	assert.NoError(t, err)
	mockRule.AssertExpectations(t)
}

// TestLimitRemoveCmd tests the limit remove command
// TestLimitRemoveCmd 测试 limit remove 命令
func TestLimitRemoveCmd(t *testing.T) {
	mockBlacklist := new(MockBlacklist)
	mockWhitelist := new(MockWhitelist)
	mockRule := new(MockRule)
	mockSecurity := new(MockSecurity)

	common.MockSDK = &sdk.SDK{
		Blacklist: mockBlacklist,
		Whitelist: mockWhitelist,
		Rule:      mockRule,
		Security:  mockSecurity,
	}

	// Test removing rate limit rule
	// 测试移除限速规则
	mockRule.On("RemoveRateLimitRule", "192.168.1.1").Return(nil)
	_, err := executeCommand(LimitCmd, "remove", "192.168.1.1")
	assert.NoError(t, err)
	mockRule.AssertExpectations(t)
}

// TestLimitListCmd tests the limit list command
// TestLimitListCmd 测试 limit list 命令
func TestLimitListCmd(t *testing.T) {
	mockBlacklist := new(MockBlacklist)
	mockWhitelist := new(MockWhitelist)
	mockRule := new(MockRule)
	mockSecurity := new(MockSecurity)

	common.MockSDK = &sdk.SDK{
		Blacklist: mockBlacklist,
		Whitelist: mockWhitelist,
		Rule:      mockRule,
		Security:  mockSecurity,
	}

	// Test listing rate limit rules
	// 测试列出限速规则
	rules := map[string]sdk.RateLimitConf{
		"192.168.1.1": {Rate: 100, Burst: 200},
		"10.0.0.1":    {Rate: 50, Burst: 100},
	}
	mockRule.On("ListRateLimitRules", 100, "").Return(rules, 2, nil)
	output, err := executeCommand(LimitCmd, "list")
	assert.NoError(t, err)
	assert.Contains(t, output, "Rate Limit Rules")
	mockRule.AssertExpectations(t)
}

// TestLimitListEmpty tests listing when no rules exist
// TestLimitListEmpty 测试无规则时列出
func TestLimitListEmpty(t *testing.T) {
	mockBlacklist := new(MockBlacklist)
	mockWhitelist := new(MockWhitelist)
	mockRule := new(MockRule)
	mockSecurity := new(MockSecurity)

	common.MockSDK = &sdk.SDK{
		Blacklist: mockBlacklist,
		Whitelist: mockWhitelist,
		Rule:      mockRule,
		Security:  mockSecurity,
	}

	// Test listing empty rules
	// 测试列出空规则
	rules := map[string]sdk.RateLimitConf{}
	mockRule.On("ListRateLimitRules", 100, "").Return(rules, 0, nil)
	output, err := executeCommand(LimitCmd, "list")
	assert.NoError(t, err)
	assert.Contains(t, output, "Rate Limit Rules")
	mockRule.AssertExpectations(t)
}

// TestLimitAddHighValues tests adding with high rate/burst values
// TestLimitAddHighValues 测试使用高速率/突发值添加
func TestLimitAddHighValues(t *testing.T) {
	mockBlacklist := new(MockBlacklist)
	mockWhitelist := new(MockWhitelist)
	mockRule := new(MockRule)
	mockSecurity := new(MockSecurity)

	common.MockSDK = &sdk.SDK{
		Blacklist: mockBlacklist,
		Whitelist: mockWhitelist,
		Rule:      mockRule,
		Security:  mockSecurity,
	}

	// Test adding with high values
	// 测试使用高值添加
	mockRule.On("AddRateLimitRule", "192.168.1.1", uint64(1000000), uint64(2000000)).Return(nil)
	_, err := executeCommand(LimitCmd, "add", "192.168.1.1", "1000000", "2000000")
	assert.NoError(t, err)
	mockRule.AssertExpectations(t)
}

// TestLimitAddIPv6 tests adding rate limit for IPv6
// TestLimitAddIPv6 测试为 IPv6 添加限速
func TestLimitAddIPv6(t *testing.T) {
	mockBlacklist := new(MockBlacklist)
	mockWhitelist := new(MockWhitelist)
	mockRule := new(MockRule)
	mockSecurity := new(MockSecurity)

	common.MockSDK = &sdk.SDK{
		Blacklist: mockBlacklist,
		Whitelist: mockWhitelist,
		Rule:      mockRule,
		Security:  mockSecurity,
	}

	// Test adding IPv6 rate limit
	// 测试添加 IPv6 限速
	mockRule.On("AddRateLimitRule", "2001:db8::1", uint64(100), uint64(200)).Return(nil)
	_, err := executeCommand(LimitCmd, "add", "2001:db8::1", "100", "200")
	assert.NoError(t, err)
	mockRule.AssertExpectations(t)
}

// TestLimitAddCIDR tests adding rate limit for CIDR
// TestLimitAddCIDR 测试为 CIDR 添加限速
func TestLimitAddCIDR(t *testing.T) {
	mockBlacklist := new(MockBlacklist)
	mockWhitelist := new(MockWhitelist)
	mockRule := new(MockRule)
	mockSecurity := new(MockSecurity)

	common.MockSDK = &sdk.SDK{
		Blacklist: mockBlacklist,
		Whitelist: mockWhitelist,
		Rule:      mockRule,
		Security:  mockSecurity,
	}

	// Test adding CIDR rate limit
	// 测试添加 CIDR 限速
	mockRule.On("AddRateLimitRule", "192.168.1.0/24", uint64(100), uint64(200)).Return(nil)
	_, err := executeCommand(LimitCmd, "add", "192.168.1.0/24", "100", "200")
	assert.NoError(t, err)
	mockRule.AssertExpectations(t)
}

// TestLimitRemoveIPv6 tests removing IPv6 rate limit
// TestLimitRemoveIPv6 测试移除 IPv6 限速
func TestLimitRemoveIPv6(t *testing.T) {
	mockBlacklist := new(MockBlacklist)
	mockWhitelist := new(MockWhitelist)
	mockRule := new(MockRule)
	mockSecurity := new(MockSecurity)

	common.MockSDK = &sdk.SDK{
		Blacklist: mockBlacklist,
		Whitelist: mockWhitelist,
		Rule:      mockRule,
		Security:  mockSecurity,
	}

	// Test removing IPv6 rate limit
	// 测试移除 IPv6 限速
	mockRule.On("RemoveRateLimitRule", "2001:db8::1").Return(nil)
	_, err := executeCommand(LimitCmd, "remove", "2001:db8::1")
	assert.NoError(t, err)
	mockRule.AssertExpectations(t)
}
