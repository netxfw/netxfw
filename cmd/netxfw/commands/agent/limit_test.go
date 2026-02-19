package agent

import (
	"testing"

	"github.com/livp123/netxfw/cmd/netxfw/commands/common"
	"github.com/livp123/netxfw/pkg/sdk"
	"github.com/livp123/netxfw/pkg/sdk/mock"
	"github.com/stretchr/testify/assert"
)

// TestLimitAddCmd tests the limit add command.
// TestLimitAddCmd 测试 limit add 命令。
func TestLimitAddCmd(t *testing.T) {
	mockBlacklist := new(mock.MockBlacklistAPI)
	mockWhitelist := new(mock.MockWhitelistAPI)
	mockRule := new(mock.MockRuleAPI)
	mockSecurity := new(mock.MockSecurityAPI)

	common.MockSDK = &sdk.SDK{
		Blacklist: mockBlacklist,
		Whitelist: mockWhitelist,
		Rule:      mockRule,
		Security:  mockSecurity,
	}

	// Test adding rate limit rule / 测试添加限速规则
	mockRule.On("AddRateLimitRule", "192.168.1.1", uint64(100), uint64(200)).Return(nil)
	_, err := executeCommand(LimitCmd, "add", "192.168.1.1", "100", "200")
	assert.NoError(t, err)
	mockRule.AssertExpectations(t)
}

// TestLimitRemoveCmd tests the limit remove command.
// TestLimitRemoveCmd 测试 limit remove 命令。
func TestLimitRemoveCmd(t *testing.T) {
	mockBlacklist := new(mock.MockBlacklistAPI)
	mockWhitelist := new(mock.MockWhitelistAPI)
	mockRule := new(mock.MockRuleAPI)
	mockSecurity := new(mock.MockSecurityAPI)

	common.MockSDK = &sdk.SDK{
		Blacklist: mockBlacklist,
		Whitelist: mockWhitelist,
		Rule:      mockRule,
		Security:  mockSecurity,
	}

	// Test removing rate limit rule / 测试移除限速规则
	mockRule.On("RemoveRateLimitRule", "192.168.1.1").Return(nil)
	_, err := executeCommand(LimitCmd, "remove", "192.168.1.1")
	assert.NoError(t, err)
	mockRule.AssertExpectations(t)
}

// TestLimitListCmd tests the limit list command.
// TestLimitListCmd 测试 limit list 命令。
func TestLimitListCmd(t *testing.T) {
	mockBlacklist := new(mock.MockBlacklistAPI)
	mockWhitelist := new(mock.MockWhitelistAPI)
	mockRule := new(mock.MockRuleAPI)
	mockSecurity := new(mock.MockSecurityAPI)

	common.MockSDK = &sdk.SDK{
		Blacklist: mockBlacklist,
		Whitelist: mockWhitelist,
		Rule:      mockRule,
		Security:  mockSecurity,
	}

	// Test listing rate limit rules / 测试列出限速规则
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

// TestLimitListEmpty tests listing when no rules exist.
// TestLimitListEmpty 测试无规则时列出。
func TestLimitListEmpty(t *testing.T) {
	mockBlacklist := new(mock.MockBlacklistAPI)
	mockWhitelist := new(mock.MockWhitelistAPI)
	mockRule := new(mock.MockRuleAPI)
	mockSecurity := new(mock.MockSecurityAPI)

	common.MockSDK = &sdk.SDK{
		Blacklist: mockBlacklist,
		Whitelist: mockWhitelist,
		Rule:      mockRule,
		Security:  mockSecurity,
	}

	// Test listing empty rules / 测试列出空规则
	mockRule.On("ListRateLimitRules", 100, "").Return(map[string]sdk.RateLimitConf{}, 0, nil)
	output, err := executeCommand(LimitCmd, "list")
	assert.NoError(t, err)
	assert.Contains(t, output, "Rate Limit Rules")
	mockRule.AssertExpectations(t)
}
