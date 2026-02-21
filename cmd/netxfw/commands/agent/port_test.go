package agent

import (
	"testing"

	"github.com/netxfw/netxfw/cmd/netxfw/commands/common"
	"github.com/netxfw/netxfw/pkg/sdk"
	"github.com/netxfw/netxfw/pkg/sdk/mock"
	"github.com/stretchr/testify/assert"
)

// TestPortAddCmd tests the port add command.
// TestPortAddCmd 测试 port add 命令。
func TestPortAddCmd(t *testing.T) {
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

	// Test adding port 80 / 测试添加端口 80
	mockRule.On("AllowPort", uint16(80)).Return(nil)
	_, err := executeCommand(PortCmd, "add", "80")
	assert.NoError(t, err)
	mockRule.AssertExpectations(t)
}

// TestPortAddCmd_Port443 tests adding port 443.
// TestPortAddCmd_Port443 测试添加端口 443。
func TestPortAddCmd_Port443(t *testing.T) {
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

	// Test adding port 443 / 测试添加端口 443
	mockRule.On("AllowPort", uint16(443)).Return(nil)
	_, err := executeCommand(PortCmd, "add", "443")
	assert.NoError(t, err)
	mockRule.AssertExpectations(t)
}

// TestPortRemoveCmd tests the port remove command.
// TestPortRemoveCmd 测试 port remove 命令。
func TestPortRemoveCmd(t *testing.T) {
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

	// Test removing port 80 / 测试移除端口 80
	mockRule.On("RemoveAllowedPort", uint16(80)).Return(nil)
	_, err := executeCommand(PortCmd, "remove", "80")
	assert.NoError(t, err)
	mockRule.AssertExpectations(t)
}

// TestPortAddHighPort tests adding high port number.
// TestPortAddHighPort 测试添加高端口号。
func TestPortAddHighPort(t *testing.T) {
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

	// Test adding high port / 测试添加高端口
	mockRule.On("AllowPort", uint16(65535)).Return(nil)
	_, err := executeCommand(PortCmd, "add", "65535")
	assert.NoError(t, err)
	mockRule.AssertExpectations(t)
}
