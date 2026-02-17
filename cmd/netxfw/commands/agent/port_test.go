package agent

import (
	"testing"

	"github.com/livp123/netxfw/cmd/netxfw/commands/common"
	"github.com/livp123/netxfw/pkg/sdk"
	"github.com/stretchr/testify/assert"
)

// TestPortAddCmd tests the port add command
// TestPortAddCmd 测试 port add 命令
func TestPortAddCmd(t *testing.T) {
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

	// Test adding port 80
	// 测试添加端口 80
	mockRule.On("AllowPort", uint16(80)).Return(nil)
	_, err := executeCommand(PortCmd, "add", "80")
	assert.NoError(t, err)
	mockRule.AssertExpectations(t)
}

// TestPortAddCmd_Port443 tests adding port 443
// TestPortAddCmd_Port443 测试添加端口 443
func TestPortAddCmd_Port443(t *testing.T) {
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

	// Test adding port 443
	// 测试添加端口 443
	mockRule.On("AllowPort", uint16(443)).Return(nil)
	_, err := executeCommand(PortCmd, "add", "443")
	assert.NoError(t, err)
	mockRule.AssertExpectations(t)
}

// TestPortRemoveCmd tests the port remove command
// TestPortRemoveCmd 测试 port remove 命令
func TestPortRemoveCmd(t *testing.T) {
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

	// Test removing port 80
	// 测试移除端口 80
	mockRule.On("RemoveAllowedPort", uint16(80)).Return(nil)
	_, err := executeCommand(PortCmd, "remove", "80")
	assert.NoError(t, err)
	mockRule.AssertExpectations(t)
}

// TestPortAddHighPort tests adding high port number
// TestPortAddHighPort 测试添加高端口号
func TestPortAddHighPort(t *testing.T) {
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

	// Test adding high port
	// 测试添加高端口
	mockRule.On("AllowPort", uint16(65535)).Return(nil)
	_, err := executeCommand(PortCmd, "add", "65535")
	assert.NoError(t, err)
	mockRule.AssertExpectations(t)
}

// TestPortRemovePort443 tests removing port 443
// TestPortRemovePort443 测试移除端口 443
func TestPortRemovePort443(t *testing.T) {
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

	// Test removing port 443
	// 测试移除端口 443
	mockRule.On("RemoveAllowedPort", uint16(443)).Return(nil)
	_, err := executeCommand(PortCmd, "remove", "443")
	assert.NoError(t, err)
	mockRule.AssertExpectations(t)
}

// TestPortAddPort22 tests adding SSH port
// TestPortAddPort22 测试添加 SSH 端口
func TestPortAddPort22(t *testing.T) {
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

	// Test adding port 22
	// 测试添加端口 22
	mockRule.On("AllowPort", uint16(22)).Return(nil)
	_, err := executeCommand(PortCmd, "add", "22")
	assert.NoError(t, err)
	mockRule.AssertExpectations(t)
}

// TestPortAddPort8080 tests adding port 8080
// TestPortAddPort8080 测试添加端口 8080
func TestPortAddPort8080(t *testing.T) {
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

	// Test adding port 8080
	// 测试添加端口 8080
	mockRule.On("AllowPort", uint16(8080)).Return(nil)
	_, err := executeCommand(PortCmd, "add", "8080")
	assert.NoError(t, err)
	mockRule.AssertExpectations(t)
}
