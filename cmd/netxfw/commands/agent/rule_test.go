package agent

import (
	"testing"

	"github.com/netxfw/netxfw/cmd/netxfw/commands/common"
	"github.com/netxfw/netxfw/pkg/sdk"
	"github.com/netxfw/netxfw/pkg/sdk/mock"
	"github.com/stretchr/testify/assert"
)

// TestRuleAddAllowCmd tests the rule add allow command.
// TestRuleAddAllowCmd 测试 rule add allow 命令。
func TestRuleAddAllowCmd(t *testing.T) {
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

	// Test adding IP to whitelist (allow) / 测试添加 IP 到白名单（允许）
	mockWhitelist.On("Add", "192.168.1.1", uint16(0)).Return(nil)
	mockBlacklist.On("Remove", "192.168.1.1").Return(nil)
	_, err := executeCommand(RuleCmd, "add", "192.168.1.1", "allow")
	assert.NoError(t, err)
	mockWhitelist.AssertExpectations(t)
}

// TestRuleAddIPPortCmd tests adding IP+Port rule.
// TestRuleAddIPPortCmd 测试添加 IP+端口规则。
func TestRuleAddIPPortCmd(t *testing.T) {
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

	// Test adding IP:Port deny rule / 测试添加 IP:端口 拒绝规则
	mockRule.On("AddIPPortRule", "192.168.1.1", uint16(80), uint8(2)).Return(nil)
	_, err := executeCommand(RuleCmd, "add", "192.168.1.1:80", "deny")
	assert.NoError(t, err)
	mockRule.AssertExpectations(t)
}

// TestRuleAddIPPortAllowCmd tests adding IP+Port allow rule.
// TestRuleAddIPPortAllowCmd 测试添加 IP+端口 允许规则。
func TestRuleAddIPPortAllowCmd(t *testing.T) {
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

	// Test adding IP:Port allow rule / 测试添加 IP:端口 允许规则
	mockRule.On("AddIPPortRule", "192.168.1.1", uint16(443), uint8(1)).Return(nil)
	_, err := executeCommand(RuleCmd, "add", "192.168.1.1:443", "allow")
	assert.NoError(t, err)
	mockRule.AssertExpectations(t)
}

// TestRuleRemoveCmd tests the rule remove command.
// TestRuleRemoveCmd 测试 rule remove 命令。
func TestRuleRemoveCmd(t *testing.T) {
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

	// Test removing IP from blacklist and whitelist / 测试从黑名单和白名单移除 IP
	mockBlacklist.On("Remove", "192.168.1.1").Return(nil)
	mockWhitelist.On("Remove", "192.168.1.1").Return(nil)
	_, err := executeCommand(RuleCmd, "remove", "192.168.1.1")
	assert.NoError(t, err)
	mockBlacklist.AssertExpectations(t)
}

// TestRuleRemoveIPPortCmd tests removing IP+Port rule.
// TestRuleRemoveIPPortCmd 测试移除 IP+端口 规则。
func TestRuleRemoveIPPortCmd(t *testing.T) {
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

	// Test removing IP:Port rule / 测试移除 IP:端口 规则
	mockRule.On("RemoveIPPortRule", "192.168.1.1", uint16(80)).Return(nil)
	_, err := executeCommand(RuleCmd, "remove", "192.168.1.1:80")
	assert.NoError(t, err)
	mockRule.AssertExpectations(t)
}

// TestRuleAddIPv6Cmd tests adding IPv6 rule.
// TestRuleAddIPv6Cmd 测试添加 IPv6 规则。
func TestRuleAddIPv6Cmd(t *testing.T) {
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

	// Test adding IPv6 to blacklist / 测试添加 IPv6 到黑名单
	mockBlacklist.On("Add", "2001:db8::1").Return(nil)
	mockWhitelist.On("Remove", "2001:db8::1").Return(nil)
	_, err := executeCommand(RuleCmd, "add", "2001:db8::1")
	assert.NoError(t, err)
	mockBlacklist.AssertExpectations(t)
}

// TestRuleAddIPv6AllowCmd tests adding IPv6 allow rule.
// TestRuleAddIPv6AllowCmd 测试添加 IPv6 允许规则。
func TestRuleAddIPv6AllowCmd(t *testing.T) {
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

	// Test adding IPv6 to whitelist / 测试添加 IPv6 到白名单
	mockWhitelist.On("Add", "2001:db8::1", uint16(0)).Return(nil)
	mockBlacklist.On("Remove", "2001:db8::1").Return(nil)
	_, err := executeCommand(RuleCmd, "add", "2001:db8::1", "allow")
	assert.NoError(t, err)
	mockWhitelist.AssertExpectations(t)
}

// TestRuleAddCIDRCmd tests adding CIDR rule.
// TestRuleAddCIDRCmd 测试添加 CIDR 规则。
func TestRuleAddCIDRCmd(t *testing.T) {
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

	// Test adding CIDR to blacklist / 测试添加 CIDR 到黑名单
	mockBlacklist.On("Add", "192.168.0.0/16").Return(nil)
	mockWhitelist.On("Remove", "192.168.0.0/16").Return(nil)
	_, err := executeCommand(RuleCmd, "add", "192.168.0.0/16")
	assert.NoError(t, err)
	mockBlacklist.AssertExpectations(t)
}

// TestRuleAddPort8080Cmd tests adding port 8080 rule.
// TestRuleAddPort8080Cmd 测试添加端口 8080 规则。
func TestRuleAddPort8080Cmd(t *testing.T) {
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

	// Test adding IP:Port rule for port 8080 / 测试添加端口 8080 的 IP:端口 规则
	mockRule.On("AddIPPortRule", "10.0.0.1", uint16(8080), uint8(2)).Return(nil)
	_, err := executeCommand(RuleCmd, "add", "10.0.0.1:8080", "deny")
	assert.NoError(t, err)
	mockRule.AssertExpectations(t)
}

// TestRuleAddPort22AllowCmd tests adding SSH port allow rule.
// TestRuleAddPort22AllowCmd 测试添加 SSH 端口允许规则。
func TestRuleAddPort22AllowCmd(t *testing.T) {
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

	// Test adding IP:Port allow rule for SSH / 测试添加 SSH 的 IP:端口 允许规则
	mockRule.On("AddIPPortRule", "10.0.0.1", uint16(22), uint8(1)).Return(nil)
	_, err := executeCommand(RuleCmd, "add", "10.0.0.1:22", "allow")
	assert.NoError(t, err)
	mockRule.AssertExpectations(t)
}

// TestRuleAddCIDRAllowCmd tests adding CIDR allow rule.
// TestRuleAddCIDRAllowCmd 测试添加 CIDR 允许规则。
func TestRuleAddCIDRAllowCmd(t *testing.T) {
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

	// Test adding CIDR to whitelist / 测试添加 CIDR 到白名单
	mockWhitelist.On("Add", "10.0.0.0/8", uint16(0)).Return(nil)
	mockBlacklist.On("Remove", "10.0.0.0/8").Return(nil)
	_, err := executeCommand(RuleCmd, "add", "10.0.0.0/8", "allow")
	assert.NoError(t, err)
	mockWhitelist.AssertExpectations(t)
}

// TestRuleRemoveFromWhitelistCmd tests removing from whitelist.
// TestRuleRemoveFromWhitelistCmd 测试从白名单移除。
func TestRuleRemoveFromWhitelistCmd(t *testing.T) {
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

	// Test removing from whitelist / 测试从白名单移除
	mockBlacklist.On("Remove", "10.0.0.1").Return(nil)
	mockWhitelist.On("Remove", "10.0.0.1").Return(nil)
	_, err := executeCommand(RuleCmd, "remove", "10.0.0.1")
	assert.NoError(t, err)
}

// TestRuleAddPort3306Cmd tests adding MySQL port rule.
// TestRuleAddPort3306Cmd 测试添加 MySQL 端口规则。
func TestRuleAddPort3306Cmd(t *testing.T) {
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

	// Test adding IP:Port rule for MySQL / 测试添加 MySQL 的 IP:端口 规则
	mockRule.On("AddIPPortRule", "192.168.1.100", uint16(3306), uint8(2)).Return(nil)
	_, err := executeCommand(RuleCmd, "add", "192.168.1.100:3306", "deny")
	assert.NoError(t, err)
	mockRule.AssertExpectations(t)
}

// TestRuleAddPort5432AllowCmd tests adding PostgreSQL port allow rule.
// TestRuleAddPort5432AllowCmd 测试添加 PostgreSQL 端口允许规则。
func TestRuleAddPort5432AllowCmd(t *testing.T) {
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

	// Test adding IP:Port allow rule for PostgreSQL / 测试添加 PostgreSQL 的 IP:端口 允许规则
	mockRule.On("AddIPPortRule", "192.168.1.100", uint16(5432), uint8(1)).Return(nil)
	_, err := executeCommand(RuleCmd, "add", "192.168.1.100:5432", "allow")
	assert.NoError(t, err)
	mockRule.AssertExpectations(t)
}
