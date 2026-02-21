package agent

import (
	"bytes"
	"testing"

	"github.com/netxfw/netxfw/cmd/netxfw/commands/common"
	"github.com/netxfw/netxfw/pkg/sdk"
	"github.com/netxfw/netxfw/pkg/sdk/mock"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

// executeCommand executes a cobra command and returns output.
// executeCommand 执行 cobra 命令并返回输出。
func executeCommand(cmd *cobra.Command, args ...string) (string, error) {
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return buf.String(), err
}

// TestRuleAddCmd tests the rule add command.
// TestRuleAddCmd 测试规则添加命令。
func TestRuleAddCmd(t *testing.T) {
	mockBlacklist := new(mock.MockBlacklistAPI)
	mockWhitelist := new(mock.MockWhitelistAPI)
	mockRule := new(mock.MockRuleAPI)

	common.MockSDK = &sdk.SDK{
		Blacklist: mockBlacklist,
		Whitelist: mockWhitelist,
		Rule:      mockRule,
	}

	// Test adding to blacklist / 测试添加到黑名单
	mockBlacklist.On("Add", "1.2.3.4").Return(nil)
	mockWhitelist.On("Remove", "1.2.3.4").Return(nil)
	output, err := executeCommand(RuleCmd, "add", "1.2.3.4", "deny")
	assert.NoError(t, err)
	assert.Contains(t, output, "Added 1.2.3.4 to Blacklist")
	mockBlacklist.AssertExpectations(t)
	mockWhitelist.AssertExpectations(t)

	// Test adding to whitelist / 测试添加到白名单
	mockWhitelist.On("Add", "5.6.7.8", uint16(0)).Return(nil)
	mockBlacklist.On("Remove", "5.6.7.8").Return(nil)
	output, err = executeCommand(RuleCmd, "add", "5.6.7.8", "allow")
	assert.NoError(t, err)
	assert.Contains(t, output, "Added 5.6.7.8 to Whitelist")
	mockWhitelist.AssertExpectations(t)
	mockBlacklist.AssertExpectations(t)

	// Test adding IP+Port rule / 测试添加 IP+端口规则
	mockRule.On("AddIPPortRule", "10.0.0.1", uint16(80), uint8(2)).Return(nil)
	output, err = executeCommand(RuleCmd, "add", "10.0.0.1:80", "deny")
	assert.NoError(t, err)
	assert.Contains(t, output, "Rule added: 10.0.0.1:80 (Action: 2)")
	mockRule.AssertExpectations(t)
}

// TestRuleListCmd tests the rule list command.
// TestRuleListCmd 测试规则列表命令。
func TestRuleListCmd(t *testing.T) {
	mockBlacklist := new(mock.MockBlacklistAPI)
	mockWhitelist := new(mock.MockWhitelistAPI)
	mockRule := new(mock.MockRuleAPI)

	common.MockSDK = &sdk.SDK{
		Blacklist: mockBlacklist,
		Whitelist: mockWhitelist,
		Rule:      mockRule,
	}

	mockWhitelist.On("List", 100, "").Return([]string{"1.1.1.1"}, 1, nil)
	mockBlacklist.On("List", 100, "").Return([]sdk.BlockedIP{{IP: "2.2.2.2"}}, 1, nil)
	mockRule.On("ListIPPortRules", 100, "").Return([]sdk.IPPortRule{{IP: "3.3.3.3", Port: 80, Action: 2}}, 1, nil)

	// Test list all / 测试列出所有
	output, err := executeCommand(RuleCmd, "list")
	assert.NoError(t, err)
	assert.Contains(t, output, "1.1.1.1")
	assert.Contains(t, output, "2.2.2.2")
	assert.Contains(t, output, "3.3.3.3:80")

	// Test list specific / 测试列出特定类型
	mockWhitelist.On("List", 100, "").Return([]string{"1.1.1.1"}, 1, nil)
	output, err = executeCommand(RuleCmd, "list", "allow")
	assert.NoError(t, err)
	assert.Contains(t, output, "1.1.1.1")
}
