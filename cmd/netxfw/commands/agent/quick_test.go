package agent

import (
	"testing"

	"github.com/livp123/netxfw/cmd/netxfw/commands/common"
	"github.com/livp123/netxfw/pkg/sdk"
	"github.com/stretchr/testify/assert"
)

// TestQuickBlockCmd tests the quick block command
// TestQuickBlockCmd 测试 quick block 命令
func TestQuickBlockCmd(t *testing.T) {
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

	// Test blocking an IP
	// 测试封锁 IP
	mockBlacklist.On("Add", "192.168.1.100").Return(nil)
	_, err := executeCommand(QuickBlockCmd, "192.168.1.100")
	assert.NoError(t, err)
	mockBlacklist.AssertExpectations(t)
}

// TestQuickUnlockCmd tests the quick unlock command
// TestQuickUnlockCmd 测试 quick unlock 命令
func TestQuickUnlockCmd(t *testing.T) {
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

	// Test unlocking an IP
	// 测试解锁 IP
	mockBlacklist.On("Remove", "192.168.1.100").Return(nil)
	_, err := executeCommand(QuickUnlockCmd, "192.168.1.100")
	assert.NoError(t, err)
	mockBlacklist.AssertExpectations(t)
}

// TestQuickAllowCmd tests the quick allow command
// TestQuickAllowCmd 测试 quick allow 命令
func TestQuickAllowCmd(t *testing.T) {
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

	// Test allowing an IP without port
	// 测试允许 IP（无端口）
	mockWhitelist.On("Add", "10.0.0.1", uint16(0)).Return(nil)
	_, err := executeCommand(QuickAllowCmd, "10.0.0.1")
	assert.NoError(t, err)
	mockWhitelist.AssertExpectations(t)
}

// TestQuickAllowWithPortCmd tests the quick allow command with port
// TestQuickAllowWithPortCmd 测试带端口的 quick allow 命令
func TestQuickAllowWithPortCmd(t *testing.T) {
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

	// Test allowing an IP with port
	// 测试允许 IP（带端口）
	mockWhitelist.On("Add", "10.0.0.2", uint16(443)).Return(nil)
	_, err := executeCommand(QuickAllowCmd, "10.0.0.2", "443")
	assert.NoError(t, err)
	mockWhitelist.AssertExpectations(t)
}

// TestQuickUnallowCmd tests the quick unallow command
// TestQuickUnallowCmd 测试 quick unallow 命令
func TestQuickUnallowCmd(t *testing.T) {
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

	// Test removing from whitelist
	// 测试从白名单移除
	mockWhitelist.On("Remove", "10.0.0.1").Return(nil)
	_, err := executeCommand(QuickUnallowCmd, "10.0.0.1")
	assert.NoError(t, err)
	mockWhitelist.AssertExpectations(t)
}

// TestQuickBlockIPv6 tests blocking IPv6 address
// TestQuickBlockIPv6 测试封锁 IPv6 地址
func TestQuickBlockIPv6(t *testing.T) {
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

	// Test blocking IPv6
	// 测试封锁 IPv6
	mockBlacklist.On("Add", "2001:db8::1").Return(nil)
	_, err := executeCommand(QuickBlockCmd, "2001:db8::1")
	assert.NoError(t, err)
	mockBlacklist.AssertExpectations(t)
}

// TestQuickBlockCIDR tests blocking CIDR
// TestQuickBlockCIDR 测试封锁 CIDR
func TestQuickBlockCIDR(t *testing.T) {
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

	// Test blocking CIDR
	// 测试封锁 CIDR
	mockBlacklist.On("Add", "192.168.0.0/16").Return(nil)
	_, err := executeCommand(QuickBlockCmd, "192.168.0.0/16")
	assert.NoError(t, err)
	mockBlacklist.AssertExpectations(t)
}

// TestQuickAllowIPv6 tests allowing IPv6 address
// TestQuickAllowIPv6 测试允许 IPv6 地址
func TestQuickAllowIPv6(t *testing.T) {
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

	// Test allowing IPv6
	// 测试允许 IPv6
	mockWhitelist.On("Add", "2001:db8::1", uint16(0)).Return(nil)
	_, err := executeCommand(QuickAllowCmd, "2001:db8::1")
	assert.NoError(t, err)
	mockWhitelist.AssertExpectations(t)
}

// TestQuickAllowPort80 tests allowing with port 80
// TestQuickAllowPort80 测试允许端口 80
func TestQuickAllowPort80(t *testing.T) {
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

	// Test allowing with port 80
	// 测试允许端口 80
	mockWhitelist.On("Add", "192.168.1.1", uint16(80)).Return(nil)
	_, err := executeCommand(QuickAllowCmd, "192.168.1.1", "80")
	assert.NoError(t, err)
	mockWhitelist.AssertExpectations(t)
}
