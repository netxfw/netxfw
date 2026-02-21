package agent

import (
	"testing"

	"github.com/netxfw/netxfw/cmd/netxfw/commands/common"
	"github.com/netxfw/netxfw/pkg/sdk/mock"
	"github.com/stretchr/testify/assert"
)

// TestQuickBlockCmd tests the quick block command.
// TestQuickBlockCmd 测试 quick block 命令。
func TestQuickBlockCmd(t *testing.T) {
	m := mock.NewMockSDK()
	mock.SetupMockBlacklist(m)
	common.MockSDK = m

	_, err := executeCommand(QuickBlockCmd, "192.168.1.100")
	assert.NoError(t, err)
}

// TestQuickUnlockCmd tests the quick unlock command.
// TestQuickUnlockCmd 测试 quick unlock 命令。
func TestQuickUnlockCmd(t *testing.T) {
	m := mock.NewMockSDK()
	mock.SetupMockBlacklist(m)
	common.MockSDK = m

	_, err := executeCommand(QuickUnlockCmd, "192.168.1.100")
	assert.NoError(t, err)
}

// TestQuickAllowCmd tests the quick allow command.
// TestQuickAllowCmd 测试 quick allow 命令。
func TestQuickAllowCmd(t *testing.T) {
	m := mock.NewMockSDK()
	mock.SetupMockWhitelist(m)
	common.MockSDK = m

	_, err := executeCommand(QuickAllowCmd, "10.0.0.1")
	assert.NoError(t, err)
}

// TestQuickAllowWithPortCmd tests the quick allow command with port.
// TestQuickAllowWithPortCmd 测试带端口的 quick allow 命令。
func TestQuickAllowWithPortCmd(t *testing.T) {
	m := mock.NewMockSDK()
	mock.SetupMockWhitelist(m)
	common.MockSDK = m

	_, err := executeCommand(QuickAllowCmd, "10.0.0.2", "443")
	assert.NoError(t, err)
}

// TestQuickUnallowCmd tests the quick unallow command.
// TestQuickUnallowCmd 测试 quick unallow 命令。
func TestQuickUnallowCmd(t *testing.T) {
	m := mock.NewMockSDK()
	mock.SetupMockWhitelist(m)
	common.MockSDK = m

	_, err := executeCommand(QuickUnallowCmd, "10.0.0.1")
	assert.NoError(t, err)
}

// TestQuickBlockIPv6 tests blocking IPv6 address.
// TestQuickBlockIPv6 测试封锁 IPv6 地址。
func TestQuickBlockIPv6(t *testing.T) {
	m := mock.NewMockSDK()
	mock.SetupMockBlacklist(m)
	common.MockSDK = m

	_, err := executeCommand(QuickBlockCmd, "2001:db8::1")
	assert.NoError(t, err)
}

// TestQuickBlockCIDR tests blocking CIDR.
// TestQuickBlockCIDR 测试封锁 CIDR。
func TestQuickBlockCIDR(t *testing.T) {
	m := mock.NewMockSDK()
	mock.SetupMockBlacklist(m)
	common.MockSDK = m

	_, err := executeCommand(QuickBlockCmd, "192.168.0.0/16")
	assert.NoError(t, err)
}

// TestQuickAllowIPv6 tests allowing IPv6 address.
// TestQuickAllowIPv6 测试允许 IPv6 地址。
func TestQuickAllowIPv6(t *testing.T) {
	m := mock.NewMockSDK()
	mock.SetupMockWhitelist(m)
	common.MockSDK = m

	_, err := executeCommand(QuickAllowCmd, "2001:db8::1")
	assert.NoError(t, err)
}

// TestQuickAllowPort80 tests allowing with port 80.
// TestQuickAllowPort80 测试允许端口 80。
func TestQuickAllowPort80(t *testing.T) {
	m := mock.NewMockSDK()
	mock.SetupMockWhitelist(m)
	common.MockSDK = m

	_, err := executeCommand(QuickAllowCmd, "192.168.1.1", "80")
	assert.NoError(t, err)
}
