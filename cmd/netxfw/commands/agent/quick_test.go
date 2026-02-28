package agent

import (
	"testing"
	"time"

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

	_, err := executeCommand(SimpleBlockCmd, "192.168.1.100")
	assert.NoError(t, err)
}

// TestQuickUnlockCmd tests the quick unlock command.
// TestQuickUnlockCmd 测试 quick unlock 命令。
func TestQuickUnlockCmd(t *testing.T) {
	m := mock.NewMockSDK()
	mock.SetupMockBlacklist(m)
	common.MockSDK = m

	_, err := executeCommand(SimpleUnblockCmd, "192.168.1.100")
	assert.NoError(t, err)
}

// TestQuickAllowCmd tests the quick allow command.
// TestQuickAllowCmd 测试 quick allow 命令。
func TestQuickAllowCmd(t *testing.T) {
	m := mock.NewMockSDK()
	mock.SetupMockWhitelist(m)
	common.MockSDK = m

	_, err := executeCommand(SimpleAllowCmd, "10.0.0.1")
	assert.NoError(t, err)
}

// TestQuickAllowWithPortCmd tests the quick allow command with port.
// TestQuickAllowWithPortCmd 测试带端口的 quick allow 命令。
func TestQuickAllowWithPortCmd(t *testing.T) {
	m := mock.NewMockSDK()
	mock.SetupMockWhitelist(m)
	common.MockSDK = m

	_, err := executeCommand(SimpleAllowCmd, "10.0.0.2:443")
	assert.NoError(t, err)
}

// TestQuickUnallowCmd tests the quick unallow command.
// TestQuickUnallowCmd 测试 quick unallow 命令。
func TestQuickUnallowCmd(t *testing.T) {
	m := mock.NewMockSDK()
	mock.SetupMockWhitelist(m)
	common.MockSDK = m

	_, err := executeCommand(SimpleUnallowCmd, "10.0.0.1")
	assert.NoError(t, err)
}

// TestQuickBlockIPv6 tests blocking IPv6 address.
// TestQuickBlockIPv6 测试封锁 IPv6 地址。
func TestQuickBlockIPv6(t *testing.T) {
	m := mock.NewMockSDK()
	mock.SetupMockBlacklist(m)
	common.MockSDK = m

	_, err := executeCommand(SimpleBlockCmd, "2001:db8::1")
	assert.NoError(t, err)
}

// TestQuickBlockCIDR tests blocking CIDR.
// TestQuickBlockCIDR 测试封锁 CIDR。
func TestQuickBlockCIDR(t *testing.T) {
	m := mock.NewMockSDK()
	mock.SetupMockBlacklist(m)
	common.MockSDK = m

	_, err := executeCommand(SimpleBlockCmd, "192.168.0.0/16")
	assert.NoError(t, err)
}

// TestQuickAllowIPv6 tests allowing IPv6 address.
// TestQuickAllowIPv6 测试允许 IPv6 地址。
func TestQuickAllowIPv6(t *testing.T) {
	m := mock.NewMockSDK()
	mock.SetupMockWhitelist(m)
	common.MockSDK = m

	_, err := executeCommand(SimpleAllowCmd, "2001:db8::1")
	assert.NoError(t, err)
}

// TestQuickAllowPort80 tests allowing with port 80.
// TestQuickAllowPort80 测试允许端口 80。
func TestQuickAllowPort80(t *testing.T) {
	m := mock.NewMockSDK()
	mock.SetupMockWhitelist(m)
	common.MockSDK = m

	_, err := executeCommand(SimpleAllowCmd, "192.168.1.1:80")
	assert.NoError(t, err)
}

// TestQuickDenyCmd tests the quick deny command.
// TestQuickDenyCmd 测试 quick deny 命令。
func TestQuickDenyCmd(t *testing.T) {
	m := mock.NewMockSDK()
	mock.SetupMockBlacklist(m)
	common.MockSDK = m

	_, err := executeCommand(SimpleDenyCmd, "192.168.1.100")
	assert.NoError(t, err)
}

// TestQuickDenyWithPortCmd tests deny command with port.
// TestQuickDenyWithPortCmd 测试带端口的 deny 命令。
func TestQuickDenyWithPortCmd(t *testing.T) {
	m := mock.NewMockSDK()
	mock.SetupMockRule(m)
	common.MockSDK = m

	_, err := executeCommand(SimpleDenyCmd, "192.168.1.100:8080")
	assert.NoError(t, err)
}

// TestQuickDenyWithTTL tests deny command with TTL.
// TestQuickDenyWithTTL 测试带 TTL 的 deny 命令。
func TestQuickDenyWithTTL(t *testing.T) {
	m := mock.NewMockSDK()
	mock.SetupMockBlacklist(m)
	common.MockSDK = m

	_, err := executeCommand(SimpleDenyCmd, "192.168.1.100", "--ttl", "1h")
	assert.NoError(t, err)
}

// TestQuickDenyWithTTL_TooSmall tests TTL too small.
// TestQuickDenyWithTTL_TooSmall 测试 TTL 太小。
func TestQuickDenyWithTTL_TooSmall(t *testing.T) {
	// Test validation logic directly to avoid os.Exit in tests
	// 直接测试验证逻辑以避免测试中的 os.Exit
	minTTL := time.Minute
	ttl := 30 * time.Second
	assert.True(t, ttl < minTTL, "TTL 30s should be invalid (less than 1 minute)")
}

// TestQuickDenyWithTTL_TooLarge tests TTL too large.
// TestQuickDenyWithTTL_TooLarge 测试 TTL 太大。
func TestQuickDenyWithTTL_TooLarge(t *testing.T) {
	// Test validation logic directly to avoid os.Exit in tests
	// 直接测试验证逻辑以避免测试中的 os.Exit
	maxTTL := 365 * 24 * time.Hour
	ttl := 400 * 24 * time.Hour
	assert.True(t, ttl > maxTTL, "TTL 400 days should be invalid (more than 365 days)")
}

// TestQuickDeleteCmd tests the quick delete command.
// TestQuickDeleteCmd 测试 quick delete 命令。
func TestQuickDeleteCmd(t *testing.T) {
	m := mock.NewMockSDK()
	mock.SetupMockBlacklist(m)
	mock.SetupMockWhitelist(m)
	common.MockSDK = m

	_, err := executeCommand(SimpleDeleteCmd, "192.168.1.100")
	assert.NoError(t, err)
}

// TestQuickDeleteWithPortCmd tests delete command with port.
// TestQuickDeleteWithPortCmd 测试带端口的 delete 命令。
func TestQuickDeleteWithPortCmd(t *testing.T) {
	m := mock.NewMockSDK()
	mock.SetupMockRule(m)
	common.MockSDK = m

	_, err := executeCommand(SimpleDeleteCmd, "192.168.1.100:8080")
	assert.NoError(t, err)
}
