package core

import (
	"context"
	"testing"

	"github.com/netxfw/netxfw/internal/xdp"
	"github.com/stretchr/testify/assert"
)

// TestSyncIPPortRule_Add tests adding IP+Port rule
// TestSyncIPPortRule_Add 测试添加 IP+端口规则
func TestSyncIPPortRule_Add(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncIPPortRule(ctx, mockMgr, "192.168.1.1", 80, 1, true)
	assert.NoError(t, err)

	rules, _, err := mockMgr.ListIPPortRules(false, 100, "")
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, len(rules), 1)
}

// TestSyncIPPortRule_Remove tests removing IP+Port rule
// TestSyncIPPortRule_Remove 测试移除 IP+端口规则
func TestSyncIPPortRule_Remove(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	mockMgr.AddIPPortRule("192.168.1.1/32", 80, 1)

	err := SyncIPPortRule(ctx, mockMgr, "192.168.1.1", 80, 1, false)
	assert.NoError(t, err)
}

// TestSyncIPPortRule_IPv6 tests IPv6 IP+Port rule
// TestSyncIPPortRule_IPv6 测试 IPv6 IP+端口规则
func TestSyncIPPortRule_IPv6(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncIPPortRule(ctx, mockMgr, "2001:db8::1", 443, 1, true)
	assert.NoError(t, err)
}

// TestSyncAllowedPort_Add tests adding allowed port
// TestSyncAllowedPort_Add 测试添加允许端口
func TestSyncAllowedPort_Add(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncAllowedPort(ctx, mockMgr, 443, true)
	assert.NoError(t, err)

	ports, err := mockMgr.ListAllowedPorts()
	assert.NoError(t, err)
	assert.Contains(t, ports, uint16(443))
}

// TestSyncAllowedPort_Remove tests removing allowed port
// TestSyncAllowedPort_Remove 测试移除允许端口
func TestSyncAllowedPort_Remove(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	mockMgr.AllowPort(443)

	err := SyncAllowedPort(ctx, mockMgr, 443, false)
	assert.NoError(t, err)

	ports, err := mockMgr.ListAllowedPorts()
	assert.NoError(t, err)
	assert.NotContains(t, ports, uint16(443))
}

// TestSyncAllowedPort_MultiplePorts tests multiple port operations
// TestSyncAllowedPort_MultiplePorts 测试多个端口操作
func TestSyncAllowedPort_MultiplePorts(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	ports := []uint16{22, 80, 443, 8080}

	for _, port := range ports {
		err := SyncAllowedPort(ctx, mockMgr, port, true)
		assert.NoError(t, err)
	}

	listedPorts, err := mockMgr.ListAllowedPorts()
	assert.NoError(t, err)
	for _, port := range ports {
		assert.Contains(t, listedPorts, port)
	}

	for _, port := range ports {
		err := SyncAllowedPort(ctx, mockMgr, port, false)
		assert.NoError(t, err)
	}

	listedPorts, err = mockMgr.ListAllowedPorts()
	assert.NoError(t, err)
	for _, port := range ports {
		assert.NotContains(t, listedPorts, port)
	}
}

// TestSyncRateLimitRule_Add tests adding rate limit rule
// TestSyncRateLimitRule_Add 测试添加速率限制规则
func TestSyncRateLimitRule_Add(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncRateLimitRule(ctx, mockMgr, "192.168.1.0/24", 1000, 100, true)
	assert.NoError(t, err)
}

// TestSyncRateLimitRule_Remove tests removing rate limit rule
// TestSyncRateLimitRule_Remove 测试移除速率限制规则
func TestSyncRateLimitRule_Remove(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	mockMgr.AddRateLimitRule("192.168.1.0/24", 1000, 100)

	err := SyncRateLimitRule(ctx, mockMgr, "192.168.1.0/24", 0, 0, false)
	assert.NoError(t, err)
}

// TestSyncRateLimitRule_IPv6 tests IPv6 rate limit rule
// TestSyncRateLimitRule_IPv6 测试 IPv6 速率限制规则
func TestSyncRateLimitRule_IPv6(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncRateLimitRule(ctx, mockMgr, "2001:db8::/32", 500, 50, true)
	assert.NoError(t, err)
}

// TestSyncAutoBlock_Enable tests enabling auto-block
// TestSyncAutoBlock_Enable 测试启用自动封禁
func TestSyncAutoBlock_Enable(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncAutoBlock(ctx, mockMgr, true)
	assert.NoError(t, err)
}

// TestSyncAutoBlock_Disable tests disabling auto-block
// TestSyncAutoBlock_Disable 测试禁用自动封禁
func TestSyncAutoBlock_Disable(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	mockMgr.SetAutoBlock(true)

	err := SyncAutoBlock(ctx, mockMgr, false)
	assert.NoError(t, err)
}

// TestSyncAutoBlockExpiry tests setting auto-block expiry
// TestSyncAutoBlockExpiry 测试设置自动封禁过期时间
func TestSyncAutoBlockExpiry(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncAutoBlockExpiry(ctx, mockMgr, 3600)
	assert.NoError(t, err)
}

// TestClearBlacklist tests clearing blacklist
// TestClearBlacklist 测试清除黑名单
func TestClearBlacklist(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	mockMgr.AddBlacklistIP("192.168.1.1/32")
	mockMgr.AddBlacklistIP("192.168.1.2/32")
	mockMgr.AddBlacklistIP("10.0.0.1/32")

	err := ClearBlacklist(ctx, mockMgr)
	assert.NoError(t, err)

	count, err := mockMgr.GetLockedIPCount()
	assert.NoError(t, err)
	assert.Equal(t, 0, count)
}

// Table-driven tests for IP+Port rules
// IP+端口规则的表驱动测试

// TestTableDriven_IPPortRules tests various IP+Port rule scenarios
// TestTableDriven_IPPortRules 测试各种 IP+端口规则场景
func TestTableDriven_IPPortRules(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	testCases := []struct {
		name   string
		ip     string
		port   uint16
		action uint8
	}{
		{"IPv4_HTTP", "192.168.1.1", 80, 1},
		{"IPv4_HTTPS", "192.168.1.1", 443, 1},
		{"IPv4_SSH", "10.0.0.1", 22, 1},
		{"IPv4_Custom", "172.16.0.1", 8080, 2},
		{"IPv6_HTTP", "2001:db8::1", 80, 1},
		{"IPv6_HTTPS", "2001:db8::1", 443, 1},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := SyncIPPortRule(ctx, mockMgr, tc.ip, tc.port, tc.action, true)
			assert.NoError(t, err)
		})
	}
}

// Table-driven tests for allowed ports
// 允许端口的表驱动测试

// TestTableDriven_AllowedPorts tests various port scenarios
// TestTableDriven_AllowedPorts 测试各种端口场景
func TestTableDriven_AllowedPorts(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	testCases := []struct {
		name string
		port uint16
	}{
		{"SSH", 22},
		{"HTTP", 80},
		{"HTTPS", 443},
		{"MySQL", 3306},
		{"PostgreSQL", 5432},
		{"Redis", 6379},
		{"Custom_8080", 8080},
		{"Custom_9000", 9000},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := SyncAllowedPort(ctx, mockMgr, tc.port, true)
			assert.NoError(t, err)
		})
	}
}

// Table-driven tests for rate limit rules
// 速率限制规则的表驱动测试

// TestTableDriven_RateLimitRules tests various rate limit scenarios
// TestTableDriven_RateLimitRules 测试各种速率限制场景
func TestTableDriven_RateLimitRules(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	testCases := []struct {
		name  string
		ip    string
		rate  uint64
		burst uint64
	}{
		{"LowRate_IPv4", "192.168.1.0/24", 100, 10},
		{"MediumRate_IPv4", "10.0.0.0/8", 1000, 100},
		{"HighRate_IPv4", "172.16.0.0/16", 10000, 1000},
		{"LowRate_IPv6", "2001:db8::/32", 100, 10},
		{"HighRate_IPv6", "2001:db8::/64", 10000, 1000},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := SyncRateLimitRule(ctx, mockMgr, tc.ip, tc.rate, tc.burst, true)
			assert.NoError(t, err)
		})
	}
}

// TestSyncIPPortRule_DenyAction tests deny action for IP+Port rule
// TestSyncIPPortRule_DenyAction 测试 IP+端口规则的拒绝动作
func TestSyncIPPortRule_DenyAction(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncIPPortRule(ctx, mockMgr, "192.168.1.1", 8080, 2, true)
	assert.NoError(t, err)
}

// TestSyncRateLimitRule_Update tests updating rate limit rule
// TestSyncRateLimitRule_Update 测试更新速率限制规则
func TestSyncRateLimitRule_Update(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncRateLimitRule(ctx, mockMgr, "192.168.1.0/24", 1000, 100, true)
	assert.NoError(t, err)

	err = SyncRateLimitRule(ctx, mockMgr, "192.168.1.0/24", 2000, 200, true)
	assert.NoError(t, err)
}

// TestClearBlacklist_Empty tests clearing empty blacklist
// TestClearBlacklist_Empty 测试清除空黑名单
func TestClearBlacklist_Empty(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := ClearBlacklist(ctx, mockMgr)
	assert.NoError(t, err)
}

// TestSyncAllowedPort_ReAdd tests re-adding same port
// TestSyncAllowedPort_ReAdd 测试重新添加相同端口
func TestSyncAllowedPort_ReAdd(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncAllowedPort(ctx, mockMgr, 443, true)
	assert.NoError(t, err)

	err = SyncAllowedPort(ctx, mockMgr, 443, true)
	assert.NoError(t, err)
}

// TestSyncIPPortRule_ReAdd tests re-adding same rule
// TestSyncIPPortRule_ReAdd 测试重新添加相同规则
func TestSyncIPPortRule_ReAdd(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	err := SyncIPPortRule(ctx, mockMgr, "192.168.1.1", 80, 1, true)
	assert.NoError(t, err)

	err = SyncIPPortRule(ctx, mockMgr, "192.168.1.1", 80, 1, true)
	assert.NoError(t, err)
}
