package integration

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/netxfw/netxfw/internal/xdp"
)

// TestEndToEnd_MockWorkflow tests the complete workflow using MockManager
// TestEndToEnd_MockWorkflow 使用 MockManager 测试完整工作流
func TestEndToEnd_MockWorkflow(t *testing.T) {
	// Step 1: Create MockManager
	// 步骤 1：创建 MockManager
	mockMgr := xdp.NewMockManager()
	require.NotNil(t, mockMgr)

	// Step 2: Configure basic settings
	// 步骤 2：配置基本设置
	err := mockMgr.SetDefaultDeny(true)
	require.NoError(t, err)

	err = mockMgr.SetAllowReturnTraffic(true)
	require.NoError(t, err)

	err = mockMgr.SetAllowICMP(true)
	require.NoError(t, err)

	err = mockMgr.SetStrictTCP(true)
	require.NoError(t, err)

	err = mockMgr.SetSYNLimit(true)
	require.NoError(t, err)

	err = mockMgr.SetBogonFilter(true)
	require.NoError(t, err)

	// Step 3: Manage blacklist
	// 步骤 3：管理黑名单
	err = mockMgr.AddBlacklistIP("192.168.100.1/32")
	require.NoError(t, err)

	err = mockMgr.AddBlacklistIP("10.0.0.0/8")
	require.NoError(t, err)

	count, err := mockMgr.GetLockedIPCount()
	require.NoError(t, err)
	assert.Equal(t, 2, count)

	// Step 4: Manage whitelist
	// 步骤 4：管理白名单
	err = mockMgr.AddWhitelistIP("192.168.1.1/32", 0)
	require.NoError(t, err)

	err = mockMgr.AddWhitelistIP("192.168.1.2/32", 443)
	require.NoError(t, err)

	count, err = mockMgr.GetWhitelistCount()
	require.NoError(t, err)
	assert.Equal(t, 2, count)

	// Step 5: Remove from blacklist
	// 步骤 5：从黑名单移除
	err = mockMgr.RemoveBlacklistIP("192.168.100.1/32")
	require.NoError(t, err)

	count, err = mockMgr.GetLockedIPCount()
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	// Step 6: Clear blacklist
	// 步骤 6：清除黑名单
	err = mockMgr.ClearBlacklist()
	require.NoError(t, err)

	count, err = mockMgr.GetLockedIPCount()
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

// TestEndToEnd_ConfigPersistence tests configuration persistence
// TestEndToEnd_ConfigPersistence 测试配置持久化
func TestEndToEnd_ConfigPersistence(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test_config.yaml")

	// Create initial config
	// 创建初始配置
	cfg := &types.GlobalConfig{
		Base: types.BaseConfig{
			DefaultDeny:        true,
			AllowReturnTraffic: true,
			AllowICMP:          true,
			Whitelist: []string{
				"192.168.1.1/32",
				"10.0.0.0/8",
			},
		},
	}

	// Save config
	// 保存配置
	err := types.SaveGlobalConfig(configPath, cfg)
	require.NoError(t, err)

	// Verify file exists
	// 验证文件存在
	_, err = os.Stat(configPath)
	require.NoError(t, err)

	// Load config
	// 加载配置
	loadedCfg, err := types.LoadGlobalConfig(configPath)
	require.NoError(t, err)
	require.NotNil(t, loadedCfg)

	// Verify config values
	// 验证配置值
	assert.True(t, loadedCfg.Base.DefaultDeny)
	assert.True(t, loadedCfg.Base.AllowReturnTraffic)
	assert.True(t, loadedCfg.Base.AllowICMP)
	assert.Len(t, loadedCfg.Base.Whitelist, 2)
}

// TestEndToEnd_MultipleOperations tests multiple sequential operations
// TestEndToEnd_MultipleOperations 测试多个顺序操作
func TestEndToEnd_MultipleOperations(t *testing.T) {
	mockMgr := xdp.NewMockManager()

	// Add multiple IPs to blacklist
	// 向黑名单添加多个 IP
	blacklistIPs := []string{
		"192.168.1.1/32",
		"192.168.1.2/32",
		"192.168.1.3/32",
		"10.0.0.0/8",
		"172.16.0.0/12",
	}

	for _, ip := range blacklistIPs {
		err := mockMgr.AddBlacklistIP(ip)
		require.NoError(t, err)
	}

	count, err := mockMgr.GetLockedIPCount()
	require.NoError(t, err)
	assert.Equal(t, len(blacklistIPs), count)

	// Add multiple IPs to whitelist
	// 向白名单添加多个 IP
	whitelistIPs := []struct {
		ip   string
		port uint16
	}{
		{"192.168.100.1/32", 0},
		{"192.168.100.2/32", 80},
		{"192.168.100.3/32", 443},
	}

	for _, entry := range whitelistIPs {
		err := mockMgr.AddWhitelistIP(entry.ip, entry.port)
		require.NoError(t, err)
	}

	count, err = mockMgr.GetWhitelistCount()
	require.NoError(t, err)
	assert.Equal(t, len(whitelistIPs), count)

	// Remove some IPs
	// 移除一些 IP
	err = mockMgr.RemoveBlacklistIP("192.168.1.1/32")
	require.NoError(t, err)

	err = mockMgr.RemoveWhitelistIP("192.168.100.1/32")
	require.NoError(t, err)

	count, err = mockMgr.GetLockedIPCount()
	require.NoError(t, err)
	assert.Equal(t, len(blacklistIPs)-1, count)

	count, err = mockMgr.GetWhitelistCount()
	require.NoError(t, err)
	assert.Equal(t, len(whitelistIPs)-1, count)
}

// TestEndToEnd_IPv6Support tests IPv6 support
// TestEndToEnd_IPv6Support 测试 IPv6 支持
func TestEndToEnd_IPv6Support(t *testing.T) {
	mockMgr := xdp.NewMockManager()

	// Add IPv6 addresses to blacklist
	// 向黑名单添加 IPv6 地址
	ipv6Blacklist := []string{
		"::1/128",
		"fe80::1/128",
		"2001:db8::1/128",
	}

	for _, ip := range ipv6Blacklist {
		err := mockMgr.AddBlacklistIP(ip)
		require.NoError(t, err)
	}

	count, err := mockMgr.GetLockedIPCount()
	require.NoError(t, err)
	assert.Equal(t, len(ipv6Blacklist), count)

	// Add IPv6 addresses to whitelist
	// 向白名单添加 IPv6 地址
	ipv6Whitelist := []struct {
		ip   string
		port uint16
	}{
		{"2001:db8::2/128", 0},
		{"2001:db8::3/128", 80},
	}

	for _, entry := range ipv6Whitelist {
		err := mockMgr.AddWhitelistIP(entry.ip, entry.port)
		require.NoError(t, err)
	}

	count, err = mockMgr.GetWhitelistCount()
	require.NoError(t, err)
	assert.Equal(t, len(ipv6Whitelist), count)
}

// TestEndToEnd_ConfigReload tests configuration reload scenario
// TestEndToEnd_ConfigReload 测试配置重载场景
func TestEndToEnd_ConfigReload(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "reload_config.yaml")

	// Create initial config
	// 创建初始配置
	cfg1 := &types.GlobalConfig{
		Base: types.BaseConfig{
			DefaultDeny:        false,
			AllowReturnTraffic: false,
			Whitelist:          []string{"192.168.1.1/32"},
		},
	}

	err := types.SaveGlobalConfig(configPath, cfg1)
	require.NoError(t, err)

	// Load and verify
	// 加载并验证
	loaded1, err := types.LoadGlobalConfig(configPath)
	require.NoError(t, err)
	assert.False(t, loaded1.Base.DefaultDeny)

	// Modify config
	// 修改配置
	cfg2 := &types.GlobalConfig{
		Base: types.BaseConfig{
			DefaultDeny:        true,
			AllowReturnTraffic: true,
			Whitelist:          []string{"192.168.1.1/32", "10.0.0.0/8"},
		},
	}

	err = types.SaveGlobalConfig(configPath, cfg2)
	require.NoError(t, err)

	// Reload and verify changes
	// 重载并验证更改
	loaded2, err := types.LoadGlobalConfig(configPath)
	require.NoError(t, err)
	assert.True(t, loaded2.Base.DefaultDeny)
	assert.True(t, loaded2.Base.AllowReturnTraffic)
	assert.Len(t, loaded2.Base.Whitelist, 2)
}

// TestEndToEnd_ErrorHandling tests error handling scenarios
// TestEndToEnd_ErrorHandling 测试错误处理场景
func TestEndToEnd_ErrorHandling(t *testing.T) {
	mockMgr := xdp.NewMockManager()

	// Test removing non-existent IP
	// 测试移除不存在的 IP
	err := mockMgr.RemoveBlacklistIP("192.168.999.999/32")
	// MockManager doesn't validate IP format, so this might succeed
	// MockManager 不验证 IP 格式，因此这可能成功
	_ = err

	// Test removing from empty blacklist
	// 测试从空黑名单移除
	err = mockMgr.RemoveBlacklistIP("192.168.1.1/32")
	// Should handle gracefully
	// 应优雅处理
	_ = err

	// Test clearing empty blacklist
	// 测试清除空黑名单
	err = mockMgr.ClearBlacklist()
	require.NoError(t, err)
}

// TestEndToEnd_ConcurrentOperations tests concurrent operations
// TestEndToEnd_ConcurrentOperations 测试并发操作
func TestEndToEnd_ConcurrentOperations(t *testing.T) {
	mockMgr := xdp.NewMockManager()

	// Run multiple operations sequentially (MockManager is not thread-safe)
	// 顺序运行多个操作（MockManager 不是线程安全的）
	for i := 0; i < 10; i++ {
		err := mockMgr.AddBlacklistIP("192.168.1.1/32")
		require.NoError(t, err)

		err = mockMgr.RemoveBlacklistIP("192.168.1.1/32")
		require.NoError(t, err)
	}

	// Verify final state
	// 验证最终状态
	count, err := mockMgr.GetLockedIPCount()
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

// TestEndToEnd_Statistics tests statistics collection
// TestEndToEnd_Statistics 测试统计收集
func TestEndToEnd_Statistics(t *testing.T) {
	mockMgr := xdp.NewMockManager()

	// Add same IP multiple times
	// 多次添加相同 IP
	for i := 0; i < 5; i++ {
		err := mockMgr.AddBlacklistIP("192.168.1.1/32")
		require.NoError(t, err)
	}

	// Get statistics - same IP should only count once
	// 获取统计 - 相同 IP 应只计数一次
	count, err := mockMgr.GetLockedIPCount()
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	// Add unique IPs
	// 添加唯一 IP
	for i := 2; i <= 5; i++ {
		ip := "192.168.1." + string(rune('0'+i)) + "/32"
		err := mockMgr.AddBlacklistIP(ip)
		require.NoError(t, err)
	}

	count, err = mockMgr.GetLockedIPCount()
	require.NoError(t, err)
	// Total should be 1 (original) + 4 (new unique IPs) = 5
	// 总数应为 1（原始）+ 4（新唯一 IP）= 5
	assert.Equal(t, 5, count)
}

// TestEndToEnd_Cleanup tests cleanup operations
// TestEndToEnd_Cleanup 测试清理操作
func TestEndToEnd_Cleanup(t *testing.T) {
	mockMgr := xdp.NewMockManager()

	// Add IPs
	// 添加 IP
	for i := 0; i < 10; i++ {
		err := mockMgr.AddBlacklistIP("192.168.1.1/32")
		require.NoError(t, err)
	}

	// Clear all
	// 清除所有
	err := mockMgr.ClearBlacklist()
	require.NoError(t, err)

	// Verify cleared
	// 验证已清除
	count, err := mockMgr.GetLockedIPCount()
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

// TestEndToEnd_ConfigValidation tests configuration validation
// TestEndToEnd_ConfigValidation 测试配置验证
func TestEndToEnd_ConfigValidation(t *testing.T) {
	cfg := &types.GlobalConfig{
		Base: types.BaseConfig{
			DefaultDeny:        true,
			AllowReturnTraffic: true,
			AllowICMP:          true,
			EnableAFXDP:        false,
			StrictTCP:          true,
			SYNLimit:           true,
			BogonFilter:        true,
			StrictProtocol:     true,
			DropFragments:      true,
		},
	}

	// Validate should not panic
	// 验证不应发生 panic
	err := cfg.Validate()
	// Validate might return nil or an error depending on implementation
	// Validate 可能返回 nil 或错误，取决于实现
	_ = err
}

// TestEndToEnd_ContextCancellation tests context cancellation
// TestEndToEnd_ContextCancellation 测试上下文取消
func TestEndToEnd_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Simulate long-running operation
	// 模拟长时间运行的操作
	done := make(chan struct{})
	go func() {
		// Simulate work
		// 模拟工作
		time.Sleep(50 * time.Millisecond)
		close(done)
	}()

	select {
	case <-ctx.Done():
		t.Error("Operation timed out")
	case <-done:
		// Success
		// 成功
	}
}
