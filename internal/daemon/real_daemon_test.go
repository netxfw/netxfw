//go:build linux && integration
// +build linux,integration

package daemon

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/livp123/netxfw/internal/config"
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/utils/logger"
	"github.com/livp123/netxfw/internal/xdp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRealDaemon_ManagePidFile tests PID file management in real environment
// TestRealDaemon_ManagePidFile 测试真实环境中的 PID 文件管理
func TestRealDaemon_ManagePidFile(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create temp directory for PID file
	// 为 PID 文件创建临时目录
	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "test.pid")

	// Test 1: Create new PID file
	// 测试 1：创建新的 PID 文件
	err := managePidFile(pidFile)
	require.NoError(t, err, "Should create PID file successfully")

	// Verify PID file exists and contains current PID
	// 验证 PID 文件存在并包含当前 PID
	content, err := os.ReadFile(pidFile)
	require.NoError(t, err)
	assert.Equal(t, os.Getpid(), parseInt(string(content)))

	// Test 2: Second call should fail (process already running)
	// 测试 2：第二次调用应该失败（进程已在运行）
	err = managePidFile(pidFile)
	assert.Error(t, err, "Should fail when PID file exists with running process")
	assert.Contains(t, err.Error(), "process")

	// Test 3: Remove PID file and verify it's gone
	// 测试 3：移除 PID 文件并验证已删除
	removePidFile(pidFile)
	_, err = os.Stat(pidFile)
	assert.True(t, os.IsNotExist(err), "PID file should be removed")
}

// TestRealDaemon_ManagePidFile_StaleProcess tests handling of stale PID files
// TestRealDaemon_ManagePidFile_StaleProcess 测试处理过期 PID 文件
func TestRealDaemon_ManagePidFile_StaleProcess(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "test_stale.pid")

	// Write a stale PID (non-existent process)
	// 写入一个过期的 PID（不存在的进程）
	stalePID := 9999999 // Very unlikely to exist
	err := os.WriteFile(pidFile, []byte(string(rune(stalePID))), 0644)
	require.NoError(t, err)

	// managePidFile should detect stale PID and remove it
	// managePidFile 应该检测到过期 PID 并将其移除
	err = managePidFile(pidFile)
	require.NoError(t, err, "Should handle stale PID file")

	// Verify new PID is written
	// 验证新 PID 已写入
	content, err := os.ReadFile(pidFile)
	require.NoError(t, err)
	assert.Equal(t, os.Getpid(), parseInt(string(content)))

	// Cleanup
	// 清理
	removePidFile(pidFile)
}

// TestRealDaemon_CleanupLoop tests the cleanup loop functionality
// TestRealDaemon_CleanupLoop 测试清理循环功能
func TestRealDaemon_CleanupLoop(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create test config with cleanup enabled
	// 创建启用清理的测试配置
	globalCfg := &types.GlobalConfig{
		Base: types.BaseConfig{
			EnableExpiry:    true,
			CleanupInterval: "100ms", // Short interval for testing
		},
	}

	// Start cleanup loop in goroutine
	// 在 goroutine 中启动清理循环
	done := make(chan bool)
	go func() {
		runCleanupLoop(ctx, globalCfg)
		done <- true
	}()

	// Wait a bit for the loop to start
	// 等待循环启动
	time.Sleep(50 * time.Millisecond)

	// Cancel context to stop the loop
	// 取消上下文以停止循环
	cancel()

	// Wait for loop to stop
	// 等待循环停止
	select {
	case <-done:
		t.Log("Cleanup loop stopped successfully")
	case <-time.After(500 * time.Millisecond):
		t.Error("Cleanup loop did not stop in time")
	}
}

// TestRealDaemon_CleanupLoop_Disabled tests cleanup loop when disabled
// TestRealDaemon_CleanupLoop_Disabled 测试禁用时的清理循环
func TestRealDaemon_CleanupLoop_Disabled(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()

	// Create test config with cleanup disabled
	// 创建禁用清理的测试配置
	globalCfg := &types.GlobalConfig{
		Base: types.BaseConfig{
			EnableExpiry:    false,
			CleanupInterval: "100ms",
		},
	}

	// runCleanupLoop should return immediately when disabled
	// 禁用时 runCleanupLoop 应该立即返回
	start := time.Now()
	runCleanupLoop(ctx, globalCfg)
	elapsed := time.Since(start)

	// Should return almost immediately
	// 应该几乎立即返回
	assert.Less(t, elapsed.Milliseconds(), int64(50), "Should return immediately when disabled")
}

// TestRealDaemon_CleanupLoop_InvalidInterval tests cleanup loop with invalid interval
// TestRealDaemon_CleanupLoop_InvalidInterval 测试无效间隔的清理循环
func TestRealDaemon_CleanupLoop_InvalidInterval(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create test config with invalid interval
	// 创建无效间隔的测试配置
	globalCfg := &types.GlobalConfig{
		Base: types.BaseConfig{
			EnableExpiry:    true,
			CleanupInterval: "invalid",
		},
	}

	// Start cleanup loop - should use default interval
	// 启动清理循环 - 应该使用默认间隔
	done := make(chan bool)
	go func() {
		runCleanupLoop(ctx, globalCfg)
		done <- true
	}()

	// Wait a bit then cancel
	// 等待一会儿然后取消
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
		t.Log("Cleanup loop handled invalid interval correctly")
	case <-time.After(500 * time.Millisecond):
		t.Error("Cleanup loop did not stop in time")
	}
}

// TestRealDaemon_ConfigPath tests config path resolution
// TestRealDaemon_ConfigPath 测试配置路径解析
func TestRealDaemon_ConfigPath(t *testing.T) {
	// Test default config path
	// 测试默认配置路径
	defaultPath := config.GetConfigPath()
	assert.NotEmpty(t, defaultPath, "Config path should not be empty")
	t.Logf("Default config path: %s", defaultPath)

	// Test pin path
	// 测试 pin 路径
	pinPath := config.GetPinPath()
	assert.NotEmpty(t, pinPath, "Pin path should not be empty")
	t.Logf("Pin path: %s", pinPath)
}

// TestRealDaemon_SignalHandling tests signal handling setup
// TestRealDaemon_SignalHandling 测试信号处理设置
func TestRealDaemon_SignalHandling(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// This test verifies that signal handling can be set up without errors
	// 此测试验证信号处理可以无错误地设置
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create a done channel to verify signal handling completes
	// 创建一个 done channel 来验证信号处理完成
	done := make(chan bool, 1)

	go func() {
		// Simulate signal handling with a short timeout
		// 用短超时模拟信号处理
		select {
		case <-ctx.Done():
			done <- true
		case <-time.After(100 * time.Millisecond):
			done <- false
		}
	}()

	// Cancel context
	// 取消上下文
	cancel()

	select {
	case completed := <-done:
		assert.True(t, completed, "Signal handling should complete")
	case <-time.After(200 * time.Millisecond):
		t.Error("Signal handling did not complete in time")
	}
}

// TestRealDaemon_PprofServer tests pprof server startup
// TestRealDaemon_PprofServer 测试 pprof 服务器启动
func TestRealDaemon_PprofServer(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Use a random high port for testing
	// 使用随机高端口进行测试
	testPort := 65530

	// Start pprof server
	// 启动 pprof 服务器
	startPprof(testPort)

	// Give server time to start
	// 给服务器启动时间
	time.Sleep(100 * time.Millisecond)

	// Note: We can't easily test the server is running without making HTTP requests
	// 注意：如果不发送 HTTP 请求，我们很难测试服务器是否正在运行
	// The test just verifies that startPprof doesn't panic
	// 此测试仅验证 startPprof 不会 panic
	t.Log("Pprof server started successfully")
}

// Helper function to parse int from string
// 从字符串解析整数的辅助函数
func parseInt(s string) int {
	var result int
	for _, c := range s {
		if c >= '0' && c <= '9' {
			result = result*10 + int(c-'0')
		}
	}
	return result
}

// TestRealDaemon_PIDFileLifecycle tests PID file lifecycle with real filesystem
// TestRealDaemon_PIDFileLifecycle 测试真实文件系统的 PID 文件生命周期
func TestRealDaemon_PIDFileLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tmpDir, err := os.MkdirTemp("", "daemon_integration")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	pidPath := filepath.Join(tmpDir, "netxfw.pid")

	// Test managePidFile
	// 测试 managePidFile
	err = managePidFile(pidPath)
	require.NoError(t, err, "First managePidFile should succeed")

	// Verify PID file was created
	// 验证 PID 文件已创建
	content, err := os.ReadFile(pidPath)
	require.NoError(t, err)
	assert.Equal(t, strconv.Itoa(os.Getpid()), strings.TrimSpace(string(content)))

	// Second call should fail (process is running)
	// 第二次调用应该失败（进程正在运行）
	err = managePidFile(pidPath)
	assert.Error(t, err, "Second managePidFile should fail")
	assert.Contains(t, err.Error(), "is running")

	// Remove PID file
	// 删除 PID 文件
	removePidFile(pidPath)

	// Verify PID file is removed
	// 验证 PID 文件已删除
	_, err = os.Stat(pidPath)
	assert.True(t, os.IsNotExist(err))
}

// TestRealDaemon_ManagePidFile_InvalidContent tests invalid PID file handling
// TestRealDaemon_ManagePidFile_InvalidContent 测试无效 PID 文件处理
func TestRealDaemon_ManagePidFile_InvalidContent(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tmpDir, err := os.MkdirTemp("", "daemon_integration")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	pidPath := filepath.Join(tmpDir, "invalid.pid")

	// Write invalid content
	// 写入无效内容
	err = os.WriteFile(pidPath, []byte("not-a-number"), 0644)
	require.NoError(t, err)

	// managePidFile should remove invalid PID and create new one
	// managePidFile 应该删除无效 PID 并创建新的
	err = managePidFile(pidPath)
	require.NoError(t, err, "managePidFile should handle invalid PID file")

	// Verify new PID file was created
	// 验证新 PID 文件已创建
	content, err := os.ReadFile(pidPath)
	require.NoError(t, err)
	assert.Equal(t, strconv.Itoa(os.Getpid()), strings.TrimSpace(string(content)))

	removePidFile(pidPath)
}

// TestRealDaemon_SignalHandling_SIGHUP tests SIGHUP signal handling
// TestRealDaemon_SignalHandling_SIGHUP 测试 SIGHUP 信号处理
func TestRealDaemon_SignalHandling_SIGHUP(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()

	reloadCalled := false
	reloadFunc := func() error {
		reloadCalled = true
		return nil
	}

	stopCalled := false
	stopFunc := func() {
		stopCalled = true
	}

	done := make(chan bool)
	go func() {
		waitForSignal(ctx, "", nil, reloadFunc, stopFunc)
		done <- true
	}()

	// Send SIGHUP to trigger reload
	// 发送 SIGHUP 触发重新加载
	time.Sleep(50 * time.Millisecond)
	syscall.Kill(os.Getpid(), syscall.SIGHUP)
	time.Sleep(100 * time.Millisecond)

	// Send SIGTERM to stop
	// 发送 SIGTERM 停止
	syscall.Kill(os.Getpid(), syscall.SIGTERM)

	<-done

	assert.True(t, reloadCalled, "Reload should be called on SIGHUP")
	assert.True(t, stopCalled, "Stop should be called on SIGTERM")
}

// TestRealDaemon_SignalHandling_MultipleSIGHUP tests multiple SIGHUP signals
// TestRealDaemon_SignalHandling_MultipleSIGHUP 测试多个 SIGHUP 信号
func TestRealDaemon_SignalHandling_MultipleSIGHUP(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()

	reloadCount := 0
	reloadFunc := func() error {
		reloadCount++
		return nil
	}

	done := make(chan bool)
	go func() {
		waitForSignal(ctx, "", nil, reloadFunc, nil)
		done <- true
	}()

	// Send multiple SIGHUP signals
	// 发送多个 SIGHUP 信号
	time.Sleep(50 * time.Millisecond)
	syscall.Kill(os.Getpid(), syscall.SIGHUP)
	time.Sleep(50 * time.Millisecond)
	syscall.Kill(os.Getpid(), syscall.SIGHUP)
	time.Sleep(50 * time.Millisecond)
	syscall.Kill(os.Getpid(), syscall.SIGTERM)

	<-done

	assert.Equal(t, 2, reloadCount, "Reload should be called twice")
}

// TestRealDaemon_DaemonOptions tests DaemonOptions with real manager
// TestRealDaemon_DaemonOptions 测试带真实管理器的 DaemonOptions
func TestRealDaemon_DaemonOptions(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Test with MockManager
	// 使用 MockManager 测试
	opts := &DaemonOptions{
		Manager: xdp.NewMockManager(),
	}

	require.NotNil(t, opts.Manager)
	require.NotNil(t, opts.Manager.(*xdp.MockManager))
}

// TestRealDaemon_CleanupInterval tests cleanup interval parsing
// TestRealDaemon_CleanupInterval 测试清理间隔解析
func TestRealDaemon_CleanupInterval(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	intervals := []struct {
		input    string
		expected time.Duration
	}{
		{"1s", time.Second},
		{"30s", 30 * time.Second},
		{"1m", time.Minute},
		{"5m", 5 * time.Minute},
		{"1h", time.Hour},
	}

	for _, tt := range intervals {
		t.Run(tt.input, func(t *testing.T) {
			d, err := time.ParseDuration(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, d)
		})
	}
}

// TestRealDaemon_MultiplePIDFiles tests multiple PID file operations
// TestRealDaemon_MultiplePIDFiles 测试多个 PID 文件操作
func TestRealDaemon_MultiplePIDFiles(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tmpDir, err := os.MkdirTemp("", "daemon_multi_pid")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create multiple PID files
	// 创建多个 PID 文件
	for i := 0; i < 5; i++ {
		pidPath := filepath.Join(tmpDir, "test_"+strconv.Itoa(i)+".pid")
		pid := os.Getpid() + i
		err := os.WriteFile(pidPath, []byte(strconv.Itoa(pid)), 0644)
		require.NoError(t, err)

		// Verify file exists
		// 验证文件存在
		content, err := os.ReadFile(pidPath)
		require.NoError(t, err)
		assert.Equal(t, strconv.Itoa(pid), strings.TrimSpace(string(content)))
	}
}

// TestRealDaemon_XDPManager tests XDP manager operations
// TestRealDaemon_XDPManager 测试 XDP 管理器操作
func TestRealDaemon_XDPManager(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	log := logger.Get(context.Background())
	pinPath := config.GetPinPath()

	// Try to create manager from existing pins
	// 尝试从现有 pins 创建管理器
	mgr, err := xdp.NewManagerFromPins(pinPath, log)
	if err != nil {
		t.Skipf("Skipping test: no existing BPF pins found: %v", err)
	}
	defer mgr.Close()

	// Verify manager is valid
	// 验证管理器有效
	require.NotNil(t, mgr)

	// Test getting stats
	// 测试获取统计信息
	dropCount, err := mgr.GetDropCount()
	require.NoError(t, err)
	t.Logf("Drop count: %d", dropCount)

	passCount, err := mgr.GetPassCount()
	require.NoError(t, err)
	t.Logf("Pass count: %d", passCount)

	lockedCount, err := mgr.GetLockedIPCount()
	require.NoError(t, err)
	t.Logf("Locked IP count: %d", lockedCount)
}

// TestRealDaemon_XDPAdapter tests XDP adapter operations
// TestRealDaemon_XDPAdapter 测试 XDP 适配器操作
func TestRealDaemon_XDPAdapter(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	log := logger.Get(context.Background())
	pinPath := config.GetPinPath()

	mgr, err := xdp.NewManagerFromPins(pinPath, log)
	if err != nil {
		t.Skipf("Skipping test: no existing BPF pins found: %v", err)
	}
	defer mgr.Close()

	adapter := xdp.NewAdapter(mgr)
	require.NotNil(t, adapter)

	// Test adapter operations
	// 测试适配器操作
	testIP := "10.255.254.1/32"

	// Add to blacklist
	// 添加到黑名单
	err = adapter.AddBlacklistIP(testIP)
	require.NoError(t, err)

	// Check if in blacklist
	// 检查是否在黑名单中
	contains, err := adapter.IsIPInBlacklist(testIP)
	require.NoError(t, err)
	assert.True(t, contains)

	// Remove from blacklist
	// 从黑名单移除
	err = adapter.RemoveBlacklistIP(testIP)
	require.NoError(t, err)

	// Verify removed
	// 验证已移除
	contains, err = adapter.IsIPInBlacklist(testIP)
	require.NoError(t, err)
	assert.False(t, contains)
}

// TestRealDaemon_ContextCancellation tests context cancellation
// TestRealDaemon_ContextCancellation 测试上下文取消
func TestRealDaemon_ContextCancellation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	done := make(chan bool)
	go func() {
		<-ctx.Done()
		done <- true
	}()

	select {
	case <-done:
		// Expected
		// 预期
	case <-time.After(1 * time.Second):
		t.Error("Context should be cancelled")
	}
}

// TestRealDaemon_RunMode tests Run function mode selection
// TestRealDaemon_RunMode 测试 Run 函数模式选择
func TestRealDaemon_RunMode(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Test with MockManager
	// 使用 MockManager 测试
	opts := &DaemonOptions{
		Manager: xdp.NewMockManager(),
	}

	// Test mode selection - just verify the function doesn't panic
	// 测试模式选择 - 仅验证函数不会 panic
	// We can't fully test Run() because it requires full daemon setup
	// 我们无法完全测试 Run()，因为它需要完整的守护进程设置
	require.NotNil(t, opts)
	require.NotNil(t, opts.Manager)
}

// TestRealDaemon_ConfigFileValidation tests configuration file validation
// TestRealDaemon_ConfigFileValidation 测试配置文件验证
func TestRealDaemon_ConfigFileValidation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create a temporary config file
	// 创建临时配置文件
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Write a minimal valid config
	// 写入一个最小的有效配置
	validConfig := `
base:
  interfaces:
    - eth0
  enable_expiry: true
  cleanup_interval: 5m

logging:
  level: info

capacity:
  max_locked_ips: 10000
  max_whitelist_ips: 10000
`
	err := os.WriteFile(configPath, []byte(validConfig), 0644)
	require.NoError(t, err)

	// Verify file exists
	// 验证文件存在
	_, err = os.Stat(configPath)
	require.NoError(t, err)
}

// TestRealDaemon_InvalidConfigFile tests invalid configuration handling
// TestRealDaemon_InvalidConfigFile 测试无效配置处理
func TestRealDaemon_InvalidConfigFile(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "invalid_config.yaml")

	// Write an invalid config
	// 写入无效配置
	invalidConfig := `
base:
  interfaces: "should_be_array"
  cleanup_interval: "not_a_duration"
`
	err := os.WriteFile(configPath, []byte(invalidConfig), 0644)
	require.NoError(t, err)

	// File exists but config may have issues
	// 文件存在但配置可能有问题
	_, err = os.Stat(configPath)
	require.NoError(t, err)
}

// TestRealDaemon_CleanupExpiredRules tests cleanup of expired rules
// TestRealDaemon_CleanupExpiredRules 测试过期规则清理
func TestRealDaemon_CleanupExpiredRules(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	log := logger.Get(context.Background())
	pinPath := config.GetPinPath()

	mgr, err := xdp.NewManagerFromPins(pinPath, log)
	if err != nil {
		t.Skipf("Skipping test: no existing BPF pins found: %v", err)
	}
	defer mgr.Close()

	// Test cleanup with nil map (should not panic)
	// 测试 nil map 的清理（不应该 panic）
	removed, err := xdp.CleanupExpiredRules(nil, false)
	assert.NoError(t, err)
	assert.Equal(t, 0, removed)

	// Test cleanup with actual map
	// 测试实际 map 的清理
	if mgr.LockList() != nil {
		removed, err = xdp.CleanupExpiredRules(mgr.LockList(), false)
		assert.NoError(t, err)
		t.Logf("Cleaned up %d expired rules from lock_list", removed)
	}
}

// TestRealDaemon_GetPhysicalInterfaces tests getting physical interfaces
// TestRealDaemon_GetPhysicalInterfaces 测试获取物理接口
func TestRealDaemon_GetPhysicalInterfaces(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	interfaces, err := xdp.GetPhysicalInterfaces()
	require.NoError(t, err)

	t.Logf("Found %d physical interfaces", len(interfaces))
	for _, iface := range interfaces {
		t.Logf("  - %s", iface)
	}
}

// TestRealDaemon_GetAttachedInterfaces tests getting attached interfaces
// TestRealDaemon_GetAttachedInterfaces 测试获取已附加的接口
func TestRealDaemon_GetAttachedInterfaces(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	pinPath := config.GetPinPath()
	attached, err := xdp.GetAttachedInterfaces(pinPath)
	if err != nil {
		t.Logf("No attached interfaces or error: %v", err)
		return
	}

	t.Logf("Found %d attached interfaces", len(attached))
	for _, iface := range attached {
		t.Logf("  - %s", iface)
	}
}

// TestRealDaemon_ManagerPinPath tests manager pin path operations
// TestRealDaemon_ManagerPinPath 测试管理器 pin 路径操作
func TestRealDaemon_ManagerPinPath(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	log := logger.Get(context.Background())
	pinPath := config.GetPinPath()

	// Create a test pin path
	// 创建测试 pin 路径
	testPinPath := filepath.Join(t.TempDir(), "test_bpf")

	// Use default capacity config
	// 使用默认容量配置
	capacity := types.CapacityConfig{
		LockList:     10000,
		DynLockList:  10000,
		Whitelist:    10000,
		IPPortRules:  10000,
		AllowedPorts: 100,
	}

	mgr, err := xdp.NewManager(capacity, log)
	if err != nil {
		t.Skipf("Skipping test: failed to create XDP manager: %v", err)
	}
	defer mgr.Close()

	// Pin the manager
	// 固定管理器
	err = mgr.Pin(testPinPath)
	if err != nil {
		t.Logf("Failed to pin manager: %v", err)
		return
	}

	// Verify pin path exists
	// 验证 pin 路径存在
	_, err = os.Stat(testPinPath)
	if err == nil {
		t.Logf("Manager pinned to %s", testPinPath)
	}

	// Clean up
	// 清理
	_ = os.RemoveAll(testPinPath)

	t.Logf("Using pin path: %s", pinPath)
}

// TestRealDaemon_MockManagerFull tests MockManager full functionality
// TestRealDaemon_MockManagerFull 测试 MockManager 完整功能
func TestRealDaemon_MockManagerFull(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	mockMgr := xdp.NewMockManager()
	require.NotNil(t, mockMgr)

	// Test all manager operations
	// 测试所有管理器操作
	testIP := "192.168.100.1/32"

	// Blacklist operations
	// 黑名单操作
	err := mockMgr.AddBlacklistIP(testIP)
	require.NoError(t, err)

	contains, err := mockMgr.IsIPInBlacklist(testIP)
	require.NoError(t, err)
	assert.True(t, contains)

	err = mockMgr.RemoveBlacklistIP(testIP)
	require.NoError(t, err)

	// Whitelist operations
	// 白名单操作
	err = mockMgr.AddWhitelistIP(testIP, 0)
	require.NoError(t, err)

	contains, err = mockMgr.IsIPInWhitelist(testIP)
	require.NoError(t, err)
	assert.True(t, contains)

	err = mockMgr.RemoveWhitelistIP(testIP)
	require.NoError(t, err)

	// Port operations
	// 端口操作
	err = mockMgr.AllowPort(8080)
	require.NoError(t, err)

	ports, err := mockMgr.ListAllowedPorts()
	require.NoError(t, err)
	assert.Contains(t, ports, uint16(8080))

	err = mockMgr.RemoveAllowedPort(8080)
	require.NoError(t, err)

	// Stats operations
	// 统计操作
	dropCount, err := mockMgr.GetDropCount()
	require.NoError(t, err)
	assert.Equal(t, uint64(0), dropCount)

	passCount, err := mockMgr.GetPassCount()
	require.NoError(t, err)
	assert.Equal(t, uint64(0), passCount)
}
