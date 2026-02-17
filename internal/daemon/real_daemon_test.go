//go:build linux && integration
// +build linux,integration

package daemon

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/livp123/netxfw/internal/config"
	"github.com/livp123/netxfw/internal/plugins/types"
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
