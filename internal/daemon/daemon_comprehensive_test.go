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

	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/stretchr/testify/assert"
)

// TestRun_DpMode tests Run function with dp mode
// TestRun_DpMode 测试 Run 函数的 dp 模式
func TestRun_DpMode(t *testing.T) {
	// Skip this test as it requires actual daemon setup
	// 跳过此测试，因为它需要实际的守护进程设置
	t.Skip("Requires actual daemon setup with BPF maps")
}

// TestRun_AgentMode tests Run function with agent mode
// TestRun_AgentMode 测试 Run 函数的 agent 模式
func TestRun_AgentMode(t *testing.T) {
	// Skip this test as it requires actual daemon setup
	// 跳过此测试，因为它需要实际的守护进程设置
	t.Skip("Requires actual daemon setup with BPF maps")
}

// TestRun_UnifiedMode tests Run function with unified mode
// TestRun_UnifiedMode 测试 Run 函数的 unified 模式
func TestRun_UnifiedMode(t *testing.T) {
	// Skip this test as it requires actual daemon setup
	// 跳过此测试，因为它需要实际的守护进程设置
	t.Skip("Requires actual daemon setup with BPF maps")
}

// TestRun_NilOptions tests Run function with nil options
// TestRun_NilOptions 测试 Run 函数的 nil 选项
func TestRun_NilOptions(t *testing.T) {
	// Skip this test as it requires actual daemon setup
	// 跳过此测试，因为它需要实际的守护进程设置
	t.Skip("Requires actual daemon setup with BPF maps")
}

// TestStartPprof tests starting pprof server
// TestStartPprof 测试启动 pprof 服务器
func TestStartPprof(t *testing.T) {
	// Use a random high port to avoid conflicts
	// 使用随机高端口避免冲突
	port := 65433

	// Start pprof
	// 启动 pprof
	startPprof(port)

	// Give it time to start
	// 给它启动时间
	time.Sleep(50 * time.Millisecond)

	// The server should be running
	// 服务器应该正在运行
	// We can't easily test if it's running without making HTTP requests
	// 我们无法轻松测试它是否正在运行而不发出 HTTP 请求
}

// TestCleanupLoop_EnabledState tests cleanup loop when enabled
// TestCleanupLoop_EnabledState 测试启用时的清理循环
func TestCleanupLoop_EnabledState(t *testing.T) {
	// Skip this test as it requires actual BPF maps
	// 跳过此测试，因为它需要实际的 BPF Map
	t.Skip("Requires actual BPF maps to be available")
}

// TestCleanupLoop_ContextCancel tests cleanup loop context cancellation
// TestCleanupLoop_ContextCancel 测试清理循环上下文取消
func TestCleanupLoop_ContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	globalCfg := &types.GlobalConfig{
		Base: types.BaseConfig{
			EnableExpiry:    true,
			CleanupInterval: "1h", // Long interval
		},
	}

	done := make(chan bool)
	go func() {
		runCleanupLoop(ctx, globalCfg)
		done <- true
	}()

	// Cancel immediately
	// 立即取消
	cancel()

	select {
	case <-done:
		// Expected
		// 预期
	case <-time.After(100 * time.Millisecond):
		t.Error("Cleanup loop should stop immediately on context cancellation")
	}
}

// TestManagePidFile_ConcurrentAccess tests concurrent PID file access
// TestManagePidFile_ConcurrentAccess 测试并发 PID 文件访问
func TestManagePidFile_ConcurrentAccess(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "pid_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	pidPath := filepath.Join(tmpDir, "concurrent.pid")

	// First call should succeed
	// 第一次调用应该成功
	err = managePidFile(pidPath)
	assert.NoError(t, err)

	// Second call should fail
	// 第二次调用应该失败
	err = managePidFile(pidPath)
	assert.Error(t, err)

	// Clean up
	// 清理
	removePidFile(pidPath)

	// Should succeed again
	// 应该再次成功
	err = managePidFile(pidPath)
	assert.NoError(t, err)

	removePidFile(pidPath)
}

// TestManagePidFile_DeadProcess tests PID file with dead process
// TestManagePidFile_DeadProcess 测试包含已死进程的 PID 文件
func TestManagePidFile_DeadProcess(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "pid_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	pidPath := filepath.Join(tmpDir, "dead.pid")

	// Find a PID that doesn't exist
	// 查找不存在的 PID
	nonExistentPID := 40000
	for i := 0; i < 100; i++ {
		process, err := os.FindProcess(nonExistentPID)
		if err == nil {
			err = process.Signal(syscall.Signal(0))
			if err != nil {
				break
			}
		}
		nonExistentPID++
	}

	// Write PID for non-existent process
	// 写入不存在进程的 PID
	err = os.WriteFile(pidPath, []byte(strconv.Itoa(nonExistentPID)), 0644)
	assert.NoError(t, err)

	// Should remove stale PID file and create new one
	// 应该删除过期的 PID 文件并创建新文件
	err = managePidFile(pidPath)
	assert.NoError(t, err)

	// Verify new PID file was created with current PID
	// 验证新 PID 文件已创建并包含当前 PID
	content, err := os.ReadFile(pidPath)
	assert.NoError(t, err)
	assert.Equal(t, strconv.Itoa(os.Getpid()), strings.TrimSpace(string(content)))

	removePidFile(pidPath)
}

// TestWaitForSignal_SIGHUP tests waitForSignal with SIGHUP
// TestWaitForSignal_SIGHUP 测试 waitForSignal 的 SIGHUP 信号
func TestWaitForSignal_SIGHUP(t *testing.T) {
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

	// Run waitForSignal in goroutine
	// 在 goroutine 中运行 waitForSignal
	done := make(chan bool)
	go func() {
		waitForSignal(ctx, "", nil, reloadFunc, stopFunc)
		done <- true
	}()

	// Send SIGHUP
	// 发送 SIGHUP
	time.Sleep(50 * time.Millisecond)
	syscall.Kill(os.Getpid(), syscall.SIGHUP)

	// Wait for reload to be called
	// 等待 reload 被调用
	time.Sleep(100 * time.Millisecond)

	// Send SIGTERM to stop
	// 发送 SIGTERM 以停止
	syscall.Kill(os.Getpid(), syscall.SIGTERM)

	<-done

	assert.True(t, reloadCalled, "Reload function should be called on SIGHUP")
	assert.True(t, stopCalled, "Stop function should be called on SIGTERM")
}

// TestWaitForSignal_ReloadError tests waitForSignal with reload error
// TestWaitForSignal_ReloadError 测试 waitForSignal 的 reload 错误
func TestWaitForSignal_ReloadError(t *testing.T) {
	ctx := context.Background()

	reloadFunc := func() error {
		return assert.AnError
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

	time.Sleep(50 * time.Millisecond)
	syscall.Kill(os.Getpid(), syscall.SIGHUP)
	time.Sleep(50 * time.Millisecond)
	syscall.Kill(os.Getpid(), syscall.SIGTERM)

	<-done

	assert.True(t, stopCalled)
}

// TestWaitForSignal_NilFunctions tests waitForSignal with nil functions
// TestWaitForSignal_NilFunctions 测试 waitForSignal 的 nil 函数
func TestWaitForSignal_NilFunctions(t *testing.T) {
	ctx := context.Background()

	done := make(chan bool)
	go func() {
		waitForSignal(ctx, "", nil, nil, nil)
		done <- true
	}()

	time.Sleep(50 * time.Millisecond)
	syscall.Kill(os.Getpid(), syscall.SIGTERM)

	<-done
}

// TestWaitForSignal_SIGINT tests waitForSignal with SIGINT
// TestWaitForSignal_SIGINT 测试 waitForSignal 的 SIGINT 信号
func TestWaitForSignal_SIGINT(t *testing.T) {
	ctx := context.Background()

	stopCalled := false
	stopFunc := func() {
		stopCalled = true
	}

	done := make(chan bool)
	go func() {
		waitForSignal(ctx, "", nil, nil, stopFunc)
		done <- true
	}()

	time.Sleep(50 * time.Millisecond)
	syscall.Kill(os.Getpid(), syscall.SIGINT)

	<-done

	assert.True(t, stopCalled)
}

// TestDaemonOptions tests DaemonOptions struct
// TestDaemonOptions 测试 DaemonOptions 结构体
func TestDaemonOptions_New(t *testing.T) {
	opts := &DaemonOptions{}
	assert.Nil(t, opts.Manager)
}

// TestManagePidFile_InvalidContent tests PID file with invalid content
// TestManagePidFile_InvalidContent 测试包含无效内容的 PID 文件
func TestManagePidFile_InvalidContent(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "pid_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	pidPath := filepath.Join(tmpDir, "invalid.pid")

	// Write invalid content
	// 写入无效内容
	err = os.WriteFile(pidPath, []byte("not-a-number"), 0644)
	assert.NoError(t, err)

	// Should remove invalid PID file and create new one
	// 应该删除无效 PID 文件并创建新文件
	err = managePidFile(pidPath)
	assert.NoError(t, err)

	// Verify new PID file was created
	// 验证新 PID 文件已创建
	content, err := os.ReadFile(pidPath)
	assert.NoError(t, err)
	assert.Equal(t, strconv.Itoa(os.Getpid()), strings.TrimSpace(string(content)))

	removePidFile(pidPath)
}

// TestRemovePidFile_Error tests removePidFile with non-existent file
// TestRemovePidFile_Error 测试删除不存在的 PID 文件
func TestRemovePidFile_Error(t *testing.T) {
	// Should not panic on non-existent file
	// 不存在的文件不应 panic
	removePidFile("/non/existent/path/pid")
}
