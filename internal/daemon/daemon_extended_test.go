package daemon

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/netxfw/netxfw/internal/xdp"
	"github.com/stretchr/testify/assert"
)

// TestRun_ModeSwitch tests Run function mode switching
// TestRun_ModeSwitch 测试 Run 函数的模式切换
func TestRun_ModeSwitch(t *testing.T) {
	tests := []struct {
		name    string
		mode    string
		opts    *DaemonOptions
		skipMsg string
	}{
		{
			name:    "dp mode",
			mode:    "dp",
			opts:    &DaemonOptions{},
			skipMsg: "Requires actual BPF maps",
		},
		{
			name:    "agent mode",
			mode:    "agent",
			opts:    &DaemonOptions{},
			skipMsg: "Requires actual BPF maps",
		},
		{
			name:    "unified mode (default)",
			mode:    "",
			opts:    &DaemonOptions{},
			skipMsg: "Requires actual BPF maps",
		},
		{
			name:    "nil options",
			mode:    "",
			opts:    nil,
			skipMsg: "Requires actual BPF maps",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Skip(tt.skipMsg)
		})
	}
}

// TestRunControlPlane_Basic tests runControlPlane function basic behavior
// TestRunControlPlane_Basic 测试 runControlPlane 函数的基本行为
func TestRunControlPlane_Basic(t *testing.T) {
	t.Skip("Requires actual BPF maps and plugin system")
}

// TestRunDataPlane_Basic tests runDataPlane function basic behavior
// TestRunDataPlane_Basic 测试 runDataPlane 函数的基本行为
func TestRunDataPlane_Basic(t *testing.T) {
	t.Skip("Requires actual BPF maps and plugin system")
}

// TestRunUnified_Basic tests runUnified function basic behavior
// TestRunUnified_Basic 测试 runUnified 函数的基本行为
func TestRunUnified_Basic(t *testing.T) {
	t.Skip("Requires actual BPF maps and plugin system")
}

// TestCleanupOrphanedInterfaces_Basic tests cleanupOrphanedInterfaces function
// TestCleanupOrphanedInterfaces_Basic 测试 cleanupOrphanedInterfaces 函数
func TestCleanupOrphanedInterfaces_Basic(t *testing.T) {
	t.Skip("Requires actual XDP interfaces")
}

// TestCleanupLoop_Disabled tests cleanup loop when disabled
// TestCleanupLoop_Disabled 测试禁用时的清理循环
func TestCleanupLoop_Disabled(t *testing.T) {
	ctx := context.Background()
	globalCfg := &types.GlobalConfig{
		Base: types.BaseConfig{
			EnableExpiry: false,
		},
	}

	done := make(chan bool)
	go func() {
		runCleanupLoop(ctx, globalCfg)
		done <- true
	}()

	select {
	case <-done:
		// Expected - should return immediately when disabled
		// 预期 - 禁用时应立即返回
	case <-time.After(100 * time.Millisecond):
		t.Error("Cleanup loop should return immediately when disabled")
	}
}

// TestCleanupLoop_InvalidIntervalExtended tests cleanup loop with invalid interval
// TestCleanupLoop_InvalidIntervalExtended 测试无效间隔的清理循环
func TestCleanupLoop_InvalidIntervalExtended(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	globalCfg := &types.GlobalConfig{
		Base: types.BaseConfig{
			EnableExpiry:    true,
			CleanupInterval: "invalid",
		},
	}

	done := make(chan bool)
	go func() {
		runCleanupLoop(ctx, globalCfg)
		done <- true
	}()

	// Should use default interval of 1m
	// 应该使用默认间隔 1m
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// Expected
		// 预期
	case <-time.After(100 * time.Millisecond):
		t.Error("Cleanup loop should stop on context cancellation")
	}
}

// TestManagePidFile_ExistingRunningProcess tests PID file with existing running process
// TestManagePidFile_ExistingRunningProcess 测试包含正在运行进程的 PID 文件
func TestManagePidFile_ExistingRunningProcess(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "pid_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	pidPath := filepath.Join(tmpDir, "running.pid")

	// Write current process PID
	// 写入当前进程 PID
	currentPID := os.Getpid()
	err = os.WriteFile(pidPath, []byte(strconv.Itoa(currentPID)), 0644)
	assert.NoError(t, err)

	// Should fail because current process is running
	// 应该失败，因为当前进程正在运行
	err = managePidFile(pidPath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "is running")
}

// TestManagePidFile_PermissionError tests PID file with permission error
// TestManagePidFile_PermissionError 测试权限错误的 PID 文件
func TestManagePidFile_PermissionError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("Skipping test when running as root")
	}

	// Try to write to a directory that requires root
	// 尝试写入需要 root 权限的目录
	err := managePidFile("/root/test_pid.pid")
	assert.Error(t, err)
}

// TestStartPprof_MultiplePorts tests starting multiple pprof servers
// TestStartPprof_MultiplePorts 测试启动多个 pprof 服务器
func TestStartPprof_MultiplePorts(t *testing.T) {
	// Start first pprof server
	// 启动第一个 pprof 服务器
	startPprof(65434)
	time.Sleep(50 * time.Millisecond)

	// Starting another on the same port should fail silently
	// 在同一端口启动另一个应该静默失败
	startPprof(65434)
	time.Sleep(50 * time.Millisecond)
}

// TestWaitForSignal_MultipleSIGHUP tests multiple SIGHUP signals
// TestWaitForSignal_MultipleSIGHUP 测试多个 SIGHUP 信号
func TestWaitForSignal_MultipleSIGHUP(t *testing.T) {
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

// TestWaitForSignal_SIGTERM tests SIGTERM signal
// TestWaitForSignal_SIGTERM 测试 SIGTERM 信号
func TestWaitForSignal_SIGTERM(t *testing.T) {
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
	syscall.Kill(os.Getpid(), syscall.SIGTERM)

	<-done

	assert.True(t, stopCalled, "Stop function should be called on SIGTERM")
}

// TestDaemonOptions_WithManagerExtended tests DaemonOptions with Manager
// TestDaemonOptions_WithManagerExtended 测试带 Manager 的 DaemonOptions
func TestDaemonOptions_WithManagerExtended(t *testing.T) {
	opts := &DaemonOptions{
		Manager: xdp.NewMockManager(),
	}

	assert.NotNil(t, opts.Manager)
}
