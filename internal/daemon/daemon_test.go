package daemon

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/netxfw/netxfw/internal/xdp"
	"github.com/stretchr/testify/assert"
)

// TestManagePidFile tests PID file management
// TestManagePidFile 测试 PID 文件管理
func TestManagePidFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "pid_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	pidPath := filepath.Join(tmpDir, "test.pid")

	// Test creating new PID file
	// 测试创建新 PID 文件
	err = managePidFile(pidPath)
	assert.NoError(t, err)

	// Verify PID file was created
	// 验证 PID 文件已创建
	_, err = os.Stat(pidPath)
	assert.NoError(t, err)

	// Test that second call fails (process already running)
	// 测试第二次调用失败（进程已在运行）
	err = managePidFile(pidPath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "PID file")

	// Remove PID file and test again
	// 删除 PID 文件并再次测试
	removePidFile(pidPath)

	// Verify PID file was removed
	// 验证 PID 文件已删除
	_, err = os.Stat(pidPath)
	assert.True(t, os.IsNotExist(err))
}

// TestManagePidFile_InvalidPID tests PID file with invalid content
// TestManagePidFile_InvalidPID 测试包含无效内容的 PID 文件
func TestManagePidFile_InvalidPID(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "pid_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	pidPath := filepath.Join(tmpDir, "test.pid")

	// Write invalid PID content
	// 写入无效 PID 内容
	err = os.WriteFile(pidPath, []byte("invalid"), 0644)
	assert.NoError(t, err)

	// Should remove invalid PID file and create new one
	// 应该删除无效 PID 文件并创建新文件
	err = managePidFile(pidPath)
	assert.NoError(t, err)

	// Verify new PID file was created
	// 验证新 PID 文件已创建
	content, err := os.ReadFile(pidPath)
	assert.NoError(t, err)
	assert.NotEqual(t, "invalid", string(content))
}

// TestManagePidFile_NonExistentProcess tests PID file with non-existent process
// TestManagePidFile_NonExistentProcess 测试包含不存在进程的 PID 文件
func TestManagePidFile_NonExistentProcess(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "pid_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	pidPath := filepath.Join(tmpDir, "test.pid")

	// Write PID for non-existent process (very large PID)
	// 写入不存在进程的 PID（非常大的 PID）
	err = os.WriteFile(pidPath, []byte("999999999"), 0644)
	assert.NoError(t, err)

	// Should remove stale PID file and create new one
	// 应该删除过期的 PID 文件并创建新文件
	err = managePidFile(pidPath)
	assert.NoError(t, err)
}

// TestRemovePidFile tests PID file removal
// TestRemovePidFile 测试 PID 文件删除
func TestRemovePidFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "pid_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	pidPath := filepath.Join(tmpDir, "test.pid")

	// Create PID file
	// 创建 PID 文件
	err = os.WriteFile(pidPath, []byte("12345"), 0644)
	assert.NoError(t, err)

	// Remove PID file
	// 删除 PID 文件
	removePidFile(pidPath)

	// Verify file was removed
	// 验证文件已删除
	_, err = os.Stat(pidPath)
	assert.True(t, os.IsNotExist(err))
}

// TestRemovePidFile_NonExistent tests removing non-existent PID file
// TestRemovePidFile_NonExistent 测试删除不存在的 PID 文件
func TestRemovePidFile_NonExistent(t *testing.T) {
	// Should not error on non-existent file
	// 不存在的文件不应报错
	removePidFile("/non/existent/path/pid")
}

// TestDaemonOptions tests DaemonOptions struct
// TestDaemonOptions 测试 DaemonOptions 结构体
func TestDaemonOptions(t *testing.T) {
	opts := &DaemonOptions{}
	assert.Nil(t, opts.Manager)
}

// TestCleanupLoopDisabled tests that cleanup loop is disabled when EnableExpiry is false
// TestCleanupLoopDisabled 测试当 EnableExpiry 为 false 时清理循环被禁用
func TestCleanupLoopDisabled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	globalCfg := &types.GlobalConfig{
		Base: types.BaseConfig{
			EnableExpiry: false,
		},
	}

	// Should return immediately when disabled
	// 禁用时应立即返回
	done := make(chan bool)
	go func() {
		runCleanupLoop(ctx, globalCfg)
		done <- true
	}()

	select {
	case <-done:
		// Expected
		// 预期
	case <-time.After(100 * time.Millisecond):
		t.Error("Cleanup loop should return immediately when disabled")
	}
}

// TestCleanupLoop_InvalidInterval tests cleanup loop with invalid interval
// TestCleanupLoop_InvalidInterval 测试清理循环的无效间隔
func TestCleanupLoop_InvalidInterval(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	globalCfg := &types.GlobalConfig{
		Base: types.BaseConfig{
			EnableExpiry:    true,
			CleanupInterval: "invalid",
		},
	}

	// Should use default interval and run
	// 应该使用默认间隔并运行
	done := make(chan bool)
	go func() {
		runCleanupLoop(ctx, globalCfg)
		done <- true
	}()

	// Cancel context to stop the loop
	// 取消上下文以停止循环
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// Expected - loop stopped
		// 预期 - 循环已停止
	case <-time.After(200 * time.Millisecond):
		t.Error("Cleanup loop should stop when context is cancelled")
	}
}

// TestDaemonOptions_Fields tests DaemonOptions field assignments
// TestDaemonOptions_Fields 测试 DaemonOptions 字段赋值
func TestDaemonOptions_Fields(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	opts := &DaemonOptions{
		Manager: mockMgr,
	}

	assert.NotNil(t, opts.Manager)
	assert.Equal(t, mockMgr, opts.Manager)
}

// TestDaemonOptions_Defaults tests DaemonOptions default values
// TestDaemonOptions_Defaults 测试 DaemonOptions 默认值
func TestDaemonOptions_Defaults(t *testing.T) {
	opts := &DaemonOptions{}
	assert.Nil(t, opts.Manager)
}

// TestManagePidFile_EmptyPath tests PID file with empty path
// TestManagePidFile_EmptyPath 测试空路径的 PID 文件
func TestManagePidFile_EmptyPath(t *testing.T) {
	// Should fail with empty path
	// 空路径应该失败
	err := managePidFile("")
	assert.Error(t, err)
}

// TestManagePidFile_Overwrite tests overwriting PID file
// TestManagePidFile_Overwrite 测试覆盖 PID 文件
func TestManagePidFile_Overwrite(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "pid_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	pidPath := filepath.Join(tmpDir, "test.pid")

	// Write a PID for a non-existent process
	// 写入不存在进程的 PID
	err = os.WriteFile(pidPath, []byte("999999999"), 0644)
	assert.NoError(t, err)

	// Should overwrite stale PID file
	// 应该覆盖过期的 PID 文件
	err = managePidFile(pidPath)
	assert.NoError(t, err)

	// Verify new PID was written
	// 验证新 PID 已写入
	content, err := os.ReadFile(pidPath)
	assert.NoError(t, err)
	assert.NotEqual(t, "999999999", string(content))

	// Verify it's a valid PID
	// 验证它是有效的 PID
	currentPid := os.Getpid()
	assert.Equal(t, strconv.Itoa(currentPid), string(content))
}

// TestManagePidFile_Directory tests PID file in non-existent directory
// TestManagePidFile_Directory 测试不存在目录中的 PID 文件
func TestManagePidFile_Directory(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "pid_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create PID file in subdirectory
	// 在子目录中创建 PID 文件
	pidPath := filepath.Join(tmpDir, "subdir", "test.pid")

	// Should fail because subdirectory doesn't exist
	// 应该失败，因为子目录不存在
	err = managePidFile(pidPath)
	assert.Error(t, err)
}

// TestManagePidFile_MultipleCalls tests multiple calls to managePidFile
// TestManagePidFile_MultipleCalls 测试多次调用 managePidFile
func TestManagePidFile_MultipleCalls(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "pid_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	pidPath := filepath.Join(tmpDir, "test.pid")

	// First call should succeed
	// 第一次调用应该成功
	err = managePidFile(pidPath)
	assert.NoError(t, err)

	// Second call should fail (process already running)
	// 第二次调用应该失败（进程已在运行）
	err = managePidFile(pidPath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "PID file")

	// Remove and try again
	// 删除并重试
	removePidFile(pidPath)
	err = managePidFile(pidPath)
	assert.NoError(t, err)
}

// TestRemovePidFile_MultipleCalls tests multiple calls to removePidFile
// TestRemovePidFile_MultipleCalls 测试多次调用 removePidFile
func TestRemovePidFile_MultipleCalls(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "pid_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	pidPath := filepath.Join(tmpDir, "test.pid")

	// Create PID file
	// 创建 PID 文件
	err = os.WriteFile(pidPath, []byte("12345"), 0644)
	assert.NoError(t, err)

	// First call should succeed
	// 第一次调用应该成功
	removePidFile(pidPath)

	// Second call should not panic (file doesn't exist)
	// 第二次调用不应该 panic（文件不存在）
	removePidFile(pidPath)
}

// TestDaemonOptions_WithManager tests DaemonOptions with manager
// TestDaemonOptions_WithManager 测试带管理器的 DaemonOptions
func TestDaemonOptions_WithManager(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	opts := &DaemonOptions{
		Manager: mockMgr,
	}

	assert.NotNil(t, opts.Manager)
	assert.IsType(t, &xdp.MockManager{}, opts.Manager)
}

// TestCleanupLoop_DefaultInterval tests cleanup loop with default interval
// TestCleanupLoop_DefaultInterval 测试带默认间隔的清理循环
func TestCleanupLoop_DefaultInterval(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	globalCfg := &types.GlobalConfig{
		Base: types.BaseConfig{
			EnableExpiry:    true,
			CleanupInterval: "", // Empty - should use default
		},
	}

	done := make(chan bool)
	go func() {
		runCleanupLoop(ctx, globalCfg)
		done <- true
	}()

	// Let it run briefly
	// 让它短暂运行
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// Expected
		// 预期
	case <-time.After(200 * time.Millisecond):
		t.Error("Cleanup loop should stop when context is cancelled")
	}
}

// TestManagePidFile_ValidPID tests PID file with valid existing process
// TestManagePidFile_ValidPID 测试有效存在进程的 PID 文件
func TestManagePidFile_ValidPID(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "pid_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	pidPath := filepath.Join(tmpDir, "test.pid")

	// First call creates PID file
	// 第一次调用创建 PID 文件
	err = managePidFile(pidPath)
	assert.NoError(t, err)

	// Verify PID file contains current process PID
	// 验证 PID 文件包含当前进程 PID
	content, err := os.ReadFile(pidPath)
	assert.NoError(t, err)

	currentPid := os.Getpid()
	assert.Equal(t, strconv.Itoa(currentPid), strings.TrimSpace(string(content)))

	// Clean up
	// 清理
	removePidFile(pidPath)
}

// TestManagePidFile_Permissions tests PID file permissions
// TestManagePidFile_Permissions 测试 PID 文件权限
func TestManagePidFile_Permissions(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "pid_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	pidPath := filepath.Join(tmpDir, "test.pid")

	err = managePidFile(pidPath)
	assert.NoError(t, err)

	// Check file permissions
	// 检查文件权限
	info, err := os.Stat(pidPath)
	assert.NoError(t, err)
	assert.Equal(t, os.FileMode(0644), info.Mode().Perm())
}

// TestCleanupLoop_VariousIntervals tests cleanup loop with various intervals
// TestCleanupLoop_VariousIntervals 测试各种间隔的清理循环
func TestCleanupLoop_VariousIntervals(t *testing.T) {
	testCases := []struct {
		name     string
		interval string
		valid    bool
	}{
		{"valid_seconds", "30s", true},
		{"valid_minutes", "5m", true},
		{"valid_hours", "1h", true},
		{"invalid_format", "invalid", false},
		{"empty", "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			globalCfg := &types.GlobalConfig{
				Base: types.BaseConfig{
					EnableExpiry:    true,
					CleanupInterval: tc.interval,
				},
			}

			done := make(chan bool)
			go func() {
				runCleanupLoop(ctx, globalCfg)
				done <- true
			}()

			time.Sleep(30 * time.Millisecond)
			cancel()

			select {
			case <-done:
				// Expected
				// 预期
			case <-time.After(100 * time.Millisecond):
				t.Error("Cleanup loop should stop")
			}
		})
	}
}
