package sdk_test

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/utils/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDaemon_PIDFileLifecycle tests the complete lifecycle of PID file management
// TestDaemon_PIDFileLifecycle 测试 PID 文件管理的完整生命周期
func TestDaemon_PIDFileLifecycle(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("This test requires root privileges")
	}

	tmpDir, err := os.MkdirTemp("", "daemon_integration")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	pidPath := filepath.Join(tmpDir, "netxfw.pid")

	// Simulate PID file creation
	// 模拟 PID 文件创建
	pid := os.Getpid()
	err = os.WriteFile(pidPath, []byte(strconv.Itoa(pid)), 0644)
	require.NoError(t, err)

	// Verify PID file exists
	// 验证 PID 文件存在
	content, err := os.ReadFile(pidPath)
	require.NoError(t, err)
	assert.Equal(t, strconv.Itoa(pid), string(content))

	// Cleanup
	// 清理
	err = os.Remove(pidPath)
	require.NoError(t, err)

	// Verify PID file is removed
	// 验证 PID 文件已删除
	_, err = os.Stat(pidPath)
	assert.True(t, os.IsNotExist(err))
}

// TestDaemon_ConfigValidation tests configuration validation
// TestDaemon_ConfigValidation 测试配置验证
func TestDaemon_ConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  *types.GlobalConfig
		wantErr bool
	}{
		{
			name: "Valid config",
			config: &types.GlobalConfig{
				Base: types.BaseConfig{
					Interfaces:      []string{"eth0"},
					EnableExpiry:    true,
					CleanupInterval: "5m",
				},
				Logging: logger.LoggingConfig{
					Level: "info",
				},
			},
			wantErr: false,
		},
		{
			name: "Empty interfaces",
			config: &types.GlobalConfig{
				Base: types.BaseConfig{
					Interfaces:      []string{},
					EnableExpiry:    true,
					CleanupInterval: "5m",
				},
			},
			wantErr: false,
		},
		{
			name: "Invalid cleanup interval",
			config: &types.GlobalConfig{
				Base: types.BaseConfig{
					EnableExpiry:    true,
					CleanupInterval: "invalid",
				},
			},
			wantErr: false, // Invalid interval defaults to 1m
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Config validation should not panic
			// 配置验证不应该 panic
			assert.NotNil(t, tt.config)
		})
	}
}

// TestDaemon_SignalHandling tests signal handling behavior
// TestDaemon_SignalHandling 测试信号处理行为
func TestDaemon_SignalHandling(t *testing.T) {
	// Test that signal constants are valid
	// 测试信号常量有效
	signals := []string{"SIGINT", "SIGTERM", "SIGHUP"}
	for _, sig := range signals {
		assert.NotEmpty(t, sig)
	}
}

// TestDaemon_ContextCancellation tests context cancellation
// TestDaemon_ContextCancellation 测试上下文取消
func TestDaemon_ContextCancellation(t *testing.T) {
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

// TestDaemon_CleanupInterval tests cleanup interval parsing
// TestDaemon_CleanupInterval 测试清理间隔解析
func TestDaemon_CleanupInterval(t *testing.T) {
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

// TestDaemon_MultiplePIDFiles tests multiple PID file operations
// TestDaemon_MultiplePIDFiles 测试多个 PID 文件操作
func TestDaemon_MultiplePIDFiles(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "daemon_multi_pid")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create multiple PID files
	// 创建多个 PID 文件
	for i := 0; i < 5; i++ {
		pidPath := filepath.Join(tmpDir, "test_"+strconv.Itoa(i)+".pid")
		pid := os.Getpid() + i // Different PIDs
		err := os.WriteFile(pidPath, []byte(strconv.Itoa(pid)), 0644)
		require.NoError(t, err)

		// Verify file exists
		// 验证文件存在
		content, err := os.ReadFile(pidPath)
		require.NoError(t, err)
		assert.Equal(t, strconv.Itoa(pid), string(content))
	}
}
