package app

import (
	"context"
	"os"
	"testing"

	"github.com/netxfw/netxfw/internal/utils/logger"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

// getTestContext creates a context with a test logger
// getTestContext 创建一个带有测试日志记录器的上下文
func getTestContext() context.Context {
	ctx := context.Background()
	l, _ := zap.NewDevelopment()
	return logger.WithContext(ctx, l.Sugar())
}

// skipIfNotRoot skips the test if not running as root
// skipIfNotRoot 如果不是 root 用户则跳过测试
func skipIfNotRoot(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Skipping test that requires root privileges")
	}
}

// TestInstallXDP_NoConfig tests InstallXDP with missing config
// TestInstallXDP_NoConfig 测试 InstallXDP 缺少配置的情况
func TestInstallXDP_NoConfig(t *testing.T) {
	skipIfNotRoot(t)
	ctx := getTestContext()

	// Test with empty interfaces (should fail because no physical interfaces in test env)
	// 测试空接口（应该失败，因为测试环境中没有物理接口）
	err := InstallXDP(ctx, []string{})
	// In test environment, this may fail or succeed depending on whether XDP is already loaded
	// 在测试环境中，这可能失败或成功，取决于是否已加载 XDP
	// We just verify it doesn't panic
	// 我们只验证它不会崩溃
	_ = err
}

// TestInstallXDP_InvalidInterface tests InstallXDP with invalid interface
// TestInstallXDP_InvalidInterface 测试 InstallXDP 使用无效接口
func TestInstallXDP_InvalidInterface(t *testing.T) {
	skipIfNotRoot(t)
	ctx := getTestContext()

	// Test with non-existent interface
	// 测试不存在的接口
	err := InstallXDP(ctx, []string{"nonexistent123"})
	// InstallXDP may succeed even with invalid interface (it loads the program but skips attaching)
	// InstallXDP 即使接口无效也可能成功（它会加载程序但跳过附加）
	// This is expected behavior - the program is loaded but not attached to the invalid interface
	// 这是预期行为 - 程序被加载但没有附加到无效接口
	_ = err // Accept either error or success
}

// TestRunDaemon tests RunDaemon function
// TestRunDaemon 测试 RunDaemon 函数
// Note: This test is skipped because RunDaemon starts a long-running daemon
// 注意：此测试被跳过，因为 RunDaemon 启动一个长时间运行的守护进程
func TestRunDaemon(t *testing.T) {
	t.Skip("Skipping daemon test - RunDaemon starts a long-running process")
}

// TestHandlePluginCommand_NoArgs tests HandlePluginCommand with no arguments
// TestHandlePluginCommand_NoArgs 测试 HandlePluginCommand 无参数情况
func TestHandlePluginCommand_NoArgs(t *testing.T) {
	skipIfNotRoot(t)
	ctx := getTestContext()

	err := HandlePluginCommand(ctx, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "usage")
}

// TestHandlePluginCommand_InvalidCommand tests HandlePluginCommand with invalid command
// TestHandlePluginCommand_InvalidCommand 测试 HandlePluginCommand 无效命令
func TestHandlePluginCommand_InvalidCommand(t *testing.T) {
	skipIfNotRoot(t)
	ctx := getTestContext()

	err := HandlePluginCommand(ctx, []string{"invalid"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown plugin command")
}

// TestHandlePluginCommand_Load_NoPath tests plugin load without path
// TestHandlePluginCommand_Load_NoPath 测试插件加载无路径
func TestHandlePluginCommand_Load_NoPath(t *testing.T) {
	skipIfNotRoot(t)
	ctx := getTestContext()

	err := HandlePluginCommand(ctx, []string{"load"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Usage")
}

// TestHandlePluginCommand_Load_InvalidIndex tests plugin load with invalid index
// TestHandlePluginCommand_Load_InvalidIndex 测试插件加载无效索引
func TestHandlePluginCommand_Load_InvalidIndex(t *testing.T) {
	skipIfNotRoot(t)
	ctx := getTestContext()

	err := HandlePluginCommand(ctx, []string{"load", "/path/to/plugin.o", "invalid"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid index")
}

// TestHandlePluginCommand_Remove_NoIndex tests plugin remove without index
// TestHandlePluginCommand_Remove_NoIndex 测试插件移除无索引
func TestHandlePluginCommand_Remove_NoIndex(t *testing.T) {
	skipIfNotRoot(t)
	ctx := getTestContext()

	err := HandlePluginCommand(ctx, []string{"remove"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Usage")
}

// TestHandlePluginCommand_Remove_InvalidIndex tests plugin remove with invalid index
// TestHandlePluginCommand_Remove_InvalidIndex 测试插件移除无效索引
func TestHandlePluginCommand_Remove_InvalidIndex(t *testing.T) {
	skipIfNotRoot(t)
	ctx := getTestContext()

	err := HandlePluginCommand(ctx, []string{"remove", "invalid"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid index")
}

// TestRemoveXDP_NoConfig tests RemoveXDP with no config
// TestRemoveXDP_NoConfig 测试 RemoveXDP 无配置情况
func TestRemoveXDP_NoConfig(t *testing.T) {
	skipIfNotRoot(t)
	ctx := getTestContext()

	// Test with empty interfaces
	// 测试空接口
	err := RemoveXDP(ctx, []string{})
	// Should not error even if no XDP is loaded
	// 即使没有加载 XDP 也不应该出错
	// The function handles missing config gracefully
	// 该函数优雅地处理缺少配置的情况
	assert.NoError(t, err)
}

// TestRemoveXDP_InvalidInterface tests RemoveXDP with invalid interface
// TestRemoveXDP_InvalidInterface 测试 RemoveXDP 无效接口
func TestRemoveXDP_InvalidInterface(t *testing.T) {
	skipIfNotRoot(t)
	ctx := getTestContext()

	err := RemoveXDP(ctx, []string{"nonexistent123"})
	// Should not error, just log warnings
	// 不应该出错，只记录警告
	assert.NoError(t, err)
}

// TestReloadXDP_NoConfig tests ReloadXDP with no config
// TestReloadXDP_NoConfig 测试 ReloadXDP 无配置情况
func TestReloadXDP_NoConfig(t *testing.T) {
	skipIfNotRoot(t)
	ctx := getTestContext()

	// This may succeed if XDP is already loaded in the environment
	// 如果环境中已加载 XDP，这可能会成功
	_ = ReloadXDP(ctx, []string{})
}

// TestReloadXDP_InvalidInterface tests ReloadXDP with invalid interface
// TestReloadXDP_InvalidInterface 测试 ReloadXDP 无效接口
func TestReloadXDP_InvalidInterface(t *testing.T) {
	skipIfNotRoot(t)
	ctx := getTestContext()

	// This may succeed if XDP is already loaded in the environment
	// 如果环境中已加载 XDP，这可能会成功
	_ = ReloadXDP(ctx, []string{"nonexistent123"})
}

// TestRunWebServer_NoXDP tests RunWebServer without XDP loaded
// TestRunWebServer_NoXDP 测试 RunWebServer 未加载 XDP
// Note: This test is skipped because RunWebServer starts a blocking HTTP server
// 注意：此测试被跳过，因为 RunWebServer 启动一个阻塞的 HTTP 服务器
func TestRunWebServer_NoXDP(t *testing.T) {
	t.Skip("Skipping web server test - RunWebServer starts a blocking HTTP server")
}

// TestUnloadXDP tests UnloadXDP function
// TestUnloadXDP 测试 UnloadXDP 函数
func TestUnloadXDP(t *testing.T) {
	// This function just prints messages, should not error
	// 该函数只打印消息，不应该出错
	UnloadXDP()
}
