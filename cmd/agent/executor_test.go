package agent

import (
	"bytes"
	"testing"

	"github.com/netxfw/netxfw/internal/runtime"
	"github.com/netxfw/netxfw/internal/xdp"
	"github.com/netxfw/netxfw/pkg/sdk"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestExecutorXDPCheck(t *testing.T) {
	// Save original mode, restore after test
	// 保存原始模式，测试后恢复
	originalMode := runtime.Mode
	defer func() {
		runtime.Mode = originalMode
	}()

	// Simulate production mode
	// 模拟生产模式
	runtime.Mode = "prod"

	// Create a buffer to capture output
	// 创建缓冲区捕获输出
	buf := new(bytes.Buffer)
	cmd := &cobra.Command{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	executor := NewCommandExecutor(cmd)

	// Define a function that should not be executed if XDP check fails
	// 定义一个如果不通过 XDP 检查就不应该执行的函数
	executed := false
	execFunc := func(s *sdk.SDK) error {
		executed = true
		return nil
	}

	// Execute ExecuteWithSDK
	// Since XDP is not attached, this should fail and print warning
	// 执行 ExecuteWithSDK，由于未挂载 XDP，应失败并打印警告
	executor.ExecuteWithSDK(execFunc)

	// Verify results
	// 验证结果
	output := buf.String()
	assert.False(t, executed, "Business logic should not be executed when XDP is not attached")
	assert.Contains(t, output, "XDP is not attached to any interface", "Should print warning about XDP not attached")
}

func TestExecutorXDPCheckWithManager(t *testing.T) {
	// Save original mode, restore after test
	// 保存原始模式，测试后恢复
	originalMode := runtime.Mode
	defer func() {
		runtime.Mode = originalMode
	}()

	// Simulate production mode
	// 模拟生产模式
	runtime.Mode = "prod"

	// Create a buffer to capture output
	// 创建缓冲区捕获输出
	buf := new(bytes.Buffer)
	cmd := &cobra.Command{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	executor := NewCommandExecutor(cmd)

	// Define a function that should not be executed if XDP check fails
	// 定义一个如果不通过 XDP 检查就不应该执行的函数
	executed := false
	execFunc := func(mgr *xdp.Manager) error {
		executed = true
		return nil
	}

	// Execute ExecuteWithManager
	// Since XDP is not attached, this should fail and print warning
	// 执行 ExecuteWithManager，由于未挂载 XDP，应失败并打印警告
	executor.ExecuteWithManager(execFunc)

	// Verify results
	// 验证结果
	output := buf.String()
	assert.False(t, executed, "Business logic should not be executed when XDP is not attached")
	assert.Contains(t, output, "XDP is not attached to any interface", "Should print warning about XDP not attached")
}
