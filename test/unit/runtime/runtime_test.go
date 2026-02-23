package runtime_test

import (
	"testing"

	"github.com/netxfw/netxfw/internal/runtime"
)

// Test constants for runtime modes.
// 运行时模式的测试常量。
const (
	testModeAgent = "agent"
	testModeDP    = "dp"
)

// TestMode tests the Mode variable
// TestMode 测试 Mode 变量
func TestMode(t *testing.T) {
	// Save original value
	// 保存原始值
	originalMode := runtime.Mode
	defer func() {
		runtime.Mode = originalMode
	}()

	// Test default value
	// 测试默认值
	if runtime.Mode != "" && runtime.Mode != testModeDP && runtime.Mode != testModeAgent {
		t.Logf("Mode is: %s", runtime.Mode)
	}

	// Test setting mode
	// 测试设置模式
	runtime.Mode = testModeAgent
	if runtime.Mode != testModeAgent {
		t.Errorf("Mode should be '%s', got %s", testModeAgent, runtime.Mode)
	}

	// Test different mode
	// 测试不同模式
	runtime.Mode = testModeDP
	if runtime.Mode != testModeDP {
		t.Errorf("Mode should be '%s', got %s", testModeDP, runtime.Mode)
	}
}

// TestConfigPath tests the ConfigPath variable
// TestConfigPath 测试 ConfigPath 变量
func TestConfigPath(t *testing.T) {
	// Save original value
	// 保存原始值
	originalPath := runtime.ConfigPath
	defer func() {
		runtime.ConfigPath = originalPath
	}()

	// Test setting config path
	// 测试设置配置路径
	testPath := "/tmp/test_config.yaml"
	runtime.ConfigPath = testPath
	if runtime.ConfigPath != testPath {
		t.Errorf("ConfigPath should be %s, got %s", testPath, runtime.ConfigPath)
	}
}

// TestRuntimeVariables tests that runtime variables can be modified
// TestRuntimeVariables 测试运行时变量可以被修改
func TestRuntimeVariables(t *testing.T) {
	// Save original values
	// 保存原始值
	originalMode := runtime.Mode
	originalPath := runtime.ConfigPath
	defer func() {
		runtime.Mode = originalMode
		runtime.ConfigPath = originalPath
	}()

	// Set new values
	// 设置新值
	runtime.Mode = "test"
	runtime.ConfigPath = "/test/path"

	// Verify
	// 验证
	if runtime.Mode != "test" {
		t.Errorf("Mode should be 'test', got %s", runtime.Mode)
	}
	if runtime.ConfigPath != "/test/path" {
		t.Errorf("ConfigPath should be '/test/path', got %s", runtime.ConfigPath)
	}
}
