package runtime

import (
	"testing"
)

// Test constants for runtime modes.
// 运行时模式的测试常量。
const (
	modeAgent = "agent"
	modeDP    = "dp"
)

// TestMode tests the Mode variable
// TestMode 测试 Mode 变量
func TestMode(t *testing.T) {
	// Save original value
	// 保存原始值
	originalMode := Mode
	defer func() {
		Mode = originalMode
	}()

	// Test default value
	// 测试默认值
	if Mode != "" && Mode != modeDP && Mode != modeAgent {
		t.Logf("Mode is: %s", Mode)
	}

	// Test setting mode
	// 测试设置模式
	Mode = modeAgent
	if Mode != modeAgent {
		t.Errorf("Mode should be '%s', got %s", modeAgent, Mode)
	}

	// Test different mode
	// 测试不同模式
	Mode = modeDP
	if Mode != modeDP {
		t.Errorf("Mode should be '%s', got %s", modeDP, Mode)
	}
}

// TestConfigPath tests the ConfigPath variable
// TestConfigPath 测试 ConfigPath 变量
func TestConfigPath(t *testing.T) {
	// Save original value
	// 保存原始值
	originalPath := ConfigPath
	defer func() {
		ConfigPath = originalPath
	}()

	// Test setting config path
	// 测试设置配置路径
	testPath := "/tmp/test_config.yaml"
	ConfigPath = testPath
	if ConfigPath != testPath {
		t.Errorf("ConfigPath should be %s, got %s", testPath, ConfigPath)
	}
}

// TestRuntimeVariables tests that runtime variables can be modified
// TestRuntimeVariables 测试运行时变量可以被修改
func TestRuntimeVariables(t *testing.T) {
	// Save original values
	// 保存原始值
	originalMode := Mode
	originalPath := ConfigPath
	defer func() {
		Mode = originalMode
		ConfigPath = originalPath
	}()

	// Set new values
	// 设置新值
	Mode = "test"
	ConfigPath = "/test/path"

	// Verify
	// 验证
	if Mode != "test" {
		t.Errorf("Mode should be 'test', got %s", Mode)
	}
	if ConfigPath != "/test/path" {
		t.Errorf("ConfigPath should be '/test/path', got %s", ConfigPath)
	}
}
