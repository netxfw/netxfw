package runtime

import (
	"testing"
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
	if Mode != "" && Mode != "dp" && Mode != "agent" {
		t.Logf("Mode is: %s", Mode)
	}

	// Test setting mode
	// 测试设置模式
	Mode = "agent"
	if Mode != "agent" {
		t.Errorf("Mode should be 'agent', got %s", Mode)
	}

	// Test different mode
	// 测试不同模式
	Mode = "dp"
	if Mode != "dp" {
		t.Errorf("Mode should be 'dp', got %s", Mode)
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
