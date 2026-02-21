package version

import (
	"testing"
)

// TestVersion tests that version is set
// TestVersion 测试版本已设置
func TestVersion(t *testing.T) {
	// Version should have a default value
	// Version 应该有一个默认值
	if Version == "" {
		t.Error("Version should not be empty")
	}

	// Default version should be "dev"
	// 默认版本应该是 "dev"
	if Version != "dev" {
		t.Logf("Version is: %s (expected 'dev' for development)", Version)
	}
}

// TestVersionNotEmpty tests that version is not empty
// TestVersionNotEmpty 测试版本不为空
func TestVersionNotEmpty(t *testing.T) {
	if Version == "" {
		t.Error("Version should not be empty")
	}
}
