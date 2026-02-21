package logger

import (
	"context"
	"testing"
)

// TestInit tests logger initialization
// TestInit 测试日志初始化
func TestInit(t *testing.T) {
	// Test with disabled logging
	// 测试禁用日志
	cfg := LoggingConfig{
		Enabled: false,
		Level:   "info",
	}

	Init(cfg)

	// Get logger should work
	// 获取 logger 应该工作
	log := Get(nil)
	if log == nil {
		t.Error("Get should not return nil")
	}

	// Sync may return error on stdout, which is expected
	// Sync 在 stdout 上可能返回错误，这是预期的
	_ = Sync()
}

// TestGet tests getting logger from context
// TestGet 测试从 context 获取 logger
func TestGet(t *testing.T) {
	// Test with nil context
	// 测试 nil context
	log := Get(nil)
	if log == nil {
		t.Error("Get(nil) should not return nil")
	}

	// Test with empty context
	// 测试空 context
	ctx := context.Background()
	log = Get(ctx)
	if log == nil {
		t.Error("Get(context) should not return nil")
	}
}

// TestWithContext tests adding logger to context
// TestWithContext 测试将 logger 添加到 context
func TestWithContext(t *testing.T) {
	// Initialize logger first
	// 先初始化 logger
	cfg := LoggingConfig{
		Enabled: false,
		Level:   "info",
	}
	Init(cfg)

	// Get the global logger
	// 获取全局 logger
	log := Get(nil)

	// Add to context
	// 添加到 context
	ctx := WithContext(context.Background(), log)

	// Retrieve from context
	// 从 context 获取
	retrievedLog := Get(ctx)
	if retrievedLog == nil {
		t.Error("Get should not return nil after WithContext")
	}
}
