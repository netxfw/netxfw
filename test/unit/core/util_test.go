package core_test

import (
	"bufio"
	"strings"
	"testing"

	"github.com/livp123/netxfw/internal/core"
)

// TestAskConfirmation tests the confirmation prompt
// TestAskConfirmation 测试确认提示
func TestAskConfirmation(t *testing.T) {
	// Test with "y" response
	// 测试 "y" 响应
	core.SetConfirmationReader(bufio.NewReader(strings.NewReader("y\n")))
	if !core.AskConfirmation("Test prompt") {
		t.Error("AskConfirmation should return true for 'y'")
	}

	// Test with "yes" response
	// 测试 "yes" 响应
	core.SetConfirmationReader(bufio.NewReader(strings.NewReader("yes\n")))
	if !core.AskConfirmation("Test prompt") {
		t.Error("AskConfirmation should return true for 'yes'")
	}

	// Test with "n" response
	// 测试 "n" 响应
	core.SetConfirmationReader(bufio.NewReader(strings.NewReader("n\n")))
	if core.AskConfirmation("Test prompt") {
		t.Error("AskConfirmation should return false for 'n'")
	}

	// Test with "N" response
	// 测试 "N" 响应
	core.SetConfirmationReader(bufio.NewReader(strings.NewReader("N\n")))
	if core.AskConfirmation("Test prompt") {
		t.Error("AskConfirmation should return false for 'N'")
	}

	// Test with empty response
	// 测试空响应
	core.SetConfirmationReader(bufio.NewReader(strings.NewReader("\n")))
	if core.AskConfirmation("Test prompt") {
		t.Error("AskConfirmation should return false for empty response")
	}

	// Test with random response
	// 测试随机响应
	core.SetConfirmationReader(bufio.NewReader(strings.NewReader("random\n")))
	if core.AskConfirmation("Test prompt") {
		t.Error("AskConfirmation should return false for random response")
	}
}

// TestSetConfirmationReader tests setting the confirmation reader
// TestSetConfirmationReader 测试设置确认读取器
func TestSetConfirmationReader(t *testing.T) {
	// Set a new reader
	// 设置新的读取器
	reader := bufio.NewReader(strings.NewReader("y\n"))
	core.SetConfirmationReader(reader)

	// Verify it works
	// 验证它工作
	if !core.AskConfirmation("Test") {
		t.Error("AskConfirmation should use the set reader")
	}
}
