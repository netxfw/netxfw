package fileutil_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/livp123/netxfw/internal/utils/fileutil"
)

// TestAtomicWriteFile tests atomic file writing
// TestAtomicWriteFile 测试原子文件写入
func TestAtomicWriteFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "fileutil_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	testFile := filepath.Join(tmpDir, "test.txt")
	testData := []byte("hello world")

	// Test write
	// 测试写入
	err = fileutil.AtomicWriteFile(testFile, testData, 0644)
	if err != nil {
		t.Fatalf("AtomicWriteFile failed: %v", err)
	}

	// Verify content
	// 验证内容
	content, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}
	if !bytes.Equal(content, testData) {
		t.Errorf("Content mismatch: got %s, want %s", string(content), string(testData))
	}

	// Test overwrite
	// 测试覆盖写入
	newData := []byte("new content")
	err = fileutil.AtomicWriteFile(testFile, newData, 0644)
	if err != nil {
		t.Fatalf("AtomicWriteFile overwrite failed: %v", err)
	}

	content, err = os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}
	if !bytes.Equal(content, newData) {
		t.Errorf("Content mismatch after overwrite: got %s, want %s", string(content), string(newData))
	}
}

// TestReadLines tests reading lines from a file
// TestReadLines 测试从文件读取行
func TestReadLines(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "fileutil_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	testFile := filepath.Join(tmpDir, "test.txt")

	// Test non-existent file
	// 测试不存在的文件
	lines, err := fileutil.ReadLines(testFile)
	if err != nil {
		t.Errorf("ReadLines on non-existent file should not error: %v", err)
	}
	if lines != nil {
		t.Errorf("ReadLines on non-existent file should return nil, got %v", lines)
	}

	// Test empty path
	// 测试空路径
	lines, err = fileutil.ReadLines("")
	if err != nil {
		t.Errorf("ReadLines with empty path should not error: %v", err)
	}
	if lines != nil {
		t.Errorf("ReadLines with empty path should return nil, got %v", lines)
	}

	// Test with content
	// 测试有内容的情况
	content := "line1\nline2\n\nline3\n"
	err = os.WriteFile(testFile, []byte(content), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	lines, err = fileutil.ReadLines(testFile)
	if err != nil {
		t.Fatalf("ReadLines failed: %v", err)
	}

	expected := []string{"line1", "line2", "line3"}
	if len(lines) != len(expected) {
		t.Errorf("ReadLines returned %d lines, want %d", len(lines), len(expected))
	}
	for i, line := range lines {
		if line != expected[i] {
			t.Errorf("Line %d: got %s, want %s", i, line, expected[i])
		}
	}
}

// TestAppendToFile tests appending to a file
// TestAppendToFile 测试追加到文件
func TestAppendToFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "fileutil_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	testFile := filepath.Join(tmpDir, "test.txt")

	// Test append to new file
	// 测试追加到新文件
	err = fileutil.AppendToFile(testFile, "line1")
	if err != nil {
		t.Fatalf("AppendToFile failed: %v", err)
	}

	lines, err := fileutil.ReadLines(testFile)
	if err != nil {
		t.Fatalf("ReadLines failed: %v", err)
	}
	if len(lines) != 1 || lines[0] != "line1" {
		t.Errorf("Expected ['line1'], got %v", lines)
	}

	// Test append another line
	// 测试追加另一行
	err = fileutil.AppendToFile(testFile, "line2")
	if err != nil {
		t.Fatalf("AppendToFile failed: %v", err)
	}

	lines, err = fileutil.ReadLines(testFile)
	if err != nil {
		t.Fatalf("ReadLines failed: %v", err)
	}
	if len(lines) != 2 {
		t.Errorf("Expected 2 lines, got %d", len(lines))
	}

	// Test append duplicate (should not add)
	// 测试追加重复行（不应该添加）
	err = fileutil.AppendToFile(testFile, "line1")
	if err != nil {
		t.Fatalf("AppendToFile failed: %v", err)
	}

	lines, err = fileutil.ReadLines(testFile)
	if err != nil {
		t.Fatalf("ReadLines failed: %v", err)
	}
	if len(lines) != 2 {
		t.Errorf("Expected 2 lines after duplicate append, got %d", len(lines))
	}

	// Test empty path
	// 测试空路径
	err = fileutil.AppendToFile("", "test")
	if err != nil {
		t.Errorf("AppendToFile with empty path should not error: %v", err)
	}
}

// TestRemoveFromFile tests removing a line from a file
// TestRemoveFromFile 测试从文件中删除行
func TestRemoveFromFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "fileutil_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	testFile := filepath.Join(tmpDir, "test.txt")

	// Create file with content
	// 创建有内容的文件
	content := "line1\nline2\nline3\n"
	err = os.WriteFile(testFile, []byte(content), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Test remove line
	// 测试删除行
	err = fileutil.RemoveFromFile(testFile, "line2")
	if err != nil {
		t.Fatalf("RemoveFromFile failed: %v", err)
	}

	lines, err := fileutil.ReadLines(testFile)
	if err != nil {
		t.Fatalf("ReadLines failed: %v", err)
	}

	expected := []string{"line1", "line3"}
	if len(lines) != len(expected) {
		t.Errorf("Expected %d lines, got %d", len(expected), len(lines))
	}

	// Test empty path
	// 测试空路径
	err = fileutil.RemoveFromFile("", "test")
	if err != nil {
		t.Errorf("RemoveFromFile with empty path should not error: %v", err)
	}
}
