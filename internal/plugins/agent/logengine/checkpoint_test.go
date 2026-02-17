package logengine

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/livp123/netxfw/pkg/sdk"
	"github.com/nxadm/tail"
	"github.com/stretchr/testify/assert"
)

// MockLogger is a mock implementation of sdk.Logger
// MockLogger 是 sdk.Logger 的模拟实现
type MockLogger struct{}

// Infof implements sdk.Logger
func (m *MockLogger) Infof(format string, args ...interface{})  {}
func (m *MockLogger) Warnf(format string, args ...interface{})  {}
func (m *MockLogger) Errorf(format string, args ...interface{}) {}

// NewMockLogger creates a new MockLogger
// NewMockLogger 创建一个新的 MockLogger
func NewMockLogger() sdk.Logger {
	return &MockLogger{}
}

// TestNewCheckpointManager tests NewCheckpointManager function
// TestNewCheckpointManager 测试 NewCheckpointManager 函数
func TestNewCheckpointManager(t *testing.T) {
	logger := NewMockLogger()
	cm := NewCheckpointManager(logger)

	assert.NotNil(t, cm)
	assert.NotNil(t, cm.offsets)
	assert.Equal(t, CheckpointFile, cm.file)
}

// TestCheckpointManager_UpdateOffset tests UpdateOffset method
// TestCheckpointManager_UpdateOffset 测试 UpdateOffset 方法
func TestCheckpointManager_UpdateOffset(t *testing.T) {
	logger := NewMockLogger()
	cm := NewCheckpointManager(logger)

	cm.UpdateOffset("/var/log/test.log", 12345)

	assert.Equal(t, int64(12345), cm.offsets["/var/log/test.log"])
}

// TestCheckpointManager_GetOffset_Start tests GetOffset with start mode
// TestCheckpointManager_GetOffset_Start 测试 start 模式的 GetOffset
func TestCheckpointManager_GetOffset_Start(t *testing.T) {
	logger := NewMockLogger()
	cm := NewCheckpointManager(logger)

	seekInfo := cm.GetOffset("/var/log/test.log", "start")

	assert.Equal(t, int64(0), seekInfo.Offset)
	assert.Equal(t, 0, seekInfo.Whence)
}

// TestCheckpointManager_GetOffset_End tests GetOffset with end mode
// TestCheckpointManager_GetOffset_End 测试 end 模式的 GetOffset
func TestCheckpointManager_GetOffset_End(t *testing.T) {
	logger := NewMockLogger()
	cm := NewCheckpointManager(logger)

	seekInfo := cm.GetOffset("/var/log/test.log", "end")

	assert.Equal(t, int64(0), seekInfo.Offset)
	assert.Equal(t, 2, seekInfo.Whence)
}

// TestCheckpointManager_GetOffset_Offset tests GetOffset with offset mode
// TestCheckpointManager_GetOffset_Offset 测试 offset 模式的 GetOffset
func TestCheckpointManager_GetOffset_Offset(t *testing.T) {
	logger := NewMockLogger()
	cm := NewCheckpointManager(logger)

	// Create a temp file with content
	// 创建一个临时文件并写入内容
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.log")
	err := os.WriteFile(tmpFile, []byte("test content for offset testing\n"), 0644)
	assert.NoError(t, err)

	// Update offset
	// 更新偏移量
	cm.UpdateOffset(tmpFile, 10)

	seekInfo := cm.GetOffset(tmpFile, "offset")

	assert.Equal(t, int64(10), seekInfo.Offset)
	assert.Equal(t, 0, seekInfo.Whence)
}

// TestCheckpointManager_GetOffset_OffsetWithRotation tests GetOffset with log rotation
// TestCheckpointManager_GetOffset_OffsetWithRotation 测试日志轮转时的 GetOffset
func TestCheckpointManager_GetOffset_OffsetWithRotation(t *testing.T) {
	logger := NewMockLogger()
	cm := NewCheckpointManager(logger)

	// Create a temp file with small content
	// 创建一个内容很小的临时文件
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.log")
	err := os.WriteFile(tmpFile, []byte("small\n"), 0644)
	assert.NoError(t, err)

	// Set offset larger than file size (simulating rotation)
	// 设置比文件大小更大的偏移量（模拟轮转）
	cm.UpdateOffset(tmpFile, 1000)

	seekInfo := cm.GetOffset(tmpFile, "offset")

	// Should reset to start due to rotation
	// 由于轮转应该重置到开头
	assert.Equal(t, int64(0), seekInfo.Offset)
	assert.Equal(t, 0, seekInfo.Whence)
}

// TestCheckpointManager_GetOffset_UnknownMode tests GetOffset with unknown mode
// TestCheckpointManager_GetOffset_UnknownMode 测试未知模式的 GetOffset
func TestCheckpointManager_GetOffset_UnknownMode(t *testing.T) {
	logger := NewMockLogger()
	cm := NewCheckpointManager(logger)

	seekInfo := cm.GetOffset("/var/log/test.log", "unknown")

	// Should default to end
	// 应该默认到末尾
	assert.Equal(t, int64(0), seekInfo.Offset)
	assert.Equal(t, 2, seekInfo.Whence)
}

// TestCheckpointManager_SaveAndLoad tests Save and Load methods
// TestCheckpointManager_SaveAndLoad 测试 Save 和 Load 方法
func TestCheckpointManager_SaveAndLoad(t *testing.T) {
	logger := NewMockLogger()

	// Use temp file
	// 使用临时文件
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "offsets.json")

	cm := NewCheckpointManager(logger)
	cm.file = tmpFile

	// Update offsets
	// 更新偏移量
	cm.UpdateOffset("/var/log/test1.log", 100)
	cm.UpdateOffset("/var/log/test2.log", 200)

	// Save
	// 保存
	cm.Save()

	// Create new manager and load
	// 创建新管理器并加载
	cm2 := NewCheckpointManager(logger)
	cm2.file = tmpFile
	cm2.Load()

	// Verify offsets
	// 验证偏移量
	assert.Equal(t, int64(100), cm2.offsets["/var/log/test1.log"])
	assert.Equal(t, int64(200), cm2.offsets["/var/log/test2.log"])
}

// TestCheckpointManager_Load_NonExistent tests Load with non-existent file
// TestCheckpointManager_Load_NonExistent 测试文件不存在时的 Load
func TestCheckpointManager_Load_NonExistent(t *testing.T) {
	logger := NewMockLogger()
	cm := NewCheckpointManager(logger)
	cm.file = "/non/existent/file.json"

	// Should not error
	// 不应该报错
	cm.Load()

	// Offsets should be empty
	// 偏移量应该为空
	assert.Equal(t, 0, len(cm.offsets))
}

// TestCheckpointManager_StartStop tests Start and Stop methods
// TestCheckpointManager_StartStop 测试 Start 和 Stop 方法
func TestCheckpointManager_StartStop(t *testing.T) {
	logger := NewMockLogger()

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "offsets.json")

	cm := NewCheckpointManager(logger)
	cm.file = tmpFile

	// Start
	// 启动
	cm.Start()
	assert.NotNil(t, cm.ticker)

	// Update offset
	// 更新偏移量
	cm.UpdateOffset("/var/log/test.log", 500)

	// Wait for ticker
	// 等待定时器
	time.Sleep(100 * time.Millisecond)

	// Stop
	// 停止
	cm.Stop()

	// Verify file was saved
	// 验证文件已保存
	_, err := os.Stat(tmpFile)
	assert.NoError(t, err)
}

// TestCheckpointManager_MultipleUpdates tests multiple offset updates
// TestCheckpointManager_MultipleUpdates 测试多次偏移量更新
func TestCheckpointManager_MultipleUpdates(t *testing.T) {
	logger := NewMockLogger()
	cm := NewCheckpointManager(logger)

	files := []string{
		"/var/log/test1.log",
		"/var/log/test2.log",
		"/var/log/test3.log",
	}

	for i, file := range files {
		cm.UpdateOffset(file, int64((i+1)*100))
	}

	for i, file := range files {
		assert.Equal(t, int64((i+1)*100), cm.offsets[file])
	}
}

// TestCheckpointManager_GetOffset_NonExistentFile tests GetOffset with non-existent file
// TestCheckpointManager_GetOffset_NonExistentFile 测试文件不存在时的 GetOffset
func TestCheckpointManager_GetOffset_NonExistentFile(t *testing.T) {
	logger := NewMockLogger()
	cm := NewCheckpointManager(logger)

	// Set offset for non-existent file
	// 为不存在的文件设置偏移量
	cm.UpdateOffset("/non/existent/file.log", 100)

	seekInfo := cm.GetOffset("/non/existent/file.log", "offset")

	// Should default to end since file doesn't exist
	// 由于文件不存在应该默认到末尾
	assert.Equal(t, int64(0), seekInfo.Offset)
	assert.Equal(t, 2, seekInfo.Whence)
}

// TestCheckpointManager_ConcurrentAccess tests concurrent access
// TestCheckpointManager_ConcurrentAccess 测试并发访问
func TestCheckpointManager_ConcurrentAccess(t *testing.T) {
	logger := NewMockLogger()
	cm := NewCheckpointManager(logger)

	done := make(chan bool)

	for i := 0; i < 10; i++ {
		go func(idx int) {
			for j := 0; j < 100; j++ {
				cm.UpdateOffset("/var/log/test.log", int64(idx*100+j))
			}
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	// Just verify no panic occurred
	// 只验证没有崩溃
	assert.NotNil(t, cm.offsets)
}

// TestSeekInfoDefaults tests tail.SeekInfo defaults
// TestSeekInfoDefaults 测试 tail.SeekInfo 默认值
func TestSeekInfoDefaults(t *testing.T) {
	seekInfo := &tail.SeekInfo{Offset: 0, Whence: 0}
	assert.Equal(t, int64(0), seekInfo.Offset)
	assert.Equal(t, 0, seekInfo.Whence)

	seekInfoEnd := &tail.SeekInfo{Offset: 0, Whence: 2}
	assert.Equal(t, 2, seekInfoEnd.Whence)
}
