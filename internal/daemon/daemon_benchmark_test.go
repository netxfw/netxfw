package daemon

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/netxfw/netxfw/internal/xdp"
)

// BenchmarkManagePidFile benchmarks managePidFile operation
// BenchmarkManagePidFile 基准测试 managePidFile 操作
func BenchmarkManagePidFile(b *testing.B) {
	tmpDir := b.TempDir()
	pidFile := filepath.Join(tmpDir, "benchmark.pid")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		_ = os.Remove(pidFile)
		b.StartTimer()
		_ = managePidFile(pidFile)
	}
}

// BenchmarkRemovePidFile benchmarks removePidFile operation
// BenchmarkRemovePidFile 基准测试 removePidFile 操作
func BenchmarkRemovePidFile(b *testing.B) {
	tmpDir := b.TempDir()
	pidFile := filepath.Join(tmpDir, "benchmark.pid")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		_ = managePidFile(pidFile)
		b.StartTimer()
		removePidFile(pidFile)
	}
}

// BenchmarkRun_DataPlane benchmarks Run in data plane mode
// BenchmarkRun_DataPlane 基准测试 Run 在数据平面模式
func BenchmarkRun_DataPlane(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		ctx, cancel := context.WithCancel(context.Background())
		b.StartTimer()

		go func() {
			time.Sleep(10 * time.Millisecond)
			cancel()
		}()

		Run(ctx, "dp", nil)
	}
}

// BenchmarkRun_Agent benchmarks Run in agent mode
// BenchmarkRun_Agent 基准测试 Run 在代理模式
func BenchmarkRun_Agent(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		ctx, cancel := context.WithCancel(context.Background())
		opts := &DaemonOptions{
			Manager: xdp.NewMockManager(),
		}
		b.StartTimer()

		go func() {
			time.Sleep(10 * time.Millisecond)
			cancel()
		}()

		Run(ctx, "agent", opts)
	}
}

// BenchmarkRun_Unified benchmarks Run in unified mode
// BenchmarkRun_Unified 基准测试 Run 在统一模式
func BenchmarkRun_Unified(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		ctx, cancel := context.WithCancel(context.Background())
		b.StartTimer()

		go func() {
			time.Sleep(10 * time.Millisecond)
			cancel()
		}()

		Run(ctx, "", nil)
	}
}

// BenchmarkCleanupLoop benchmarks cleanup loop
// BenchmarkCleanupLoop 基准测试清理循环
func BenchmarkCleanupLoop(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		ctx, cancel := context.WithCancel(context.Background())
		globalCfg := &types.GlobalConfig{
			Base: types.BaseConfig{
				EnableExpiry:    true,
				CleanupInterval: "10ms",
			},
		}
		b.StartTimer()

		go func() {
			time.Sleep(50 * time.Millisecond)
			cancel()
		}()

		runCleanupLoop(ctx, globalCfg)
	}
}

// BenchmarkDaemonOptions_Creation benchmarks DaemonOptions creation
// BenchmarkDaemonOptions_Creation 基准测试 DaemonOptions 创建
func BenchmarkDaemonOptions_Creation(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = &DaemonOptions{}
	}
}

// BenchmarkDaemonOptions_WithManager benchmarks DaemonOptions with manager
// BenchmarkDaemonOptions_WithManager 基准测试带有管理器的 DaemonOptions
func BenchmarkDaemonOptions_WithManager(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = &DaemonOptions{
			Manager: xdp.NewMockManager(),
		}
	}
}

// BenchmarkPidFile_Operations benchmarks combined PID file operations
// BenchmarkPidFile_Operations 基准测试组合的 PID 文件操作
func BenchmarkPidFile_Operations(b *testing.B) {
	tmpDir := b.TempDir()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pidFile := filepath.Join(tmpDir, "pid"+string(rune(i%10))+".pid")
		_ = managePidFile(pidFile)
		removePidFile(pidFile)
	}
}

// BenchmarkConcurrent_PidFileOperations benchmarks concurrent PID file operations
// BenchmarkConcurrent_PidFileOperations 基准测试并发 PID 文件操作
func BenchmarkConcurrent_PidFileOperations(b *testing.B) {
	tmpDir := b.TempDir()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			pidFile := filepath.Join(tmpDir, "pid"+string(rune(i%10))+".pid")
			_ = managePidFile(pidFile)
			removePidFile(pidFile)
			i++
		}
	})
}

// BenchmarkContext_Cancellation benchmarks context cancellation overhead
// BenchmarkContext_Cancellation 基准测试上下文取消开销
func BenchmarkContext_Cancellation(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_ = ctx
	}
}

// BenchmarkContext_Timeout benchmarks context with timeout
// BenchmarkContext_Timeout 基准测试带有超时的上下文
func BenchmarkContext_Timeout(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		cancel()
		_ = ctx
	}
}
