package core

import (
	"bufio"
	"context"
	"strings"
	"testing"

	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/netxfw/netxfw/internal/xdp"
)

// BenchmarkSyncLockMap benchmarks SyncLockMap operation
// BenchmarkSyncLockMap 基准测试 SyncLockMap 操作
func BenchmarkSyncLockMap(b *testing.B) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = SyncLockMap(ctx, mockMgr, "192.168.1.1/32", true, true)
	}
}

// BenchmarkSyncLockMap_Unlock benchmarks unlock operation
// BenchmarkSyncLockMap_Unlock 基准测试解锁操作
func BenchmarkSyncLockMap_Unlock(b *testing.B) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		mockMgr.AddBlacklistIP("192.168.1.1/32")
		b.StartTimer()
		_ = SyncLockMap(ctx, mockMgr, "192.168.1.1/32", false, true)
	}
}

// BenchmarkSyncWhitelistMap benchmarks SyncWhitelistMap operation
// BenchmarkSyncWhitelistMap 基准测试 SyncWhitelistMap 操作
func BenchmarkSyncWhitelistMap(b *testing.B) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = SyncWhitelistMap(ctx, mockMgr, "10.0.0.1/32", 0, true, true)
	}
}

// BenchmarkSyncWhitelistMap_WithPort benchmarks whitelist with port
// BenchmarkSyncWhitelistMap_WithPort 基准测试带端口白名单
func BenchmarkSyncWhitelistMap_WithPort(b *testing.B) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = SyncWhitelistMap(ctx, mockMgr, "10.0.0.1/32", 443, true, true)
	}
}

// BenchmarkSyncDefaultDeny benchmarks SyncDefaultDeny
// BenchmarkSyncDefaultDeny 基准测试 SyncDefaultDeny
func BenchmarkSyncDefaultDeny(b *testing.B) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = SyncDefaultDeny(ctx, mockMgr, true)
	}
}

// BenchmarkSyncEnableAFXDP benchmarks SyncEnableAFXDP
// BenchmarkSyncEnableAFXDP 基准测试 SyncEnableAFXDP
func BenchmarkSyncEnableAFXDP(b *testing.B) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = SyncEnableAFXDP(ctx, mockMgr, true)
	}
}

// BenchmarkSyncEnableRateLimit benchmarks SyncEnableRateLimit
// BenchmarkSyncEnableRateLimit 基准测试 SyncEnableRateLimit
func BenchmarkSyncEnableRateLimit(b *testing.B) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = SyncEnableRateLimit(ctx, mockMgr, true)
	}
}

// BenchmarkSyncDropFragments benchmarks SyncDropFragments
// BenchmarkSyncDropFragments 基准测试 SyncDropFragments
func BenchmarkSyncDropFragments(b *testing.B) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = SyncDropFragments(ctx, mockMgr, true)
	}
}

// BenchmarkSyncStrictTCP benchmarks SyncStrictTCP
// BenchmarkSyncStrictTCP 基准测试 SyncStrictTCP
func BenchmarkSyncStrictTCP(b *testing.B) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = SyncStrictTCP(ctx, mockMgr, true)
	}
}

// BenchmarkSyncSYNLimit benchmarks SyncSYNLimit
// BenchmarkSyncSYNLimit 基准测试 SyncSYNLimit
func BenchmarkSyncSYNLimit(b *testing.B) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = SyncSYNLimit(ctx, mockMgr, true)
	}
}

// BenchmarkSyncBogonFilter benchmarks SyncBogonFilter
// BenchmarkSyncBogonFilter 基准测试 SyncBogonFilter
func BenchmarkSyncBogonFilter(b *testing.B) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = SyncBogonFilter(ctx, mockMgr, true)
	}
}

// BenchmarkSyncIPPortRule benchmarks SyncIPPortRule
// BenchmarkSyncIPPortRule 基准测试 SyncIPPortRule
func BenchmarkSyncIPPortRule(b *testing.B) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = SyncIPPortRule(ctx, mockMgr, "192.168.1.1", 80, 1, true)
	}
}

// BenchmarkSyncAllowedPort benchmarks SyncAllowedPort
// BenchmarkSyncAllowedPort 基准测试 SyncAllowedPort
func BenchmarkSyncAllowedPort(b *testing.B) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = SyncAllowedPort(ctx, mockMgr, 443, true)
	}
}

// BenchmarkSyncRateLimitRule benchmarks SyncRateLimitRule
// BenchmarkSyncRateLimitRule 基准测试 SyncRateLimitRule
func BenchmarkSyncRateLimitRule(b *testing.B) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = SyncRateLimitRule(ctx, mockMgr, "192.168.1.0/24", 1000, 100, true)
	}
}

// BenchmarkSyncAutoBlock benchmarks SyncAutoBlock
// BenchmarkSyncAutoBlock 基准测试 SyncAutoBlock
func BenchmarkSyncAutoBlock(b *testing.B) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = SyncAutoBlock(ctx, mockMgr, true)
	}
}

// BenchmarkClearBlacklist benchmarks ClearBlacklist
// BenchmarkClearBlacklist 基准测试 ClearBlacklist
func BenchmarkClearBlacklist(b *testing.B) {
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		mockMgr := xdp.NewMockManager()
		for j := 0; j < 100; j++ {
			mockMgr.AddBlacklistIP("192.168.1.1/32")
		}
		b.StartTimer()
		_ = ClearBlacklist(ctx, mockMgr)
	}
}

// BenchmarkShowLockList benchmarks ShowLockList
// BenchmarkShowLockList 基准测试 ShowLockList
func BenchmarkShowLockList(b *testing.B) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	for i := 0; i < 100; i++ {
		mockMgr.AddBlacklistIP("192.168.1.1/32")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ShowLockList(ctx, mockMgr, 100, "")
	}
}

// BenchmarkShowLockList_WithSearch benchmarks ShowLockList with search
// BenchmarkShowLockList_WithSearch 基准测试带搜索的 ShowLockList
func BenchmarkShowLockList_WithSearch(b *testing.B) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	for i := 0; i < 100; i++ {
		mockMgr.AddBlacklistIP("192.168.1.1/32")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ShowLockList(ctx, mockMgr, 100, "192.168")
	}
}

// BenchmarkAskConfirmation benchmarks AskConfirmation
// BenchmarkAskConfirmation 基准测试 AskConfirmation
func BenchmarkAskConfirmation(b *testing.B) {
	SetConfirmationReader(bufio.NewReader(strings.NewReader("y\n")))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = AskConfirmation("Test prompt")
	}
}

// BenchmarkSyncBoolSettingWithConfig benchmarks the internal helper
// BenchmarkSyncBoolSettingWithConfig 基准测试内部辅助函数
func BenchmarkSyncBoolSettingWithConfig(b *testing.B) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = syncBoolSettingWithConfig(ctx, mockMgr, true,
			mockMgr.SetDefaultDeny,
			func(cfg *types.GlobalConfig, v bool) { cfg.Base.DefaultDeny = v },
			"test", "Test: %v")
	}
}

// BenchmarkParallel_SyncLockMap benchmarks parallel lock operations
// BenchmarkParallel_SyncLockMap 基准测试并行锁定操作
func BenchmarkParallel_SyncLockMap(b *testing.B) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			ip := "192.168.1.1/32"
			if i%2 == 0 {
				_ = SyncLockMap(ctx, mockMgr, ip, true, true)
			} else {
				_ = SyncLockMap(ctx, mockMgr, ip, false, true)
			}
			i++
		}
	})
}

// BenchmarkParallel_SyncWhitelistMap benchmarks parallel whitelist operations
// BenchmarkParallel_SyncWhitelistMap 基准测试并行白名单操作
func BenchmarkParallel_SyncWhitelistMap(b *testing.B) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			ip := "10.0.0.1/32"
			if i%2 == 0 {
				_ = SyncWhitelistMap(ctx, mockMgr, ip, 0, true, true)
			} else {
				_ = SyncWhitelistMap(ctx, mockMgr, ip, 0, false, true)
			}
			i++
		}
	})
}

// BenchmarkParallel_SyncIPPortRule benchmarks parallel IP+Port rule operations
// BenchmarkParallel_SyncIPPortRule 基准测试并行 IP+端口规则操作
func BenchmarkParallel_SyncIPPortRule(b *testing.B) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			port := uint16(80 + i%10)
			_ = SyncIPPortRule(ctx, mockMgr, "192.168.1.1", port, 1, true)
			i++
		}
	})
}

// BenchmarkParallel_SyncAllowedPort benchmarks parallel port operations
// BenchmarkParallel_SyncAllowedPort 基准测试并行端口操作
func BenchmarkParallel_SyncAllowedPort(b *testing.B) {
	mockMgr := xdp.NewMockManager()
	ctx := context.Background()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			port := uint16(80 + i%10)
			if i%2 == 0 {
				_ = SyncAllowedPort(ctx, mockMgr, port, true)
			} else {
				_ = SyncAllowedPort(ctx, mockMgr, port, false)
			}
			i++
		}
	})
}
