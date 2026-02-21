package xdp

import (
	"fmt"
	"testing"

	"github.com/netxfw/netxfw/internal/plugins/types"
)

// BenchmarkNewMockManager benchmarks NewMockManager function
// BenchmarkNewMockManager 基准测试 NewMockManager 函数
func BenchmarkNewMockManager(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewMockManager()
	}
}

// BenchmarkMockManager_AddBlacklistIP benchmarks AddBlacklistIP operation
// BenchmarkMockManager_AddBlacklistIP 基准测试 AddBlacklistIP 操作
func BenchmarkMockManager_AddBlacklistIP(b *testing.B) {
	mockMgr := NewMockManager()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = mockMgr.AddBlacklistIP(fmt.Sprintf("192.168.%d.%d/32", i/256, i%256))
	}
}

// BenchmarkMockManager_RemoveBlacklistIP benchmarks RemoveBlacklistIP operation
// BenchmarkMockManager_RemoveBlacklistIP 基准测试 RemoveBlacklistIP 操作
func BenchmarkMockManager_RemoveBlacklistIP(b *testing.B) {
	mockMgr := NewMockManager()
	// Pre-populate with fixed number of IPs
	// 预填充固定数量的 IP
	for i := 0; i < 1000; i++ {
		_ = mockMgr.AddBlacklistIP(fmt.Sprintf("192.168.%d.%d/32", i/256, i%256))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = mockMgr.RemoveBlacklistIP(fmt.Sprintf("192.168.%d.%d/32", (i%1000)/256, i%256))
	}
}

// BenchmarkMockManager_IsIPInBlacklist benchmarks IsIPInBlacklist operation
// BenchmarkMockManager_IsIPInBlacklist 基准测试 IsIPInBlacklist 操作
func BenchmarkMockManager_IsIPInBlacklist(b *testing.B) {
	mockMgr := NewMockManager()
	_ = mockMgr.AddBlacklistIP("192.168.1.1/32")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = mockMgr.IsIPInBlacklist("192.168.1.1/32")
	}
}

// BenchmarkMockManager_ListBlacklistIPs benchmarks ListBlacklistIPs operation
// BenchmarkMockManager_ListBlacklistIPs 基准测试 ListBlacklistIPs 操作
func BenchmarkMockManager_ListBlacklistIPs(b *testing.B) {
	mockMgr := NewMockManager()
	// Pre-populate with 1000 IPs
	// 预填充 1000 个 IP
	for i := 0; i < 1000; i++ {
		_ = mockMgr.AddBlacklistIP(fmt.Sprintf("192.168.%d.%d/32", i/256, i%256))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = mockMgr.ListBlacklistIPs(100, "")
	}
}

// BenchmarkMockManager_ListBlacklistIPs_WithSearch benchmarks ListBlacklistIPs with search
// BenchmarkMockManager_ListBlacklistIPs_WithSearch 基准测试 ListBlacklistIPs 使用搜索
func BenchmarkMockManager_ListBlacklistIPs_WithSearch(b *testing.B) {
	mockMgr := NewMockManager()
	// Pre-populate with 1000 IPs
	// 预填充 1000 个 IP
	for i := 0; i < 1000; i++ {
		_ = mockMgr.AddBlacklistIP(fmt.Sprintf("192.168.%d.%d/32", i/256, i%256))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = mockMgr.ListBlacklistIPs(100, "192.168.1")
	}
}

// BenchmarkMockManager_AddWhitelistIP benchmarks AddWhitelistIP operation
// BenchmarkMockManager_AddWhitelistIP 基准测试 AddWhitelistIP 操作
func BenchmarkMockManager_AddWhitelistIP(b *testing.B) {
	mockMgr := NewMockManager()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = mockMgr.AddWhitelistIP(fmt.Sprintf("10.0.%d.%d/32", i/256, i%256), 80)
	}
}

// BenchmarkMockManager_RemoveWhitelistIP benchmarks RemoveWhitelistIP operation
// BenchmarkMockManager_RemoveWhitelistIP 基准测试 RemoveWhitelistIP 操作
func BenchmarkMockManager_RemoveWhitelistIP(b *testing.B) {
	mockMgr := NewMockManager()
	// Pre-populate with fixed number of IPs
	// 预填充固定数量的 IP
	for i := 0; i < 1000; i++ {
		_ = mockMgr.AddWhitelistIP(fmt.Sprintf("10.0.%d.%d/32", i/256, i%256), 80)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = mockMgr.RemoveWhitelistIP(fmt.Sprintf("10.0.%d.%d/32", (i%1000)/256, i%256))
	}
}

// BenchmarkMockManager_IsIPInWhitelist benchmarks IsIPInWhitelist operation
// BenchmarkMockManager_IsIPInWhitelist 基准测试 IsIPInWhitelist 操作
func BenchmarkMockManager_IsIPInWhitelist(b *testing.B) {
	mockMgr := NewMockManager()
	_ = mockMgr.AddWhitelistIP("10.0.0.1/32", 80)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = mockMgr.IsIPInWhitelist("10.0.0.1/32")
	}
}

// BenchmarkMockManager_AddIPPortRule benchmarks AddIPPortRule operation
// BenchmarkMockManager_AddIPPortRule 基准测试 AddIPPortRule 操作
func BenchmarkMockManager_AddIPPortRule(b *testing.B) {
	mockMgr := NewMockManager()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = mockMgr.AddIPPortRule(fmt.Sprintf("172.16.%d.%d/32", i/256, i%256), uint16(i%65536), 1)
	}
}

// BenchmarkMockManager_RemoveIPPortRule benchmarks RemoveIPPortRule operation
// BenchmarkMockManager_RemoveIPPortRule 基准测试 RemoveIPPortRule 操作
func BenchmarkMockManager_RemoveIPPortRule(b *testing.B) {
	mockMgr := NewMockManager()
	// Pre-populate with fixed number of rules
	// 预填充固定数量的规则
	for i := 0; i < 1000; i++ {
		_ = mockMgr.AddIPPortRule(fmt.Sprintf("172.16.%d.%d/32", i/256, i%256), uint16(i%65536), 1)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = mockMgr.RemoveIPPortRule(fmt.Sprintf("172.16.%d.%d/32", (i%1000)/256, i%256), uint16(i%65536))
	}
}

// BenchmarkMockManager_AllowPort benchmarks AllowPort operation
// BenchmarkMockManager_AllowPort 基准测试 AllowPort 操作
func BenchmarkMockManager_AllowPort(b *testing.B) {
	mockMgr := NewMockManager()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = mockMgr.AllowPort(uint16(i % 65536))
	}
}

// BenchmarkMockManager_RemoveAllowedPort benchmarks RemoveAllowedPort operation
// BenchmarkMockManager_RemoveAllowedPort 基准测试 RemoveAllowedPort 操作
func BenchmarkMockManager_RemoveAllowedPort(b *testing.B) {
	mockMgr := NewMockManager()
	// Pre-populate with fixed number of ports
	// 预填充固定数量的端口
	for i := 0; i < 1000; i++ {
		_ = mockMgr.AllowPort(uint16(i % 65536))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = mockMgr.RemoveAllowedPort(uint16(i % 1000))
	}
}

// BenchmarkMockManager_AddRateLimitRule benchmarks AddRateLimitRule operation
// BenchmarkMockManager_AddRateLimitRule 基准测试 AddRateLimitRule 操作
func BenchmarkMockManager_AddRateLimitRule(b *testing.B) {
	mockMgr := NewMockManager()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = mockMgr.AddRateLimitRule(fmt.Sprintf("192.168.%d.0/24", i%256), 1000, 2000)
	}
}

// BenchmarkMockManager_RemoveRateLimitRule benchmarks RemoveRateLimitRule operation
// BenchmarkMockManager_RemoveRateLimitRule 基准测试 RemoveRateLimitRule 操作
func BenchmarkMockManager_RemoveRateLimitRule(b *testing.B) {
	mockMgr := NewMockManager()
	// Pre-populate with fixed number of rules
	// 预填充固定数量的规则
	for i := 0; i < 256; i++ {
		_ = mockMgr.AddRateLimitRule(fmt.Sprintf("192.168.%d.0/24", i), 1000, 2000)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = mockMgr.RemoveRateLimitRule(fmt.Sprintf("192.168.%d.0/24", i%256))
	}
}

// BenchmarkMockManager_GetDropCount benchmarks GetDropCount operation
// BenchmarkMockManager_GetDropCount 基准测试 GetDropCount 操作
func BenchmarkMockManager_GetDropCount(b *testing.B) {
	mockMgr := NewMockManager()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = mockMgr.GetDropCount()
	}
}

// BenchmarkMockManager_GetPassCount benchmarks GetPassCount operation
// BenchmarkMockManager_GetPassCount 基准测试 GetPassCount 操作
func BenchmarkMockManager_GetPassCount(b *testing.B) {
	mockMgr := NewMockManager()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = mockMgr.GetPassCount()
	}
}

// BenchmarkMockManager_GetLockedIPCount benchmarks GetLockedIPCount operation
// BenchmarkMockManager_GetLockedIPCount 基准测试 GetLockedIPCount 操作
func BenchmarkMockManager_GetLockedIPCount(b *testing.B) {
	mockMgr := NewMockManager()
	_ = mockMgr.AddBlacklistIP("192.168.1.1/32")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = mockMgr.GetLockedIPCount()
	}
}

// BenchmarkMockManager_ClearBlacklist benchmarks ClearBlacklist operation
// BenchmarkMockManager_ClearBlacklist 基准测试 ClearBlacklist 操作
func BenchmarkMockManager_ClearBlacklist(b *testing.B) {
	mockMgr := NewMockManager()
	// Pre-populate with 100 IPs once
	// 一次预填充 100 个 IP
	for j := 0; j < 100; j++ {
		_ = mockMgr.AddBlacklistIP(fmt.Sprintf("192.168.%d.%d/32", j/256, j%256))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = mockMgr.ClearBlacklist()
	}
}

// BenchmarkMockManager_ClearWhitelist benchmarks ClearWhitelist operation
// BenchmarkMockManager_ClearWhitelist 基准测试 ClearWhitelist 操作
func BenchmarkMockManager_ClearWhitelist(b *testing.B) {
	mockMgr := NewMockManager()
	// Pre-populate with 100 IPs once
	// 一次预填充 100 个 IP
	for j := 0; j < 100; j++ {
		_ = mockMgr.AddWhitelistIP(fmt.Sprintf("10.0.%d.%d/32", j/256, j%256), 80)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = mockMgr.ClearWhitelist()
	}
}

// BenchmarkMockManager_SetDefaultDeny benchmarks SetDefaultDeny operation
// BenchmarkMockManager_SetDefaultDeny 基准测试 SetDefaultDeny 操作
func BenchmarkMockManager_SetDefaultDeny(b *testing.B) {
	mockMgr := NewMockManager()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = mockMgr.SetDefaultDeny(true)
	}
}

// BenchmarkMockManager_SetConntrack benchmarks SetConntrack operation
// BenchmarkMockManager_SetConntrack 基准测试 SetConntrack 操作
func BenchmarkMockManager_SetConntrack(b *testing.B) {
	mockMgr := NewMockManager()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = mockMgr.SetConntrack(true)
	}
}

// BenchmarkMockManager_Close benchmarks Close operation
// BenchmarkMockManager_Close 基准测试 Close 操作
func BenchmarkMockManager_Close(b *testing.B) {
	for i := 0; i < b.N; i++ {
		mockMgr := NewMockManager()
		_ = mockMgr.Close()
	}
}

// BenchmarkMockManager_SyncFromFiles benchmarks SyncFromFiles operation
// BenchmarkMockManager_SyncFromFiles 基准测试 SyncFromFiles 操作
func BenchmarkMockManager_SyncFromFiles(b *testing.B) {
	mockMgr := NewMockManager()
	cfg := &types.GlobalConfig{
		Base: types.BaseConfig{
			Whitelist: []string{"10.0.0.0/8", "192.168.0.0/16"},
		},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = mockMgr.SyncFromFiles(cfg, false)
	}
}

// BenchmarkMockManager_SyncToFiles benchmarks SyncToFiles operation
// BenchmarkMockManager_SyncToFiles 基准测试 SyncToFiles 操作
func BenchmarkMockManager_SyncToFiles(b *testing.B) {
	mockMgr := NewMockManager()
	_ = mockMgr.AddWhitelistIP("10.0.0.1/32", 0)
	_ = mockMgr.AddWhitelistIP("192.168.1.1/32", 0)
	cfg := &types.GlobalConfig{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = mockMgr.SyncToFiles(cfg)
	}
}
