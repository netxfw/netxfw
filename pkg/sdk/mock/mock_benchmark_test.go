package mock

import (
	"testing"
)

// BenchmarkSDK_Creation benchmarks SDK creation.
// BenchmarkSDK_Creation 基准测试 SDK 创建。
func BenchmarkSDK_Creation(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewMockSDK()
	}
}

// BenchmarkSDK_BlacklistAdd benchmarks blacklist add operation.
// BenchmarkSDK_BlacklistAdd 基准测试黑名单添加操作。
func BenchmarkSDK_BlacklistAdd(b *testing.B) {
	s := NewMockSDK()
	SetupMockBlacklist(s)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.Blacklist.Add("192.168.1.1")
	}
}

// BenchmarkSDK_BlacklistRemove benchmarks blacklist remove operation.
// BenchmarkSDK_BlacklistRemove 基准测试黑名单移除操作。
func BenchmarkSDK_BlacklistRemove(b *testing.B) {
	s := NewMockSDK()
	SetupMockBlacklist(s)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.Blacklist.Remove("192.168.1.1")
	}
}

// BenchmarkSDK_BlacklistContains benchmarks blacklist contains check.
// BenchmarkSDK_BlacklistContains 基准测试黑名单包含检查。
func BenchmarkSDK_BlacklistContains(b *testing.B) {
	s := NewMockSDK()
	SetupMockBlacklist(s)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = s.Blacklist.Contains("192.168.1.1")
	}
}

// BenchmarkSDK_WhitelistAdd benchmarks whitelist add operation.
// BenchmarkSDK_WhitelistAdd 基准测试白名单添加操作。
func BenchmarkSDK_WhitelistAdd(b *testing.B) {
	s := NewMockSDK()
	SetupMockWhitelist(s)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.Whitelist.Add("192.168.1.1", 0)
	}
}

// BenchmarkSDK_WhitelistRemove benchmarks whitelist remove operation.
// BenchmarkSDK_WhitelistRemove 基准测试白名单移除操作。
func BenchmarkSDK_WhitelistRemove(b *testing.B) {
	s := NewMockSDK()
	SetupMockWhitelist(s)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.Whitelist.Remove("192.168.1.1")
	}
}

// BenchmarkSDK_RuleAdd benchmarks rule add operation.
// BenchmarkSDK_RuleAdd 基准测试规则添加操作。
func BenchmarkSDK_RuleAdd(b *testing.B) {
	s := NewMockSDK()
	SetupMockRule(s)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.Rule.Add("192.168.1.1", 80, 1)
	}
}

// BenchmarkSDK_RuleRemove benchmarks rule remove operation.
// BenchmarkSDK_RuleRemove 基准测试规则移除操作。
func BenchmarkSDK_RuleRemove(b *testing.B) {
	s := NewMockSDK()
	SetupMockRule(s)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.Rule.Remove("192.168.1.1", 80)
	}
}

// BenchmarkSDK_StatsGetCounters benchmarks stats get counters operation.
// BenchmarkSDK_StatsGetCounters 基准测试统计获取计数器操作。
func BenchmarkSDK_StatsGetCounters(b *testing.B) {
	s := NewMockSDK()
	SetupMockStats(s)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = s.Stats.GetCounters()
	}
}

// BenchmarkSDK_ConcurrentBlacklist benchmarks concurrent blacklist operations.
// BenchmarkSDK_ConcurrentBlacklist 基准测试并发黑名单操作。
func BenchmarkSDK_ConcurrentBlacklist(b *testing.B) {
	s := NewMockSDK()
	SetupMockBlacklist(s)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = s.Blacklist.Add("192.168.1.1")
		}
	})
}

// BenchmarkSDK_ConcurrentWhitelist benchmarks concurrent whitelist operations.
// BenchmarkSDK_ConcurrentWhitelist 基准测试并发白名单操作。
func BenchmarkSDK_ConcurrentWhitelist(b *testing.B) {
	s := NewMockSDK()
	SetupMockWhitelist(s)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = s.Whitelist.Add("192.168.1.1", 0)
		}
	})
}

// BenchmarkSDK_ConcurrentMixedOps benchmarks concurrent mixed SDK operations.
// BenchmarkSDK_ConcurrentMixedOps 基准测试并发混合 SDK 操作。
func BenchmarkSDK_ConcurrentMixedOps(b *testing.B) {
	s := NewMockSDK()
	SetupMockBlacklist(s)
	SetupMockWhitelist(s)
	SetupMockRule(s)
	SetupMockStats(s)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			switch i % 4 {
			case 0:
				_ = s.Blacklist.Add("192.168.1.1")
			case 1:
				_ = s.Whitelist.Add("192.168.1.1", 0)
			case 2:
				_ = s.Rule.Add("192.168.1.1", 80, 1)
			case 3:
				_, _, _ = s.Stats.GetCounters()
			}
			i++
		}
	})
}
