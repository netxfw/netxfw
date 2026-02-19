// Package realip provides real IP extraction and blacklisting for cloud LB environments.
// Package realip 为云 LB 环境提供真实 IP 提取和黑名单功能。
package realip

import (
	"net/netip"
	"testing"
	"time"

	"github.com/livp123/netxfw/internal/utils/logger"
)

// TestNewManager tests the Manager creation.
// TestNewManager 测试 Manager 创建。
func TestNewManager(t *testing.T) {
	cfg := &Config{
		ProxyProtocolEnabled: true,
		TrustedLBs:           []string{"10.0.0.0/8", "192.168.0.0/16"},
	}

	m := NewManager(cfg)
	if m == nil {
		t.Fatal("Expected non-nil manager")
	}

	if !m.parser.IsEnabled() {
		t.Error("Expected Proxy Protocol parser to be enabled")
	}

	if len(m.trustedLBs) != 2 {
		t.Errorf("Expected 2 trusted LB ranges, got %d", len(m.trustedLBs))
	}
}

// TestIsTrustedLB tests the trusted LB check.
// TestIsTrustedLB 测试可信 LB 检查。
func TestIsTrustedLB(t *testing.T) {
	cfg := &Config{
		ProxyProtocolEnabled: true,
		TrustedLBs:           []string{"10.0.0.0/8"},
	}

	m := NewManager(cfg)

	tests := []struct {
		ip       string
		expected bool
	}{
		{"10.0.1.100", true},
		{"10.255.255.255", true},
		{"192.168.1.1", false},
		{"172.16.0.1", false},
		{"invalid", false},
	}

	for _, tc := range tests {
		result := m.IsTrustedLB(tc.ip)
		if result != tc.expected {
			t.Errorf("IsTrustedLB(%s) = %v, expected %v", tc.ip, result, tc.expected)
		}
	}
}

// TestAddToBlacklist tests adding to blacklist.
// TestAddToBlacklist 测试添加到黑名单。
func TestAddToBlacklist(t *testing.T) {
	cfg := &Config{
		ProxyProtocolEnabled: true,
		TrustedLBs:           []string{},
	}

	m := NewManager(cfg)

	// Add permanent entry.
	// 添加永久条目。
	err := m.AddToBlacklist("192.168.1.100", "test reason", 0)
	if err != nil {
		t.Fatalf("AddToBlacklist failed: %v", err)
	}

	if !m.IsBlacklisted("192.168.1.100") {
		t.Error("Expected IP to be blacklisted")
	}

	// Add temporary entry.
	// 添加临时条目。
	err = m.AddToBlacklist("10.0.0.1", "temp block", 1*time.Hour)
	if err != nil {
		t.Fatalf("AddToBlacklist with duration failed: %v", err)
	}

	if !m.IsBlacklisted("10.0.0.1") {
		t.Error("Expected IP to be blacklisted")
	}
}

// TestRemoveFromBlacklist tests removing from blacklist.
// TestRemoveFromBlacklist 测试从黑名单移除。
func TestRemoveFromBlacklist(t *testing.T) {
	cfg := &Config{
		ProxyProtocolEnabled: true,
		TrustedLBs:           []string{},
	}

	m := NewManager(cfg)

	// Add and then remove.
	// 添加然后移除。
	m.AddToBlacklist("192.168.1.100", "test", 0)

	if !m.IsBlacklisted("192.168.1.100") {
		t.Fatal("Expected IP to be blacklisted before removal")
	}

	m.RemoveFromBlacklist("192.168.1.100")

	if m.IsBlacklisted("192.168.1.100") {
		t.Error("Expected IP to not be blacklisted after removal")
	}
}

// TestShouldDrop tests the drop decision logic.
// TestShouldDrop 测试 drop 决策逻辑。
func TestShouldDrop(t *testing.T) {
	cfg := &Config{
		ProxyProtocolEnabled: true,
		TrustedLBs:           []string{"10.0.0.0/8"},
	}

	m := NewManager(cfg)

	// Add a real IP to blacklist.
	// 添加真实 IP 到黑名单。
	m.AddToBlacklist("192.168.1.100", "malicious", 0)

	// Test with trusted LB and blacklisted real IP.
	// 测试可信 LB 和黑名单真实 IP。
	realIP := mustParseAddr("192.168.1.100")
	shouldDrop, reason := m.ShouldDrop("10.0.1.100", realIP)
	if !shouldDrop {
		t.Error("Expected drop for blacklisted real IP")
	}
	if reason != "real_ip_blacklisted" {
		t.Errorf("Expected reason 'real_ip_blacklisted', got '%s'", reason)
	}

	// Test with trusted LB and non-blacklisted real IP.
	// 测试可信 LB 和非黑名单真实 IP。
	realIP2 := mustParseAddr("192.168.1.200")
	shouldDrop, _ = m.ShouldDrop("10.0.1.100", realIP2)
	if shouldDrop {
		t.Error("Expected no drop for non-blacklisted real IP")
	}
}

// TestCleanupExpired tests expired entry cleanup.
// TestCleanupExpired 测试过期条目清理。
func TestCleanupExpired(t *testing.T) {
	cfg := &Config{
		ProxyProtocolEnabled: true,
		TrustedLBs:           []string{},
	}

	m := NewManager(cfg)

	// Add entry that expires in the past.
	// 添加过去过期的条目。
	m.AddToBlacklist("192.168.1.100", "expired", -1*time.Hour)

	// Add non-expired entry.
	// 添加未过期条目。
	m.AddToBlacklist("192.168.1.200", "active", 1*time.Hour)

	// Manually set expired time for the first entry.
	// 手动设置第一个条目的过期时间。
	m.mu.Lock()
	if entry, ok := m.blacklist["192.168.1.100"]; ok {
		entry.ExpiresAt = time.Now().Add(-1 * time.Hour)
	}
	m.mu.Unlock()

	// Cleanup.
	// 清理。
	m.CleanupExpired()

	// Check results - the expired entry should be removed from the map.
	// 检查结果 - 过期条目应该从 map 中移除。
	m.mu.RLock()
	_, existsExpired := m.blacklist["192.168.1.100"]
	_, existsActive := m.blacklist["192.168.1.200"]
	m.mu.RUnlock()

	if existsExpired {
		t.Error("Expected expired entry to be removed from map")
	}

	if !existsActive {
		t.Error("Expected active entry to remain in map")
	}
}

// TestGetStats tests statistics retrieval.
// TestGetStats 测试统计信息获取。
func TestGetStats(t *testing.T) {
	cfg := &Config{
		ProxyProtocolEnabled: true,
		TrustedLBs:           []string{"10.0.0.0/8"},
	}

	m := NewManager(cfg)
	m.AddToBlacklist("192.168.1.100", "test", 0)

	stats := m.GetStats()
	if stats["blacklist_count"] != 1 {
		t.Errorf("Expected blacklist_count 1, got %v", stats["blacklist_count"])
	}

	if stats["trusted_lb_ranges"] != 1 {
		t.Errorf("Expected trusted_lb_ranges 1, got %v", stats["trusted_lb_ranges"])
	}

	if stats["proxy_protocol"] != true {
		t.Error("Expected proxy_protocol to be true")
	}
}

// mustParseAddr parses an IP address or panics.
// mustParseAddr 解析 IP 地址或 panic。
func mustParseAddr(s string) netip.Addr {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return addr
}

func init() {
	// Initialize logger for tests.
	// 为测试初始化日志器。
	logger.Init(logger.LoggingConfig{
		Enabled: false,
	})
}
