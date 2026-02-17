package storage_test

import (
	"testing"
	"time"

	"github.com/livp123/netxfw/pkg/storage"
)

// TestRuleType tests rule type constants
// TestRuleType 测试规则类型常量
func TestRuleType(t *testing.T) {
	// Test rule type values
	// 测试规则类型值
	if storage.RuleTypeWhitelist != "whitelist" {
		t.Errorf("RuleTypeWhitelist should be 'whitelist', got %s", storage.RuleTypeWhitelist)
	}
	if storage.RuleTypeLockList != "lock_list" {
		t.Errorf("RuleTypeLockList should be 'lock_list', got %s", storage.RuleTypeLockList)
	}
	if storage.RuleTypeIPPort != "ip_port" {
		t.Errorf("RuleTypeIPPort should be 'ip_port', got %s", storage.RuleTypeIPPort)
	}
}

// TestIPRule tests IPRule struct
// TestIPRule 测试 IPRule 结构体
func TestIPRule(t *testing.T) {
	// Test without expiration
	// 测试无过期时间
	rule := storage.IPRule{
		CIDR: "192.168.1.0/24",
	}
	if rule.CIDR != "192.168.1.0/24" {
		t.Errorf("CIDR should be '192.168.1.0/24', got %s", rule.CIDR)
	}
	if rule.ExpiresAt != nil {
		t.Error("ExpiresAt should be nil")
	}

	// Test with expiration
	// 测试有过期时间
	expiry := time.Now().Add(24 * time.Hour)
	ruleWithExpiry := storage.IPRule{
		CIDR:      "10.0.0.0/8",
		ExpiresAt: &expiry,
	}
	if ruleWithExpiry.ExpiresAt == nil {
		t.Error("ExpiresAt should not be nil")
	}
}

// TestIPPortRule tests IPPortRule struct
// TestIPPortRule 测试 IPPortRule 结构体
func TestIPPortRule(t *testing.T) {
	// Test basic rule
	// 测试基本规则
	rule := storage.IPPortRule{
		CIDR:     "192.168.1.0/24",
		Port:     8080,
		Protocol: "tcp",
		Action:   "allow",
	}

	if rule.CIDR != "192.168.1.0/24" {
		t.Errorf("CIDR mismatch: got %s", rule.CIDR)
	}
	if rule.Port != 8080 {
		t.Errorf("Port should be 8080, got %d", rule.Port)
	}
	if rule.Protocol != "tcp" {
		t.Errorf("Protocol should be 'tcp', got %s", rule.Protocol)
	}
	if rule.Action != "allow" {
		t.Errorf("Action should be 'allow', got %s", rule.Action)
	}

	// Test deny action
	// 测试拒绝动作
	denyRule := storage.IPPortRule{
		CIDR:     "10.0.0.0/8",
		Port:     443,
		Protocol: "udp",
		Action:   "deny",
	}
	if denyRule.Action != "deny" {
		t.Errorf("Action should be 'deny', got %s", denyRule.Action)
	}
}

// TestNormalizeCIDR tests the CIDR normalization helper
// TestNormalizeCIDR 测试 CIDR 标准化辅助函数
func TestNormalizeCIDR(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"IPv4 Single", "192.168.1.1", "192.168.1.1/32"},
		{"IPv4 CIDR", "192.168.1.0/24", "192.168.1.0/24"},
		{"IPv6 Single", "2001:db8::1", "2001:db8::1/128"},
		{"IPv6 CIDR", "2001:db8::/32", "2001:db8::/32"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := storage.NormalizeCIDR(tt.input)
			if got != tt.want {
				t.Errorf("NormalizeCIDR(%s) = %s, want %s", tt.input, got, tt.want)
			}
		})
	}
}
