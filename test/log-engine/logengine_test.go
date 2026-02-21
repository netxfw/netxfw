package logengine_test

import (
	"net/netip"
	"testing"

	"github.com/netxfw/netxfw/internal/plugins/agent/logengine"

	"github.com/netxfw/netxfw/internal/plugins/types"
)

func TestIPExtractor(t *testing.T) {
	e := logengine.NewIPExtractor()

	tests := []struct {
		line     string
		expected []string
	}{
		{"192.168.1.1", []string{"192.168.1.1"}},
		{"User admin from 10.0.0.1 failed", []string{"10.0.0.1"}},
		{"Invalid ip 999.999.999.999", []string{}},
		{"IPv6 ::1 localhost", []string{"::1"}},
		{"Multiple 1.1.1.1 and 8.8.8.8", []string{"1.1.1.1", "8.8.8.8"}},
		{"Junk 123.456 no ip", []string{}},
	}

	for _, tt := range tests {
		ips := e.ExtractIPs(tt.line)
		if len(ips) != len(tt.expected) {
			t.Errorf("ExtractIPs(%q) = %v, want %v", tt.line, ips, tt.expected)
			continue
		}
		for i, ip := range ips {
			if ip.String() != tt.expected[i] {
				t.Errorf("ExtractIPs(%q)[%d] = %s, want %s", tt.line, i, ip, tt.expected[i])
			}
		}
	}
}

func TestCounter(t *testing.T) {
	c := logengine.NewCounter(0)
	ip := netip.MustParseAddr("192.168.1.1")

	// Inc 10 times
	// 增加 10 次
	for i := 0; i < 10; i++ {
		c.Inc(ip)
	}

	count := c.Count(ip, 10)
	if count != 10 {
		t.Errorf("Count = %d, want 10", count)
	}

	// Test window
	// 测试窗口
	if c.Count(ip, 0) != 0 {
		t.Errorf("Count(0) should be 0")
	}
}

func TestRuleEngine(t *testing.T) {
	c := logengine.NewCounter(0)
	re := logengine.NewRuleEngine(c, &MockLogger{})

	rules := []types.LogEngineRule{
		{
			ID:         "rule1",
			Expression: "Count(60) > 5",
			Action:     "block",
		},
	}

	if err := re.UpdateRules(rules); err != nil {
		t.Fatalf("UpdateRules failed: %v", err)
	}

	ip := netip.MustParseAddr("1.2.3.4")

	// Not enough counts
	// 次数不足
	_, _, _, matched := re.Evaluate(ip, logengine.LogEvent{Line: "dummy", Source: "test"})
	if matched {
		t.Errorf("Should not match yet, count is 1")
	}

	// Add more counts
	// 增加更多次数
	for i := 0; i < 5; i++ {
		re.Evaluate(ip, logengine.LogEvent{Line: "dummy", Source: "test"})
	}
	// Total 6
	// 总共 6 次

	var action logengine.ActionType
	var id string
	action, _, id, matched = re.Evaluate(ip, logengine.LogEvent{Line: "dummy", Source: "test"})
	if !matched {
		t.Errorf("Should match now")
	}
	if action != logengine.ActionDynamic {
		t.Errorf("Action = %d, want block (dynamic)", action)
	}
	if id != "rule1" {
		t.Errorf("ID = %s, want rule1", id)
	}
}

func TestIPv6Support(t *testing.T) {
	// 1. Test Extraction
	// 1. 测试提取
	extractor := logengine.NewIPExtractor()
	line := "Failed password for root from 2001:db8::1 port 22 ssh2"
	ips := extractor.ExtractIPs(line)
	if len(ips) != 1 {
		t.Fatalf("Expected 1 IP, got %d", len(ips))
	}
	ipv6 := ips[0]
	if ipv6.String() != "2001:db8::1" {
		t.Errorf("Expected 2001:db8::1, got %s", ipv6)
	}
	if !ipv6.Is6() {
		t.Errorf("Expected IPv6 address")
	}

	// 2. Test logengine.Counter
	// 2. 测试 logengine.Counter
	counter := logengine.NewCounter(0)
	// Increment 5 times
	// 增加 5 次
	for i := 0; i < 5; i++ {
		counter.Inc(ipv6)
	}
	count := counter.Count(ipv6, 10)
	if count != 5 {
		t.Errorf("logengine.Counter expected 5, got %d", count)
	}

	// 3. Test Rule Engine
	// 3. 测试规则引擎
	re := logengine.NewRuleEngine(counter, &MockLogger{})
	rules := []types.LogEngineRule{
		{
			ID:         "ipv6_test",
			Expression: "Count(60) > 3",
			Action:     "block",
		},
	}
	if err := re.UpdateRules(rules); err != nil {
		t.Fatalf("Failed to update rules: %v", err)
	}

	// Evaluate
	// 评估
	action, _, id, matched := re.Evaluate(ipv6, logengine.LogEvent{
		Line:   "Failed password for root from 2001:db8::1 port 22 ssh2",
		Source: "/var/log/auth.log",
	})
	if !matched {
		t.Errorf("Rule should match for IPv6")
	}
	if action != logengine.ActionDynamic {
		t.Errorf("Expected block action, got %d", action)
	}
	if id != "ipv6_test" {
		t.Errorf("Expected rule id ipv6_test, got %s", id)
	}
}
