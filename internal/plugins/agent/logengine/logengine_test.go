package logengine

import (
	"fmt"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/utils/logger"
)

// MockActionHandler records calls for verification
type MockActionHandler struct {
	BlockedIPs  []string
	ActionTypes []ActionType
}

func (m *MockActionHandler) Block(ip netip.Addr, actionType ActionType, ttl time.Duration) error {
	m.BlockedIPs = append(m.BlockedIPs, ip.String())
	m.ActionTypes = append(m.ActionTypes, actionType)
	fmt.Printf("MockBlock: %s, Action: %d, TTL: %v\n", ip, actionType, ttl)
	return nil
}

func (m *MockActionHandler) Stop() {}

func TestLogEngine_RuleMatching(t *testing.T) {
	// 1. Setup Mock Handler
	mockHandler := &MockActionHandler{}

	// 2. Create LogEngine Config
	cfg := types.LogEngineConfig{
		Enabled: true,
		Workers: 1,
		Rules: []types.LogEngineRule{
			{
				ID:         "test_rule_static",
				Expression: `log("failed") && log("root")`,
				Action:     "2", // Static Block
			},
			{
				ID:         "test_rule_dynamic",
				Expression: `log("invalid user")`,
				Action:     "1", // Dynamic Block
				TTL:        "1m",
			},
			{
				ID:         "test_rule_threshold",
				Expression: `log("authentication error")`,
				Action:     "2",
				Threshold:  2,
				Interval:   60,
			},
		},
	}

	// 3. Initialize Engine
	le := New(cfg, logger.Get(nil), mockHandler)

	// 4. Simulate Log Events
	// Case A: Should Match Static
	event1 := LogEvent{
		Line:      "password failed for user root from 192.168.1.100",
		Source:    "/var/log/auth.log",
		Timestamp: time.Now(),
	}

	// Case B: Should Match Dynamic
	event2 := LogEvent{
		Line:      "Invalid user admin from 10.0.0.5",
		Source:    "/var/log/auth.log",
		Timestamp: time.Now(),
	}

	// Case C: No Match
	event3 := LogEvent{
		Line:      "Accepted password for user root from 192.168.1.200",
		Source:    "/var/log/auth.log",
		Timestamp: time.Now(),
	}

	// Manually inject events into processing logic (bypassing tailer for unit test)
	// We need to expose a way to test 'evaluate' or just call the worker logic.
	// Since 'worker' is private, we can test 'ruleEngine.Evaluate' directly.

	// Test Event 1
	ip1 := netip.MustParseAddr("192.168.1.100")
	action, _, ruleID, matched := le.ruleEngine.Evaluate(ip1, event1)
	if !matched {
		t.Errorf("Event 1 should match")
	}
	if action != ActionStatic {
		t.Errorf("Event 1 should be ActionStatic, got %v", action)
	}
	if ruleID != "test_rule_static" {
		t.Errorf("Event 1 matched wrong rule: %s", ruleID)
	}

	// Test Event 2
	ip2 := netip.MustParseAddr("10.0.0.5")
	action2, ttl2, ruleID2, matched2 := le.ruleEngine.Evaluate(ip2, event2)
	if !matched2 {
		t.Errorf("Event 2 should match")
	}
	if action2 != ActionDynamic {
		t.Errorf("Event 2 should be ActionDynamic, got %v", action2)
	}
	if ttl2 != time.Minute {
		t.Errorf("Event 2 TTL should be 1m, got %v", ttl2)
	}
	if ruleID2 != "test_rule_dynamic" {
		t.Errorf("Event 2 matched wrong rule: %s", ruleID2)
	}

	// Test Event 3
	ip3 := netip.MustParseAddr("192.168.1.200")
	_, _, _, matched3 := le.ruleEngine.Evaluate(ip3, event3)
	if matched3 {
		t.Errorf("Event 3 should NOT match")
	}

	// Case D: Threshold Logic
	// First Hit
	ip4 := netip.MustParseAddr("1.1.1.1")
	// le.counter.Inc(ip4) // Simulate worker increment
	event4a := LogEvent{Line: "authentication error 1", Source: "syslog", Timestamp: time.Now()}
	_, _, _, matched4a := le.ruleEngine.Evaluate(ip4, event4a)
	if matched4a {
		t.Errorf("Threshold rule should NOT match on 1st hit")
	}

	// Second Hit (Should NOT Trigger if Threshold=2 means >2)
	// le.counter.Inc(ip4) // Simulate worker increment
	event4b := LogEvent{Line: "authentication error 2", Source: "syslog", Timestamp: time.Now()}
	_, _, _, matched4b := le.ruleEngine.Evaluate(ip4, event4b)
	if matched4b {
		t.Errorf("Threshold rule should NOT match on 2nd hit (2 > 2 is false)")
	}

	// Third Hit (Should Trigger)
	// le.counter.Inc(ip4) // Simulate worker increment
	event4c := LogEvent{Line: "authentication error 3", Source: "syslog", Timestamp: time.Now()}
	action4c, _, ruleID4c, matched4c := le.ruleEngine.Evaluate(ip4, event4c)
	if !matched4c {
		t.Errorf("Threshold rule SHOULD match on 3rd hit (3 > 2 is true)")
	}
	if ruleID4c != "test_rule_threshold" {
		t.Errorf("Matched wrong rule for threshold: %s", ruleID4c)
	}
	if action4c != ActionStatic {
		t.Errorf("Should be static block")
	}

	fmt.Println("✅ RuleEngine matching logic passed (including Threshold)")
}

func TestXDPActionHandler_Async(t *testing.T) {
	// Create a handler with a nil manager (we just want to test the channel logic)
	// Note: In real run, run() checks for nil manager and returns, so it won't crash.
	handler := NewXDPActionHandler(nil, "/tmp/lock_list.txt")

	// Push a block request
	ip := netip.MustParseAddr("1.2.3.4")
	err := handler.Block(ip, ActionStatic, 0)
	if err != nil {
		t.Errorf("Block should not return error on enqueue: %v", err)
	}

	// Wait a bit to ensure no panic in background worker
	time.Sleep(100 * time.Millisecond)
	handler.Stop()
	fmt.Println("✅ Async ActionHandler enqueue passed")
}

func TestPersistenceLogic_Mock(t *testing.T) {
	// Verify the file writing logic from xdp_manager (Simulated)
	// We duplicate the logic here just to verify the 'os' calls work as expected
	tmpFile := "test_rules.deny.txt"
	defer os.Remove(tmpFile)

	cidr := "1.2.3.4/32"

	// Use O_APPEND to add to the end of the file
	f, err := os.OpenFile(tmpFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("Failed to open file: %v", err)
	}
	if _, err := f.WriteString(cidr + "\n"); err != nil {
		f.Close()
		t.Fatalf("Failed to write: %v", err)
	}
	f.Close()

	// Verify content
	content, _ := os.ReadFile(tmpFile)
	if string(content) != "1.2.3.4/32\n" {
		t.Errorf("Content mismatch: %s", string(content))
	}

	// Append another
	f, _ = os.OpenFile(tmpFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	f.WriteString("5.6.7.8/32\n")
	f.Close()

	content, _ = os.ReadFile(tmpFile)
	expected := "1.2.3.4/32\n5.6.7.8/32\n"
	if string(content) != expected {
		t.Errorf("Append failed. Got:\n%s", string(content))
	}

	fmt.Println("✅ Persistence file logic verification passed")
}

func TestLogEngine_LongWindow(t *testing.T) {
	// 1. Setup Mock Handler
	mockHandler := &MockActionHandler{}

	// 2. Create Config with 1 hour window rule
	cfg := types.LogEngineConfig{
		Enabled: true,
		Workers: 1,
		Rules: []types.LogEngineRule{
			{
				ID:         "test_rule_1h",
				Expression: `log("failed")`,
				Action:     "2",
				Threshold:  2,    // > 2
				Interval:   3600, // 1 hour
			},
		},
	}

	le := New(cfg, logger.Get(nil), mockHandler)
	ip := netip.MustParseAddr("2.2.2.2")
	event := LogEvent{Line: "failed login", Source: "auth.log", Timestamp: time.Now()}

	// Hit 1
	// le.counter.Inc(ip) // Removed manual increment as Evaluate does it now
	_, _, _, matched := le.ruleEngine.Evaluate(ip, event)
	if matched {
		t.Errorf("Should not match on 1st hit")
	}

	// Hit 2
	// le.counter.Inc(ip)
	_, _, _, matched = le.ruleEngine.Evaluate(ip, event)
	if matched {
		t.Errorf("Should not match on 2nd hit")
	}

	// Hit 3
	// le.counter.Inc(ip)
	_, _, _, matched = le.ruleEngine.Evaluate(ip, event)
	if !matched {
		t.Errorf("Should match on 3rd hit with 3600s window")
	}

	fmt.Println("✅ 1-Hour Window configuration accepted and working for immediate hits")
}

func TestCounter_DynamicConfig(t *testing.T) {
	// Verify that MaxWindow config is respected
	cfg := types.LogEngineConfig{
		Enabled:   true,
		MaxWindow: 7200, // 2 hours
		Rules:     []types.LogEngineRule{},
	}

	mockHandler := &MockActionHandler{}
	le := New(cfg, logger.Get(nil), mockHandler)

	if le.counter.maxWindowSeconds != 7200 {
		t.Errorf("Expected maxWindowSeconds to be 7200, got %d", le.counter.maxWindowSeconds)
	}

	// Check if slices are allocated correctly
	ip := netip.MustParseAddr("3.3.3.3")
	le.counter.Inc(ip)

	shard := le.counter.getShard(ip)
	shard.RLock()
	stats, ok := shard.counts[ip]
	shard.RUnlock()

	if !ok {
		t.Fatal("Stats not found for IP")
	}

	if len(stats.buckets) != 7200 {
		t.Errorf("Expected bucket size 7200, got %d", len(stats.buckets))
	}

	fmt.Println("✅ Dynamic Counter Configuration verified")
}
