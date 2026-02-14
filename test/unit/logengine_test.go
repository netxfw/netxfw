package unit

import (
	"net/netip"
	"testing"
	"time"

	"github.com/livp123/netxfw/internal/plugins/agent/logengine"
	"github.com/livp123/netxfw/internal/plugins/types"
)

type MockLogger struct{}

func (m *MockLogger) Infof(format string, args ...interface{})  {}
func (m *MockLogger) Warnf(format string, args ...interface{})  {}
func (m *MockLogger) Errorf(format string, args ...interface{}) {}

func TestLogEngine_CounterLogic(t *testing.T) {
	// 1. Setup Rule: logE("Failed") && count(60) > 2
	ruleConfig := types.LogEngineRule{
		ID:         "test_rule",
		Expression: `logE("Failed") && count(60) > 2`,
		Action:     "log",
	}

	counter := logengine.NewCounter(3600)
	re := logengine.NewRuleEngine(counter, &MockLogger{})
	err := re.UpdateRules([]types.LogEngineRule{ruleConfig})
	if err != nil {
		t.Fatalf("Failed to update rules: %v", err)
	}

	ip := netip.MustParseAddr("192.168.1.100")

	// 2. Simulate "Success" logs (Should NOT increment)
	for i := 0; i < 10; i++ {
		event := logengine.LogEvent{
			Line:      "2023-01-01 10:00:00 Success login",
			Source:    "/var/log/auth.log",
			Timestamp: time.Now(),
		}
		// In pipeline.go, we call Evaluate.
		// Note: The global increment in pipeline.go was removed.
		// So Evaluate is the only place increment can happen.
		re.Evaluate(ip, event)
	}

	// Verify Count is 0
	count := counter.Count(ip, 60)
	if count != 0 {
		t.Errorf("Expected count 0 after non-matching logs, got %d", count)
	}

	// 3. Simulate "Failed" log (Should Increment)
	event := logengine.LogEvent{
		Line:      "2023-01-01 10:00:01 Failed login attempt",
		Source:    "/var/log/auth.log",
		Timestamp: time.Now(),
	}
	re.Evaluate(ip, event)

	// Verify Count is 1
	count = counter.Count(ip, 60)
	if count != 1 {
		t.Errorf("Expected count 1 after 1 matching log, got %d", count)
	}

	// 4. Simulate 2 more Failed logs to trigger threshold (Count -> 3)
	re.Evaluate(ip, event)                          // Count -> 2
	action, _, _, matched := re.Evaluate(ip, event) // Count -> 3. 3 > 2 is True.

	if !matched {
		t.Errorf("Expected rule to match after 3rd failed login")
	}
	if action != logengine.ActionLog {
		t.Errorf("Expected ActionLog, got %v", action)
	}

	count = counter.Count(ip, 60)
	if count != 3 {
		t.Errorf("Expected count 3, got %d", count)
	}
}

func TestLogEngine_DoubleCountPrevention(t *testing.T) {
	// Setup Rule with double count check in expression
	// Or two rules that match the same line

	// Rule 1: logE("Failed") && count(60) > 100 (High threshold)
	// Rule 2: logE("Failed") && count(60) > 100 (High threshold)

	rules := []types.LogEngineRule{
		{
			ID:         "rule1",
			Expression: `logE("Failed") && count(60) > 100`,
		},
		{
			ID:         "rule2",
			Expression: `logE("Failed") && count(60) > 100`,
		},
	}

	counter := logengine.NewCounter(3600)
	re := logengine.NewRuleEngine(counter, &MockLogger{})
	re.UpdateRules(rules)

	ip := netip.MustParseAddr("10.0.0.1")
	event := logengine.LogEvent{
		Line:      "Failed login",
		Source:    "test",
		Timestamp: time.Now(),
	}

	// Evaluate. Both rules match content. Both call Count.
	// We expect increment ONLY ONCE per Evaluate call.
	// But wait, Evaluate is called once per event.
	// Inside Evaluate, it loops over rules.
	// Env is reused.

	re.Evaluate(ip, event)

	count := counter.Count(ip, 60)
	if count != 1 {
		t.Errorf("Expected count 1 (single increment for shared event), got %d", count)
	}
}
