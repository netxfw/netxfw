package logengine_test

import (
	"net/netip"
	"testing"

	"github.com/netxfw/netxfw/internal/plugins/agent/logengine"
	"github.com/netxfw/netxfw/internal/plugins/types"
)

func TestAliasFunctions(t *testing.T) {
	c := logengine.NewCounter(0)
	re := logengine.NewRuleEngine(c, &MockLogger{})

	rules := []types.LogEngineRule{
		{
			ID:     "alias_test",
			Action: "log",
			// Using Msg() and Time() aliases
			Expression: `Msg("Failed") && Msg("root") && Time(60) > 1`,
		},
		{
			ID:     "log_func_test",
			Action: "log",
			// Using lowercase aliases: log(), logE()
			Expression: `log("error") && !logE("DEBUG")`,
		},
		{
			ID:     "lowercase_time_test",
			Action: "log",
			// Using lowercase time() and msg()
			Expression: `msg("failed") && msg("root") && time(60) > 1`,
		},
	}

	if err := re.UpdateRules(rules); err != nil {
		t.Fatalf("UpdateRules failed: %v", err)
	}

	ip := netip.MustParseAddr("1.2.3.4")
	evt := logengine.LogEvent{
		Line: "Failed password for root",
	}

	// 1st attempt: Count=1. Expression: ... && 1 > 1 -> False
	_, _, _, matched := re.Evaluate(ip, evt)
	if matched {
		t.Errorf("Should not match on first attempt (Count=1)")
	}

	// 2nd attempt: Count=2. Expression: ... && 2 > 1 -> True
	_, _, _, matched = re.Evaluate(ip, evt)
	if !matched {
		t.Errorf("Should match on second attempt")
	}

	// Verify 'lowercase_time_test' specifically
	// It requires "failed", "root", and time(60)>1.
	// The current event matches "failed" and "root". Count is 2. So it should match.
	// Since 'alias_test' is first and identical logic, it matches first.

	// Let's test log_func_test (lowercase log/logE)

	// Test Log() function
	// Case 1: "Error" matches log("error") (insensitive), and "Error" != "DEBUG" (strict)
	evt2 := logengine.LogEvent{Line: "Critical Error occurred"}
	_, _, id, matched := re.Evaluate(ip, evt2)
	if !matched || id != "log_func_test" {
		t.Errorf("Expected log_func_test for 'Critical Error', got %v/%s", matched, id)
	}

	// Case 2: "DEBUG" matches logE("DEBUG") so !logE(...) is false -> No match
	evt3 := logengine.LogEvent{Line: "This is a DEBUG message"}
	_, _, id, matched = re.Evaluate(ip, evt3)
	if matched {
		t.Errorf("Should not match DEBUG message due to strict check, got %s", id)
	}

	// Case 3: "debug" does NOT match logE("DEBUG") -> !logE(...) is true.
	// But log("error") is false. So overall false.
	evt4 := logengine.LogEvent{Line: "just debug info"}
	_, _, id, matched = re.Evaluate(ip, evt4)
	if matched {
		t.Errorf("Should not match 'debug info' (missing 'error'), got %s", id)
	}
}
