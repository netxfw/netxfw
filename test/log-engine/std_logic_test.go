package logengine_test

import (
	"github.com/livp123/netxfw/internal/plugins/agent/logengine"
	"net/netip"
	"testing"

	"github.com/livp123/netxfw/internal/plugins/types"
)

// TestStandardizedLogic validates the "and/or/not" standardized syntax.
func TestStandardizedLogic(t *testing.T) {
	c := logengine.NewCounter(0)
	re := logengine.NewRuleEngine(c)

	rules := []types.LogEngineRule{
		// Rule: Block if log contains "Error" AND "Database" (using 'and' keyword)
		{
			ID:     "std_and_logic",
			And:    []string{"Error", "Database"},
			Action: "block",
		},
		// Rule: Block if log contains "Timeout" OR "Deadlock" (using 'or' keyword)
		{
			ID:     "std_or_logic",
			Or:     []string{"Timeout", "Deadlock"},
			Action: "block",
		},
		// Rule: Block if log contains "Fatal" but NOT "Test" (using 'and' + 'not' keywords)
		{
			ID:     "std_not_logic",
			And:    []string{"Fatal"},
			Not:    []string{"Test"},
			Action: "block",
		},
	}

	if err := re.UpdateRules(rules); err != nil {
		t.Fatalf("UpdateRules failed: %v", err)
	}

	ip := netip.MustParseAddr("10.0.0.1")

	// 1. Test AND
	// Match
	e1 := logengine.LogEvent{Line: "Database connection Error"}
	_, _, id, matched := re.Evaluate(ip, e1)
	if !matched || id != "std_and_logic" {
		t.Errorf("Expected std_and_logic match, got %v/%s", matched, id)
	}
	// Fail (missing Database)
	e1b := logengine.LogEvent{Line: "Just an Error"}
	_, _, _, matched = re.Evaluate(ip, e1b)
	if matched {
		t.Errorf("Should not match std_and_logic (missing 'Database')")
	}

	// 2. Test OR
	// Match Timeout
	e2 := logengine.LogEvent{Line: "Connection Timeout"}
	_, _, id, matched = re.Evaluate(ip, e2)
	if !matched || id != "std_or_logic" {
		t.Errorf("Expected std_or_logic match, got %v/%s", matched, id)
	}
	// Match Deadlock
	e2b := logengine.LogEvent{Line: "Transaction Deadlock detected"}
	_, _, id, matched = re.Evaluate(ip, e2b)
	if !matched || id != "std_or_logic" {
		t.Errorf("Expected std_or_logic match, got %v/%s", matched, id)
	}

	// 3. Test NOT
	// Match Fatal
	e3 := logengine.LogEvent{Line: "System Fatal error"}
	_, _, id, matched = re.Evaluate(ip, e3)
	if !matched || id != "std_not_logic" {
		t.Errorf("Expected std_not_logic match, got %v/%s", matched, id)
	}
	// Fail (contains Test)
	e3b := logengine.LogEvent{Line: "Test System Fatal error"}
	_, _, _, matched = re.Evaluate(ip, e3b)
	if matched {
		t.Errorf("Should not match std_not_logic (contains 'Test')")
	}
}
