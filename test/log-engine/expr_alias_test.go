package logengine_test

import (
	"net/netip"
	"testing"

	"github.com/livp123/netxfw/internal/plugins/agent/logengine"

	"github.com/livp123/netxfw/internal/plugins/types"
)

// TestExpressionAliases validates using Log/Msg instead of Line in expressions.
func TestExpressionAliases(t *testing.T) {
	c := logengine.NewCounter(0)
	re := logengine.NewRuleEngine(c)

	rules := []types.LogEngineRule{
		// 1. Use 'Log' function alias (log() -> Log())
		{
			ID:         "use_log_alias",
			Expression: `Log("error")`,
			Action:     "block",
		},
		// 2. Use 'Msg' alias (msg() -> Msg())
		{
			ID:         "use_msg_alias",
			Expression: `Msg("panic")`,
			Action:     "block",
		},
		// 3. Mixed Usage (Log && Msg)
		{
			ID:         "mixed_aliases",
			Expression: `Log("fatal") && Msg("database")`,
			Action:     "block",
		},
	}

	if err := re.UpdateRules(rules); err != nil {
		t.Fatalf("UpdateRules failed: %v", err)
	}

	ip := netip.MustParseAddr("1.2.3.4")

	// Test 1: Log alias
	e1 := logengine.LogEvent{Line: "An error occurred"}
	_, _, id, matched := re.Evaluate(ip, e1)
	if !matched || id != "use_log_alias" {
		t.Errorf("Expected use_log_alias, got %v/%s", matched, id)
	}

	// Test 2: Msg alias
	e2 := logengine.LogEvent{Line: "Kernel panic detected"}
	_, _, id, matched = re.Evaluate(ip, e2)
	if !matched || id != "use_msg_alias" {
		t.Errorf("Expected use_msg_alias, got %v/%s", matched, id)
	}

	// Test 3: Mixed
	e3 := logengine.LogEvent{Line: "fatal database corruption"}
	_, _, id, matched = re.Evaluate(ip, e3)
	if !matched || id != "mixed_aliases" {
		t.Errorf("Expected mixed_aliases, got %v/%s", matched, id)
	}
}
