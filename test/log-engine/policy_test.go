package logengine_test

import (
	"net/netip"
	"testing"

	"github.com/livp123/netxfw/internal/plugins/agent/logengine"
	"github.com/livp123/netxfw/internal/plugins/types"
)

// TestRulePolicies verifies the specific blocking policies requested:
// 1. Non-root user failures -> Block immediately
// 2. Root user failures -> Block after 2 attempts
func TestRulePolicies(t *testing.T) {
	c := logengine.NewCounter(0)
	re := logengine.NewRuleEngine(c, &MockLogger{})

	rules := []types.LogEngineRule{
		// Rule 1: Block non-root users immediately on failure
		// Logic: Line contains "Failed" AND does NOT contain "root"
		{
			ID:         "block_non_root_immediate",
			Expression: `Contains(Line, "Failed") && !Contains(Line, "root")`,
			Action:     "block",
		},
		// Rule 2: Block root user after 2 failures
		// Logic: Line contains "Failed" AND contains "root" AND count > 2
		{
			ID:         "block_root_retry",
			Expression: `Contains(Line, "Failed") && Contains(Line, "root") && Count(60) > 2`,
			Action:     "block",
		},
	}

	if err := re.UpdateRules(rules); err != nil {
		t.Fatalf("UpdateRules failed: %v", err)
	}

	ipNonRoot := netip.MustParseAddr("1.1.1.1")
	ipRoot := netip.MustParseAddr("2.2.2.2")

	// --- Scenario 1: Non-root user failure ---
	eventNonRoot := logengine.LogEvent{
		Line: "Failed password for invalid user admin from 1.1.1.1 port 54134 ssh2",
	}

	// 1st attempt: Should block immediately
	action, _, id, matched := re.Evaluate(ipNonRoot, eventNonRoot)
	if !matched {
		t.Errorf("Non-root rule should match immediately")
	}
	if id != "block_non_root_immediate" {
		t.Errorf("Expected rule block_non_root_immediate, got %s", id)
	}
	if action != logengine.ActionDynamic {
		t.Errorf("Expected block action")
	}

	// --- Scenario 2: Root user failure ---
	eventRoot := logengine.LogEvent{
		Line: "Failed password for root from 2.2.2.2 port 50776 ssh2",
	}

	// 1st attempt: Should NOT block (Count=1 <= 2)
	_, _, _, matched = re.Evaluate(ipRoot, eventRoot)
	if matched {
		t.Errorf("Root rule should not match on 1st attempt")
	}

	// 2nd attempt: Should NOT block (Count=2 <= 2)
	_, _, _, matched = re.Evaluate(ipRoot, eventRoot)
	if matched {
		t.Errorf("Root rule should not match on 2nd attempt")
	}

	// 3rd attempt: Should BLOCK (Count=3 > 2)
	action, _, id, matched = re.Evaluate(ipRoot, eventRoot)
	if !matched {
		t.Errorf("Root rule should match on 3rd attempt")
	}
	if id != "block_root_retry" {
		t.Errorf("Expected rule block_root_retry, got %s", id)
	}
}
