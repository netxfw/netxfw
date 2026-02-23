package logengine_test

import (
	"net/netip"
	"testing"

	"github.com/netxfw/netxfw/internal/plugins/agent/logengine"

	"github.com/netxfw/netxfw/internal/plugins/types"
)

func TestIrregularLogFormat(t *testing.T) {
	c := logengine.NewCounter(0)
	re := logengine.NewRuleEngine(c, &MockLogger{})

	// Rule: Block if line contains "Failed" AND count > 3
	// Note: We implemented Contains method on Env
	rules := []types.LogEngineRule{
		{
			ID:         "auth_fail",
			Expression: `Contains(Line, "Failed") && Count(60) > 3`,
			Action:     "block",
		},
	}
	if err := re.UpdateRules(rules); err != nil {
		t.Fatalf("UpdateRules failed: %v", err)
	}

	ip := netip.MustParseAddr("10.0.0.1")

	// 1. Send 10 "Success" logs - Should NOT block even if count is high
	for i := 0; i < 10; i++ {
		// Even though count increments, the rule condition `contains(Line, "Failed")` is false
		event := logengine.LogEvent{
			Line:   "Accepted password for user admin from 10.0.0.1",
			Source: "/var/log/auth.log",
		}
		_, _, _, matched := re.Evaluate(ip, event)
		if matched {
			t.Errorf("Should not match success logs")
		}
	}

	// 2. Send 4 "Failed" logs - Should block
	// Note: Total count for IP is now 10 + 4 = 14, so Count(60) > 3 is true.
	// The gating factor is the Line content.
	for i := 0; i < 4; i++ {
		event := logengine.LogEvent{
			Line:   "Failed password for user root from 10.0.0.1",
			Source: "/var/log/auth.log",
		}
		action, _, id, matched := re.Evaluate(ip, event)
		if i == 3 { // 4th attempt
			if !matched {
				t.Errorf("Should match after 4th failure")
			}
			if action != logengine.ActionDynamic || id != "auth_fail" {
				t.Errorf("Unexpected action/id: %d/%s", action, id)
			}
		}
	}
}
