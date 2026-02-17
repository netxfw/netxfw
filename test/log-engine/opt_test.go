package logengine_test

import (
	"net/netip"
	"testing"

	"github.com/livp123/netxfw/internal/plugins/agent/logengine"

	"github.com/livp123/netxfw/internal/plugins/types"
)

func TestOptimizedLike(t *testing.T) {
	c := logengine.NewCounter(0)
	re := logengine.NewRuleEngine(c, &MockLogger{})

	rules := []types.LogEngineRule{
		{
			ID: "wildcard_test",
			// "User * failed" should be converted to regex: Line matches "User .* failed"
			Contains: []string{"User * failed"},
			Action:   "block",
		},
		{
			ID: "cidr_test",
			// Test new InCIDR function
			Expression: `InCIDR("192.168.0.0/16")`,
			Action:     "allow",
		},
	}

	if err := re.UpdateRules(rules); err != nil {
		t.Fatalf("UpdateRules failed: %v", err)
	}

	ip := netip.MustParseAddr("192.168.1.50")
	externalIP := netip.MustParseAddr("8.8.8.8")

	// 1. Wildcard Matching (via Regex optimization)
	e1 := logengine.LogEvent{Line: "User admin failed password"}
	_, _, id, matched := re.Evaluate(ip, e1)
	if !matched || id != "wildcard_test" {
		t.Errorf("Wildcard should match. Got %v/%s", matched, id)
	}

	// 2. CIDR Matching
	e2 := logengine.LogEvent{Line: "ping"}
	// Internal IP -> Should match
	_, _, id, matched = re.Evaluate(ip, e2)
	if !matched || id != "cidr_test" {
		t.Errorf("Internal IP should match CIDR. Got %v/%s", matched, id)
	}
	// External IP -> Should NOT match
	_, _, _, matched = re.Evaluate(externalIP, e2)
	if matched {
		t.Errorf("External IP should not match CIDR")
	}
}
