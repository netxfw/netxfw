package logengine_test

import (
	"testing"
	"net/netip"

	"github.com/livp123/netxfw/internal/plugins/agent/logengine"
	"github.com/livp123/netxfw/internal/plugins/types"
)

// TestSimplifiedSyntax verifies the YAML-friendly list syntax (and/or/not)
func TestSimplifiedSyntax(t *testing.T) {
	c := logengine.NewCounter()
	re := logengine.NewRuleEngine(c)

	rules := []types.LogEngineRule{
		// Rule 1: Block non-root users immediately
		// Logic: Must contain "Failed" AND must NOT contain "root"
		{
			ID:     "block_non_root_yaml",
			Action: "block",
			// "contains" is an implicit AND list
			Contains: []string{"Failed"},
			// "not_contains" is a NOT list
			NotContains: []string{"root"},
		},
		// Rule 2: Block root user after 2 failures (requires expression for Count(), but let's test basic matching)
		// Since simplified syntax doesn't support Count() directly yet, we test the matching part.
		// "and" alias for "contains", "not" alias for "not_contains"
		{
			ID:     "block_root_match_yaml",
			Action: "log",
			And:    []string{"Failed", "root"},
		},
		// Rule 3: OR logic example (e.g., "Invalid user" OR "Failed password")
		{
			ID:          "or_logic_yaml",
			Action:      "block",
			AnyContains: []string{"Invalid user", "Failed password"},
		},
	}

	if err := re.UpdateRules(rules); err != nil {
		t.Fatalf("UpdateRules failed: %v", err)
	}

	ip := netip.MustParseAddr("1.2.3.4")

	// Test 1: Non-root failure
	// Matches: Contains "Failed", NotContains "root"
	evt1 := logengine.LogEvent{Line: "Failed password for invalid user admin"}
	_, _, id, matched := re.Evaluate(ip, evt1)
	if !matched || id != "block_non_root_yaml" {
		t.Errorf("Expected block_non_root_yaml, got %v (matched=%v)", id, matched)
	}

	// Test 2: Root failure
	// Should NOT match block_non_root_yaml (contains "root")
	// Should match block_root_match_yaml (Contains "Failed" AND "root")
	evt2 := logengine.LogEvent{Line: "Failed password for root"}
	_, _, id, matched = re.Evaluate(ip, evt2)
	if !matched || id != "block_root_match_yaml" {
		t.Errorf("Expected block_root_match_yaml, got %v (matched=%v)", id, matched)
	}

	// Test 3: OR logic
	evt3 := logengine.LogEvent{Line: "Invalid user nagios"}
	_, _, id, matched = re.Evaluate(ip, evt3)
	if !matched || id != "or_logic_yaml" {
		t.Errorf("Expected or_logic_yaml, got %v (matched=%v)", id, matched)
	}
}
