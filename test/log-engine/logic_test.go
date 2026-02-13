package logengine_test

import (
	"github.com/livp123/netxfw/internal/plugins/agent/logengine"
	"net/netip"
	"testing"

	"github.com/livp123/netxfw/internal/plugins/types"
)

func TestLogicRules(t *testing.T) {
	c := logengine.NewCounter(0)
	re := logengine.NewRuleEngine(c)

	rules := []types.LogEngineRule{
		// 1. Contains (AND) + Wildcard
		{
			ID:       "contains_wildcard",
			Contains: []string{"User * failed", "ssh"},
			Action:   "block",
		},
		// 2. AnyContains (OR)
		{
			ID:          "any_contains",
			AnyContains: []string{"sys_panic", "unknown_err"},
			Action:      "block",
		},
		// 3. NotContains (NOT)
		{
			ID:          "not_contains",
			Contains:    []string{"crit_err"},
			NotContains: []string{"test", "debug"}, // Block crit_err unless it's test/debug
			Action:      "block",
		},
		// 4. Complex (AND + OR + NOT)
		{
			ID:          "complex",
			Contains:    []string{"db_fatal"},            // Must have db_fatal
			AnyContains: []string{"timeout", "deadlock"}, // AND (timeout OR deadlock)
			NotContains: []string{"replica"},             // AND NOT replica
			Action:      "block",
		},
	}

	if err := re.UpdateRules(rules); err != nil {
		t.Fatalf("UpdateRules failed: %v", err)
	}

	ip := netip.MustParseAddr("1.2.3.4")

	tests := []struct {
		name       string
		line       string
		expectedID string
	}{
		// 1. Wildcard
		{"Wildcard Match", "User admin failed password via ssh", "contains_wildcard"},
		{"Wildcard Fail 1", "User admin failed password via telnet", ""}, // Missing ssh
		{"Wildcard Fail 2", "User admin success via ssh", ""},            // Missing failed pattern

		// 2. OR
		{"OR Match 1", "System sys_panic detected", "any_contains"},
		{"OR Match 2", "An unknown_err occurred", "any_contains"},
		{"OR Fail", "System normal", ""},

		// 3. NOT
		{"NOT Match", "Major crit_err in production", "not_contains"},
		{"NOT Fail 1", "Major crit_err in test environment", ""}, // Contains test
		{"NOT Fail 2", "debug crit_err trace", ""},               // Contains debug

		// 4. Complex
		{"Complex Match 1", "db_fatal: connection timeout", "complex"},
		{"Complex Match 2", "db_fatal: transaction deadlock found", "complex"},
		{"Complex Fail 1", "db_fatal: connection closed", ""}, // Missing OR part
		{"Complex Fail 2", "db_fatal: replica timeout", ""},   // Contains replica (NOT)
		{"Complex Fail 3", "timeout deadlock", ""},            // Missing db_fatal (AND)
	}

	for _, tt := range tests {
		event := logengine.LogEvent{Line: tt.line}
		_, _, id, matched := re.Evaluate(ip, event)
		if tt.expectedID == "" {
			if matched {
				t.Errorf("%s: Expected no match, got %s", tt.name, id)
			}
		} else {
			if !matched || id != tt.expectedID {
				t.Errorf("%s: Expected %s, got %v/%s", tt.name, tt.expectedID, matched, id)
			}
		}
	}
}
