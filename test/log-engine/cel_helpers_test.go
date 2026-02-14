package logengine_test

import (
	"net/netip"
	"testing"

	"github.com/livp123/netxfw/internal/plugins/agent/logengine"
	"github.com/livp123/netxfw/internal/plugins/types"
)

func TestCELHelpers(t *testing.T) {
	c := logengine.NewCounter(0)
	re := logengine.NewRuleEngine(c, &MockLogger{})

	rules := []types.LogEngineRule{
		{
			ID:         "json_test",
			Expression: `JSON()["level"] == "error" && JSON()["user"]["name"] == "admin"`,
			Action:     "log",
		},
		{
			ID:         "kv_test",
			Expression: `KV()["status"] == "500" && KV()["method"] == "POST"`,
			Action:     "log",
		},
		{
			ID:         "match_test",
			Expression: `Match("failed.*password")`,
			Action:     "log",
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
		// JSON Tests
		{"JSON Match", `{"level": "error", "user": {"name": "admin"}, "msg": "failed"}`, "json_test"},
		{"JSON Mismatch Value", `{"level": "info", "user": {"name": "admin"}}`, ""},
		{"JSON Mismatch Nested", `{"level": "error", "user": {"name": "guest"}}`, ""},
		{"JSON Invalid", `Not a JSON string`, ""},

		// KV Tests
		{"KV Match", `time=12:00 status=500 method=POST url=/api`, "kv_test"},
		{"KV Mismatch", `time=12:00 status=200 method=POST`, ""},
		{"KV Partial", `status=500`, ""}, // Missing method

		// Match Tests
		{"Regex Match", `User failed some password check`, "match_test"},
		{"Regex Mismatch", `User entered correct password`, ""},
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
