package logengine_test

import (
	"github.com/livp123/netxfw/internal/plugins/agent/logengine"
	"net/netip"
	"testing"

	"github.com/livp123/netxfw/internal/plugins/types"
)

func TestPathMatching(t *testing.T) {
	c := logengine.NewCounter()
	re := logengine.NewRuleEngine(c)

	rules := []types.LogEngineRule{
		{
			ID:         "nginx_rule",
			Path:       "access.log",
			Expression: `true`,
			Action:     "block",
		},
		{
			ID:         "var_log_rule",
			Path:       "/var/log/*.log",
			Expression: `true`,
			Action:     "block",
		},
		{
			ID:         "exact_path",
			Path:       "/etc/hosts",
			Expression: `true`,
			Action:     "block",
		},
		{
			ID:         "no_path",
			Path:       "",
			Expression: `true`,
			Action:     "block",
		},
	}

	if err := re.UpdateRules(rules); err != nil {
		t.Fatalf("UpdateRules failed: %v", err)
	}

	ip := netip.MustParseAddr("1.2.3.4")

	tests := []struct {
		source     string
		expectedID string
	}{
		{"/var/log/nginx/access.log", "nginx_rule"}, // Basename match
		{"access.log", "nginx_rule"},                // Exact match
		{"/var/log/syslog.log", "var_log_rule"},     // Glob match
		{"/etc/hosts", "exact_path"},                // Exact path
		{"/tmp/random.txt", "no_path"},              // Fallback to no_path rule
	}

	for _, tt := range tests {
		event := logengine.LogEvent{
			Line:   "something",
			Source: tt.source,
		}
		_, _, id, matched := re.Evaluate(ip, event)
		if !matched {
			t.Errorf("Source %s: Expected match, got none", tt.source)
		} else if id != tt.expectedID {
			t.Errorf("Source %s: Expected rule %s, got %s", tt.source, tt.expectedID, id)
		}
	}
}
