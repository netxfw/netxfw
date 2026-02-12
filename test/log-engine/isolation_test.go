package logengine_test

import (
	"github.com/livp123/netxfw/internal/plugins/agent/logengine"
	"net/netip"
	"testing"

	"github.com/livp123/netxfw/internal/plugins/types"
)

func TestServiceIsolation(t *testing.T) {
	c := logengine.NewCounter()
	re := logengine.NewRuleEngine(c)

	// Rule 1: SSH Brute Force (Only applies to auth.log)
	// Rule 2: Nginx 404 Flood (Only applies to access.log)
	rules := []types.LogEngineRule{
		{
			ID:         "ssh_bruteforce",
			Expression: `Contains(Source, "auth.log") && Contains(Line, "Failed") && Count(60) > 3`,
			Action:     "block",
		},
		{
			ID:         "nginx_flood",
			Expression: `Contains(Source, "access.log") && Contains(Line, "404") && Count(60) > 5`,
			Action:     "block",
		},
	}
	if err := re.UpdateRules(rules); err != nil {
		t.Fatalf("UpdateRules failed: %v", err)
	}

	ip := netip.MustParseAddr("192.168.1.100")

	// 1. Send SSH failures (should match rule 1)
	for i := 0; i < 4; i++ {
		c.Inc(ip)
		event := logengine.LogEvent{
			Line:   "Failed password for root",
			Source: "/var/log/auth.log",
		}
		action, _, id, matched := re.Evaluate(ip, event)
		if i == 3 {
			if !matched {
				t.Errorf("SSH rule should match")
			}
			if id != "ssh_bruteforce" {
				t.Errorf("Expected ssh_bruteforce, got %s", id)
			}
			if action != logengine.ActionDynamic {
				t.Errorf("Expected block action")
			}
		}
	}

	// 2. Send Nginx 404s (but with Source = auth.log) -> Should NOT match Nginx rule
	// Reset counter or use new IP
	ip2 := netip.MustParseAddr("192.168.1.101")
	for i := 0; i < 6; i++ {
		c.Inc(ip2)
		event := logengine.LogEvent{
			Line:   "GET /admin HTTP/1.1 404",
			Source: "/var/log/auth.log", // Wrong source
		}
		_, _, _, matched := re.Evaluate(ip2, event)
		if matched {
			t.Errorf("Should not match nginx rule with auth.log source")
		}
	}

	// 3. Send Nginx 404s (Correct source) -> Should match
	ip3 := netip.MustParseAddr("192.168.1.102")
	for i := 0; i < 6; i++ {
		c.Inc(ip3)
		event := logengine.LogEvent{
			Line:   "GET /admin HTTP/1.1 404",
			Source: "/var/log/nginx/access.log",
		}
		action, _, id, matched := re.Evaluate(ip3, event)
		if i == 5 {
			if !matched {
				t.Errorf("Nginx rule should match")
			}
			if id != "nginx_flood" {
				t.Errorf("Expected nginx_flood, got %s", id)
			}
			if action != logengine.ActionDynamic {
				t.Errorf("Expected block action")
			}
		}
	}
}
