package logengine_test

import (
	"github.com/livp123/netxfw/internal/plugins/agent/logengine"
	"net/netip"
	"testing"

	"github.com/livp123/netxfw/internal/plugins/types"
)

// TestFrequencyControl demonstrates how to handle high-frequency events like 404 scans or login failures.
func TestFrequencyControl(t *testing.T) {
	c := logengine.NewCounter(0)
	re := logengine.NewRuleEngine(c, &MockLogger{})

	rules := []types.LogEngineRule{
		// Scenario 1: Nginx 404 Flood
		// Detect if an IP generates more than 5 404 errors in 10 seconds.
		{
			ID:        "nginx_404_flood",
			Path:      "/var/log/nginx/access.log",
			Contains:  []string{" 404 "}, // Match 404 with spaces to avoid matching timestamps or IDs
			Threshold: 5,
			Interval:  10,
			Action:    "block",
		},
		// Scenario 2: SSH/Auth Failure (Brute Force)
		// Detect if an IP generates more than 3 failures in 60 seconds.
		// Matches "Failed password", "authentication failure", "fail to login"
		{
			ID:          "auth_bruteforce",
			Path:        "/var/log/auth.log",
			AnyContains: []string{"Failed", "failure", "fail"}, // Fuzzy match for failure keywords
			Threshold:   3,
			Interval:    60,
			Action:      "block",
		},
	}

	if err := re.UpdateRules(rules); err != nil {
		t.Fatalf("UpdateRules failed: %v", err)
	}

	ip := netip.MustParseAddr("192.168.1.50")

	// --- Test Scenario 1: 404 Flood ---
	// 1. Generate 5 404 logs (Threshold is > 5, so 5 is safe, 6th triggers)
	for i := 0; i < 5; i++ {
		event := logengine.LogEvent{
			Line:   `192.168.1.50 - - [12/Feb/2026:10:00:00 +0000] "GET /random HTTP/1.1" 404 123 "-" "curl/7.0"`,
			Source: "/var/log/nginx/access.log",
		}
		_, _, _, matched := re.Evaluate(ip, event)
		if matched {
			t.Errorf("Should not match 404 flood yet (count %d <= 5)", i+1)
		}
	}

	// 2. The 6th 404 log should trigger the rule
	event404 := logengine.LogEvent{
		Line:   `192.168.1.50 - - [12/Feb/2026:10:00:00 +0000] "GET /overflow HTTP/1.1" 404 123`,
		Source: "/var/log/nginx/access.log",
	}
	action, _, id, matched := re.Evaluate(ip, event404)
	if !matched || id != "nginx_404_flood" {
		t.Errorf("Expected nginx_404_flood match, got %v/%s", matched, id)
	}
	if action != logengine.ActionDynamic {
		t.Errorf("Expected block action (dynamic)")
	}

	// --- Test Scenario 2: Auth Failure ---
	// Reset counter (simulating a new IP or waiting for interval expiration)
	// Since we can't easily reset time in unit test without mocking, let's use a different IP.
	attackerIP := netip.MustParseAddr("10.10.10.10")

	// 1. Generate 3 failures (Threshold is > 3, so 3 is safe, 4th triggers)
	failures := []string{
		"Failed password for root",
		"pam_unix(sshd:auth): authentication failure",
		"Login fail for user admin",
	}

	for _, line := range failures {
		event := logengine.LogEvent{
			Line:   line,
			Source: "/var/log/auth.log",
		}
		_, _, _, matched := re.Evaluate(attackerIP, event)
		if matched {
			t.Errorf("Should not match auth failure yet (count <= 3)")
		}
	}

	// 2. The 4th failure triggers
	eventFail := logengine.LogEvent{
		Line:   "Another Failed attempt",
		Source: "/var/log/auth.log",
	}
	action, _, id, matched = re.Evaluate(attackerIP, eventFail)
	if !matched || id != "auth_bruteforce" {
		t.Errorf("Expected auth_bruteforce match, got %v/%s", matched, id)
	}
}
