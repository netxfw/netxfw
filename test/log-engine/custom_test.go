package logengine_test

import (
	"github.com/livp123/netxfw/internal/plugins/agent/logengine"
	"net/netip"
	"testing"

	"github.com/livp123/netxfw/internal/plugins/types"
)

func TestCustomServiceRules(t *testing.T) {
	c := logengine.NewCounter(0)
	re := logengine.NewRuleEngine(c, &MockLogger{})

	rules := []types.LogEngineRule{
		// Test Fields()
		{
			ID:         "nginx_403",
			Expression: `len(Fields()) > 8 && Fields()[8] == "403"`,
			Action:     "block",
		},
		// Test Get()
		{
			ID:         "custom_app_error",
			Expression: `Get("service") == "payment" && Get("error_code") == "E500"`,
			Action:     "block",
		},
		// Test Get() with spaces/quotes
		{
			ID:         "quoted_value",
			Expression: `Get("msg") == "Access Denied"`,
			Action:     "block",
		},
	}

	if err := re.UpdateRules(rules); err != nil {
		t.Fatalf("UpdateRules failed: %v", err)
	}

	ip := netip.MustParseAddr("1.2.3.4")

	// 1. Nginx Log (Fields)
	// 1.2.3.4 - - [12/Feb/2026:10:00:00 +0000] "GET / HTTP/1.1" 403 1234
	// Indices:
	// 0: 1.2.3.4
	// 1: -
	// 2: -
	// 3: [12/Feb/2026:10:00:00
	// 4: +0000]
	// 5: "GET
	// 6: /
	// 7: HTTP/1.1"
	// 8: 403
	event1 := logengine.LogEvent{
		Line: `1.2.3.4 - - [12/Feb/2026:10:00:00 +0000] "GET / HTTP/1.1" 403 1234`,
	}
	_, _, id, matched := re.Evaluate(ip, event1)
	if !matched || id != "nginx_403" {
		t.Errorf("Expected nginx_403 match, got %v/%s", matched, id)
	}

	// 2. Custom App Log (Get)
	event2 := logengine.LogEvent{
		Line: `time=123 service=payment error_code=E500 user=bob`,
	}
	_, _, id, matched = re.Evaluate(ip, event2)
	if !matched || id != "custom_app_error" {
		t.Errorf("Expected custom_app_error match, got %v/%s", matched, id)
	}

	// 3. Quoted Value (Get)
	event3 := logengine.LogEvent{
		Line: `ts=0 msg="Access Denied" user=root`,
	}
	_, _, id, matched = re.Evaluate(ip, event3)
	if !matched || id != "quoted_value" {
		t.Errorf("Expected quoted_value match, got %v/%s", matched, id)
	}

	// 4. Mismatch
	event4 := logengine.LogEvent{
		Line: `service=auth error_code=E500`,
	}
	_, _, _, matched = re.Evaluate(ip, event4)
	if matched {
		t.Errorf("Should not match different service")
	}
}
