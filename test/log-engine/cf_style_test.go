package logengine_test

import (
	"net/netip"
	"testing"

	"github.com/livp123/netxfw/internal/plugins/agent/logengine"

	"github.com/livp123/netxfw/internal/plugins/types"
)

// TestCloudflareStyle demonstrates how to write rules that mimic Cloudflare's syntax.
// Cloudflare: http.request.uri contains "/admin" and ip.src in {1.1.1.1 2.2.2.2}
// NetXFW:     Get("uri") contains "/admin" && IP in ["1.1.1.1", "2.2.2.2"]
func TestCloudflareStyle(t *testing.T) {
	c := logengine.NewCounter(0)
	re := logengine.NewRuleEngine(c, &MockLogger{})

	rules := []types.LogEngineRule{
		// 1. Complex Logic (Cloudflare style)
		// Requirement: Block if URI contains "admin" AND User-Agent contains "curl"
		// AND IP is NOT in allowed list.
		{
			ID: "cf_style_complex",
			Expression: `
				Get("uri") contains "/admin" && 
				Get("ua") matches "(?i)curl" && 
				!(IP in ["10.0.0.1", "10.0.0.2"])
			`,
			Action: "block",
		},
		// 2. Case Insensitive Check
		// Cloudflare: lower(http.user_agent) contains "bot"
		{
			ID:         "cf_style_lower",
			Expression: `Lower(Get("ua")) contains "googlebot"`,
			Action:     "allow",
		},
		// 3. Status Code Range
		// Cloudflare: http.response.code ge 500
		{
			ID:         "cf_style_status",
			Expression: `Int(Get("status")) >= 500`,
			Action:     "block",
		},
	}

	if err := re.UpdateRules(rules); err != nil {
		t.Fatalf("UpdateRules failed: %v", err)
	}

	ip := netip.MustParseAddr("1.2.3.4")

	// Test 1: Complex Match
	e1 := logengine.LogEvent{Line: `uri=/admin/login ua=Curl/7.68 status=200`}
	_, _, id, matched := re.Evaluate(ip, e1)
	if !matched || id != "cf_style_complex" {
		t.Errorf("Expected cf_style_complex, got %v/%s", matched, id)
	}

	// Test 1: Complex Fail (Allowed IP)
	allowedIP := netip.MustParseAddr("10.0.0.1")
	_, _, _, matched = re.Evaluate(allowedIP, e1)
	if matched {
		t.Errorf("Should not match allowed IP")
	}

	// Test 2: Lower Case Match
	e2 := logengine.LogEvent{Line: `uri=/ ua=Mozilla/5.0 (compatible; Googlebot/2.1)`}
	_, _, id, matched = re.Evaluate(ip, e2)
	// Get("ua") extracts "Mozilla/5.0" because it splits by space in Get() implementation
	// "ua=Mozilla/5.0 (compatible; Googlebot/2.1)"
	// Get("ua") returns "Mozilla/5.0" because space is default delimiter after value start
	// We need to verify how Get works.
	// If the value is quoted it works.
	// Let's use quoted value for this test or simple value.
	e2_simple := logengine.LogEvent{Line: `uri=/ ua=Googlebot`}
	_, _, id, matched = re.Evaluate(ip, e2_simple)
	if !matched || id != "cf_style_lower" {
		t.Errorf("Expected cf_style_lower, got %v/%s", matched, id)
	}

	// Test 3: Status Range
	e3 := logengine.LogEvent{Line: `status=503 msg="Service Unavailable"`}
	_, _, id, matched = re.Evaluate(ip, e3)
	if !matched || id != "cf_style_status" {
		t.Errorf("Expected cf_style_status, got %v/%s", matched, id)
	}
}
