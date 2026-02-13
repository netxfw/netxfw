package logengine_test

import (
	"github.com/livp123/netxfw/internal/plugins/agent/logengine"
	"net/netip"
	"testing"

	"github.com/livp123/netxfw/internal/plugins/types"
)

func TestSimplifiedRules(t *testing.T) {
	c := logengine.NewCounter(0)
	re := logengine.NewRuleEngine(c)

	rules := []types.LogEngineRule{
		// 1. Keyword Check
		{
			ID:       "simple_keyword",
			Keywords: []string{"Failed", "password"},
			Action:   "block",
		},
		// 2. Threshold Check
		{
			ID:        "rate_limit",
			Keywords:  []string{"Connection"},
			Threshold: 2,
			Interval:  10,
			Action:    "block",
		},
		// 3. Regex Check
		{
			ID:     "regex_check",
			Regex:  `^User \w+ login`,
			Action: "block",
		},
		// 4. Combined
		{
			ID:        "combined",
			Keywords:  []string{"Error"},
			Regex:     `[0-9]{3}`,
			Threshold: 1,
			Action:    "block",
		},
	}

	if err := re.UpdateRules(rules); err != nil {
		t.Fatalf("UpdateRules failed: %v", err)
	}

	ip := netip.MustParseAddr("1.2.3.4")

	// Test 1: Keywords
	e1 := logengine.LogEvent{Line: "Failed password for root"}
	_, _, id, matched := re.Evaluate(ip, e1)
	if !matched || id != "simple_keyword" {
		t.Errorf("Expected simple_keyword, got %v/%s", matched, id)
	}

	// Test 2: Threshold
	e2 := logengine.LogEvent{Line: "Connection opened"}
	// 1st hit
	c.Inc(ip)
	_, _, _, matched = re.Evaluate(ip, e2)
	if matched {
		t.Errorf("Should not match rate_limit yet (1 <= 2)")
	}
	// 2nd hit
	c.Inc(ip)
	re.Evaluate(ip, e2)
	// 3rd hit (trigger > 2)
	c.Inc(ip)
	_, _, id, matched = re.Evaluate(ip, e2)
	if !matched || id != "rate_limit" {
		t.Errorf("Expected rate_limit match on 3rd attempt, got %v/%s", matched, id)
	}

	// Test 3: Regex
	e3 := logengine.LogEvent{Line: "User admin login successful"}
	_, _, id, matched = re.Evaluate(ip, e3)
	if !matched || id != "regex_check" {
		t.Errorf("Expected regex_check match, got %v/%s", matched, id)
	}
	// Regex fail
	e3_fail := logengine.LogEvent{Line: "User login"} // Missing name
	_, _, _, matched = re.Evaluate(ip, e3_fail)
	if matched {
		t.Errorf("Should not match invalid regex")
	}

	// Test 4: Combined (Keyword + Regex + Threshold)
	e4 := logengine.LogEvent{Line: "Error 500"}
	// 1st hit (Threshold=1, so >1 means 2 hits needed)
	c.Inc(ip)
	re.Evaluate(ip, e4)
	// 2nd hit
	c.Inc(ip)
	_, _, id, matched = re.Evaluate(ip, e4)
	if !matched || id != "combined" {
		t.Errorf("Expected combined match on 2nd attempt, got %v/%s", matched, id)
	}
}
