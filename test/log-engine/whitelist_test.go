package logengine_test

import (
	"github.com/livp123/netxfw/internal/plugins/agent/logengine"
	"net/netip"
	"testing"

	"github.com/livp123/netxfw/internal/plugins/types"
)

// TestWhitelistUser verifies the "Block if NOT user X" logic.
func TestWhitelistUser(t *testing.T) {
	c := logengine.NewCounter(0)
	re := logengine.NewRuleEngine(c)

	rules := []types.LogEngineRule{
		{
			ID:   "block_non_aa",
			Path: "/var/log/auth.log",
			// Condition 1: Must be a login attempt (e.g. "Accepted password", "Failed password", "user=")
			Contains: []string{"password for"},
			// Condition 2: Must NOT contain "aa"
			// Note: We use " aa " with spaces to be precise, or just "aa" if we are sure it won't substring match incorrectly.
			// For this test, let's assume usernames are surrounded by spaces or at end of line.
			NotContains: []string{" aa "},
			Action:      "block",
			// Threshold 1 means "Block on the first occurrence" (Count > 0)
			Threshold: 0, // 0 usually means "always trigger if matched" if logic follows.
			// Wait, let's check logic: src = `(%s) && Count(%d) > %d`
			// If Threshold is 0, the code block at line 235 might be skipped?
			// Let's check line 235: if cfg.Threshold > 0.
			// So if Threshold is 0, it won't add Count() check. It will just return 'true' if string matches.
			// That is what we want for "Direct block".
		},
	}

	if err := re.UpdateRules(rules); err != nil {
		t.Fatalf("UpdateRules failed: %v", err)
	}

	ip := netip.MustParseAddr("1.2.3.4")

	// Scenario 1: User "aa" logs in -> Should NOT block
	eventAllowed := logengine.LogEvent{
		Line:   "Accepted password for aa from 1.2.3.4 port 1234 ssh2",
		Source: "/var/log/auth.log",
	}
	action, _, id, matched := re.Evaluate(ip, eventAllowed)
	if matched {
		t.Errorf("Should allow user 'aa', but matched rule %s with action %d", id, action)
	}

	// Scenario 2: User "root" logs in -> Should BLOCK
	eventBlocked1 := logengine.LogEvent{
		Line:   "Failed password for root from 1.2.3.4 port 1234 ssh2",
		Source: "/var/log/auth.log",
	}
	action, _, id, matched = re.Evaluate(ip, eventBlocked1)
	if !matched {
		t.Error("Should block user 'root', but no rule matched")
	}
	if id != "block_non_aa" || action != logengine.ActionDynamic {
		t.Errorf("Expected block_non_aa/block, got %s/%d", id, action)
	}

	// Scenario 3: User "bb" logs in -> Should BLOCK
	eventBlocked2 := logengine.LogEvent{
		Line:   "Accepted password for bb from 1.2.3.4 port 1234 ssh2",
		Source: "/var/log/auth.log",
	}
	action, _, id, matched = re.Evaluate(ip, eventBlocked2)
	if !matched {
		t.Error("Should block user 'bb', but no rule matched")
	}

	// Scenario 4: Irrelevant log (no "password for") -> Should ignore
	eventIgnore := logengine.LogEvent{
		Line:   "Disconnecting: Too many authentication failures",
		Source: "/var/log/auth.log",
	}
	_, _, _, matched = re.Evaluate(ip, eventIgnore)
	if matched {
		t.Error("Should ignore irrelevant log")
	}
}
