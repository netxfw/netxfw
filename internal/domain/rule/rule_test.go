package rule

import (
	"errors"
	"testing"
	"time"
)

func TestParseSelector(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantCIDR string
		wantPort uint16
		wantErr  bool
	}{
		{name: "ipv4 with port", input: "1.2.3.4:80", wantCIDR: "1.2.3.4/32", wantPort: 80},
		{name: "ipv6 with port", input: "[2001:db8::1]:443", wantCIDR: "2001:db8::1/128", wantPort: 443},
		{name: "cidr only", input: "10.0.0.0/24", wantCIDR: "10.0.0.0/24", wantPort: 0},
		{name: "invalid", input: "bad-input", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSelector(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.CIDR != tt.wantCIDR || got.Port != tt.wantPort {
				t.Fatalf("got %+v, want cidr=%s port=%d", got, tt.wantCIDR, tt.wantPort)
			}
		})
	}
}

func TestParseAction(t *testing.T) {
	action, err := ParseAction("allow")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if action != ActionAllow {
		t.Fatalf("got %d", action)
	}

	if _, err := ParseAction("drop"); !errors.Is(err, ErrInvalidAction) {
		t.Fatalf("expected invalid action error, got %v", err)
	}
}

func TestRuleSetRejectsDuplicates(t *testing.T) {
	selector, err := NewSelector("1.2.3.4", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	rule, err := NewRule(selector, ActionDeny)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	set, err := NewRuleSet(rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := set.Add(rule); !errors.Is(err, ErrDuplicateRule) {
		t.Fatalf("expected duplicate error, got %v", err)
	}
}

func TestParseTTL(t *testing.T) {
	got, err := ParseTTL("1h")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != time.Hour {
		t.Fatalf("got %v", got)
	}

	if _, err := ParseTTL(""); !errors.Is(err, ErrEmptyTTL) {
		t.Fatalf("expected empty ttl error, got %v", err)
	}
}
