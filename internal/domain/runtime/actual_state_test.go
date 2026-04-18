package runtime

import (
	"fmt"
	"testing"

	systemstate "github.com/netxfw/netxfw/internal/domain/system"
	"github.com/netxfw/netxfw/pkg/sdk"
)

type fakeGlobalConfig struct {
	values map[uint32]uint64
}

func (f fakeGlobalConfig) Lookup(key, value interface{}) error {
	k, ok := key.(*uint32)
	if !ok {
		return fmt.Errorf("unexpected key type %T", key)
	}
	out, ok := value.(*uint64)
	if !ok {
		return fmt.Errorf("unexpected value type %T", value)
	}
	v, found := f.values[*k]
	if !found {
		return fmt.Errorf("missing key")
	}
	*out = v
	return nil
}

func TestFromGlobalConfigMap(t *testing.T) {
	state := FromGlobalConfigMap(fakeGlobalConfig{
		values: map[uint32]uint64{
			0:  1,
			1:  1,
			2:  0,
			3:  1,
			4:  42,
			5:  100,
			6:  200,
			7:  1,
			9:  1,
			10: 1,
			11: 1,
			12: 1,
			13: 0,
			14: 1,
			15: 1,
			16: 99,
		},
	})

	if !state.DefaultDeny.Known || !state.DefaultDeny.Value || !state.EnableAFXDP.Value {
		t.Fatalf("expected map fields to be projected: %+v", state)
	}
	if !state.ConntrackTimeout.Known || state.ConntrackTimeout.Value != 42 {
		t.Fatalf("expected conntrack timeout to be projected: %+v", state)
	}
}

func TestFromManager(t *testing.T) {
	mgr := sdk.NewMockManager()
	if err := mgr.AddBlacklistIP("192.168.1.1/32"); err != nil {
		t.Fatalf("AddBlacklistIP failed: %v", err)
	}
	if err := mgr.AddWhitelistIP("10.0.0.1/32", 0); err != nil {
		t.Fatalf("AddWhitelistIP failed: %v", err)
	}
	if err := mgr.AllowPort(443); err != nil {
		t.Fatalf("AllowPort failed: %v", err)
	}
	if err := mgr.AddIPPortRule("10.0.0.2/32", 80, 1); err != nil {
		t.Fatalf("AddIPPortRule failed: %v", err)
	}
	if err := mgr.AddRateLimitRule("10.0.0.0/24", 1000, 100); err != nil {
		t.Fatalf("AddRateLimitRule failed: %v", err)
	}

	state := FromManager(mgr)

	if !state.LockedCount.Known || state.LockedCount.Value != 1 {
		t.Fatalf("expected blacklist count to be projected: %+v", state)
	}
	if !state.WhitelistCount.Known || state.WhitelistCount.Value != 1 {
		t.Fatalf("expected whitelist count to be projected: %+v", state)
	}
	if !state.AllowedPortCount.Known || state.AllowedPortCount.Value != 1 {
		t.Fatalf("expected allowed port count to be projected: %+v", state)
	}
	if !state.IPPortRuleCount.Known || state.IPPortRuleCount.Value != 1 || !state.RateLimitRuleCount.Known || state.RateLimitRuleCount.Value != 1 {
		t.Fatalf("expected rule counts to be projected: %+v", state)
	}
}

func TestCompareDesired(t *testing.T) {
	desired := systemstate.DesiredState{
		DefaultDeny:        true,
		EnableRateLimit:    true,
		WhitelistCount:     2,
		AllowedPortCount:   1,
		IPPortRuleCount:    1,
		RateLimitRuleCount: 1,
	}
	actual := ActualState{
		DefaultDeny:        BoolField{Known: true, Value: false},
		EnableRateLimit:    BoolField{Known: true, Value: true},
		WhitelistCount:     IntField{Known: true, Value: 1},
		AllowedPortCount:   IntField{Known: true, Value: 1},
		IPPortRuleCount:    IntField{Known: true, Value: 0},
		RateLimitRuleCount: IntField{Known: true, Value: 1},
	}

	diff := CompareDesired(desired, actual)
	if !diff.HasMismatch() || len(diff.Mismatches) != 3 {
		t.Fatalf("expected 3 mismatches, got %+v", diff)
	}
}
