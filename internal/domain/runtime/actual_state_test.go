package runtime

import (
	"testing"

	"github.com/cilium/ebpf"
	systemstate "github.com/netxfw/netxfw/internal/domain/system"
)

type fakeGlobalConfig struct {
	values map[uint32]uint64
}

func (f fakeGlobalConfig) Lookup(key, value interface{}) error {
	kptr, ok := key.(*uint32)
	if !ok || kptr == nil {
		return ebpf.ErrKeyNotExist
	}
	vptr, ok := value.(*uint64)
	if !ok || vptr == nil {
		return ebpf.ErrKeyNotExist
	}
	v, ok := f.values[*kptr]
	if !ok {
		return ebpf.ErrKeyNotExist
	}
	*vptr = v
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
