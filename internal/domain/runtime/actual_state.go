package runtime

import (
	"reflect"
	"time"

	"github.com/netxfw/netxfw/internal/datapath/xdp/backend"
	"github.com/netxfw/netxfw/pkg/sdk"
)

type lookupReader interface {
	Lookup(key, value interface{}) error
}

type BoolField struct {
	Value bool
	Known bool
}

type Uint64Field struct {
	Value uint64
	Known bool
}

type IntField struct {
	Value int
	Known bool
}

// ActualState captures runtime-visible state from maps and manager APIs.
type ActualState struct {
	DefaultDeny        BoolField
	AllowReturnTraffic BoolField
	AllowICMP          BoolField
	EnableAFXDP        BoolField
	EnableConntrack    BoolField
	EnableRateLimit    BoolField
	StrictProtocol     BoolField
	StrictTCP          BoolField
	SYNLimit           BoolField
	BogonFilter        BoolField
	DropFragments      BoolField
	AutoBlock          BoolField

	ICMPRate         Uint64Field
	ICMPBurst        Uint64Field
	AutoBlockExpiry  Uint64Field
	ConntrackTimeout Uint64Field

	LockedCount        IntField
	DynamicLockedCount IntField
	WhitelistCount     IntField
	AllowedPortCount   IntField
	IPPortRuleCount    IntField
	RateLimitRuleCount IntField
	ConntrackCount     IntField
}

// FromManager reads runtime state from the manager without failing the whole projection on partial errors.
func FromManager(mgr sdk.ManagerInterface) ActualState {
	if mgr == nil {
		return ActualState{}
	}

	state := ActualState{}
	if globalConfig := mgr.GlobalConfig(); globalConfig != nil {
		state = FromGlobalConfigMap(globalConfig)
	}

	if count, err := mgr.GetLockedIPCount(); err == nil {
		state.LockedCount = knownInt(count)
	}
	if count, err := mgr.GetWhitelistCount(); err == nil {
		state.WhitelistCount = knownInt(count)
	}
	if count, err := mgr.GetConntrackCount(); err == nil {
		state.ConntrackCount = knownInt(count)
	}
	if count, err := mgr.GetDynLockListCount(); err == nil {
		state.DynamicLockedCount = knownInt(int(count))
	}
	if ports, err := mgr.ListAllowedPorts(); err == nil {
		state.AllowedPortCount = knownInt(len(ports))
	}
	if rules, _, err := mgr.ListIPPortRules(false, 0, ""); err == nil {
		state.IPPortRuleCount = knownInt(len(rules))
	}
	if rules, _, err := mgr.ListRateLimitRules(0, ""); err == nil {
		state.RateLimitRuleCount = knownInt(len(rules))
	}

	return state
}

// FromGlobalConfigMap reads boolean and numeric runtime flags from the global_config map.
func FromGlobalConfigMap(globalConfig lookupReader) ActualState {
	if globalConfig == nil {
		return ActualState{}
	}
	value := reflect.ValueOf(globalConfig)
	if value.Kind() == reflect.Ptr && value.IsNil() {
		return ActualState{}
	}

	return ActualState{
		DefaultDeny:        readBool(globalConfig, xdp.ConfigIndexDefaultDeny),
		AllowReturnTraffic: readBool(globalConfig, xdp.ConfigIndexAllowReturnTraffic),
		AllowICMP:          readBool(globalConfig, xdp.ConfigIndexAllowICMP),
		EnableConntrack:    readBool(globalConfig, xdp.ConfigIndexEnableConntrack),
		ConntrackTimeout:   readUint64(globalConfig, xdp.ConfigIndexConntrackTimeout),
		ICMPRate:           readUint64(globalConfig, xdp.ConfigIndexICMPRate),
		ICMPBurst:          readUint64(globalConfig, xdp.ConfigIndexICMPBurst),
		EnableAFXDP:        readBool(globalConfig, xdp.ConfigIndexEnableAFXDP),
		StrictProtocol:     readBool(globalConfig, xdp.ConfigIndexStrictProto),
		EnableRateLimit:    readBool(globalConfig, xdp.ConfigIndexEnableRateLimit),
		DropFragments:      readBool(globalConfig, xdp.ConfigIndexDropFragments),
		StrictTCP:          readBool(globalConfig, xdp.ConfigIndexStrictTCP),
		SYNLimit:           readBool(globalConfig, xdp.ConfigIndexSYNLimit),
		BogonFilter:        readBool(globalConfig, xdp.ConfigIndexBogonFilter),
		AutoBlock:          readBool(globalConfig, xdp.ConfigIndexAutoBlock),
		AutoBlockExpiry:    readUint64(globalConfig, xdp.ConfigIndexAutoBlockExpiry),
	}
}

func (f Uint64Field) Duration() time.Duration {
	if !f.Known {
		return 0
	}
	return time.Duration(f.Value)
}

func knownInt(v int) IntField {
	return IntField{Value: v, Known: true}
}

func readBool(globalConfig lookupReader, idx uint32) BoolField {
	val := readUint64(globalConfig, idx)
	if !val.Known {
		return BoolField{}
	}
	return BoolField{Value: val.Value == 1, Known: true}
}

func readUint64(globalConfig lookupReader, idx uint32) Uint64Field {
	var value uint64
	key := idx
	if err := globalConfig.Lookup(&key, &value); err != nil {
		return Uint64Field{}
	}
	return Uint64Field{Value: value, Known: true}
}
