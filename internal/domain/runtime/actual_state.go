// Package runtime provides runtime functionality.
package runtime

import (
	"reflect"
	"time"

	"github.com/cilium/ebpf"
	datapathmaps "github.com/netxfw/netxfw/internal/datapath/xdp/maps"
	"github.com/netxfw/netxfw/internal/ports"
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

type topStatsMapProvider interface {
	TopDropMap() *ebpf.Map
	TopPassMap() *ebpf.Map
}

type legacyStatsMapProvider interface {
	DropReasonStats() *ebpf.Map
	PassReasonStats() *ebpf.Map
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

	ConntrackCapacity       IntField
	LockListCapacity        IntField
	DynLockListCapacity     IntField
	WhitelistCapacity       IntField
	RuleMapCapacity         IntField
	RateLimitsCapacity      IntField
	DropReasonStatsCapacity IntField
	PassReasonStatsCapacity IntField
}

// FromManager reads runtime state from the manager without failing the whole projection on partial errors.
func FromManager(mgr ports.RuntimeStateReader) ActualState {
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

	state.ConntrackCapacity = mapCapacity(mgr.ConntrackMap())
	state.LockListCapacity = mapCapacity(mgr.LockList())
	state.DynLockListCapacity = mapCapacity(mgr.DynLockList())
	state.WhitelistCapacity = mapCapacity(mgr.Whitelist())
	state.RuleMapCapacity = mapCapacity(mgr.IPPortRules())
	state.RateLimitsCapacity = mapCapacity(mgr.RateLimitConfig())
	if provider, ok := any(mgr).(topStatsMapProvider); ok {
		state.DropReasonStatsCapacity = mapCapacity(provider.TopDropMap())
		state.PassReasonStatsCapacity = mapCapacity(provider.TopPassMap())
	} else if provider, ok := any(mgr).(legacyStatsMapProvider); ok {
		state.DropReasonStatsCapacity = mapCapacity(provider.DropReasonStats())
		state.PassReasonStatsCapacity = mapCapacity(provider.PassReasonStats())
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
		DefaultDeny:        readBool(globalConfig, datapathmaps.ConfigIndexDefaultDeny),
		AllowReturnTraffic: readBool(globalConfig, datapathmaps.ConfigIndexAllowReturnTraffic),
		AllowICMP:          readBool(globalConfig, datapathmaps.ConfigIndexAllowICMP),
		EnableConntrack:    readBool(globalConfig, datapathmaps.ConfigIndexEnableConntrack),
		ConntrackTimeout:   readUint64(globalConfig, datapathmaps.ConfigIndexConntrackTimeout),
		ICMPRate:           readUint64(globalConfig, datapathmaps.ConfigIndexICMPRate),
		ICMPBurst:          readUint64(globalConfig, datapathmaps.ConfigIndexICMPBurst),
		EnableAFXDP:        readBool(globalConfig, datapathmaps.ConfigIndexEnableAFXDP),
		StrictProtocol:     readBool(globalConfig, datapathmaps.ConfigIndexStrictProto),
		EnableRateLimit:    readBool(globalConfig, datapathmaps.ConfigIndexEnableRateLimit),
		DropFragments:      readBool(globalConfig, datapathmaps.ConfigIndexDropFragments),
		StrictTCP:          readBool(globalConfig, datapathmaps.ConfigIndexStrictTCP),
		SYNLimit:           readBool(globalConfig, datapathmaps.ConfigIndexSYNLimit),
		BogonFilter:        readBool(globalConfig, datapathmaps.ConfigIndexBogonFilter),
		AutoBlock:          readBool(globalConfig, datapathmaps.ConfigIndexAutoBlock),
		AutoBlockExpiry:    readUint64(globalConfig, datapathmaps.ConfigIndexAutoBlockExpiry),
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

func mapCapacity(m *ebpf.Map) IntField {
	if m == nil {
		return IntField{}
	}
	return knownInt(int(m.MaxEntries()))
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
