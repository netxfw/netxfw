package runtime

import (
	"fmt"
	"time"

	systemstate "github.com/netxfw/netxfw/internal/domain/system"
)

type Mismatch struct {
	Field   string
	Desired string
	Actual  string
}

type StateDiff struct {
	Mismatches []Mismatch
}

func (d StateDiff) HasMismatch() bool {
	return len(d.Mismatches) > 0
}

// CompareDesired reports the fields where runtime diverges from the config-derived desired state.
func CompareDesired(desired systemstate.DesiredState, actual ActualState) StateDiff {
	var diff StateDiff

	compareBool(&diff, "default_deny", desired.DefaultDeny, actual.DefaultDeny)
	compareBool(&diff, "allow_return_traffic", desired.AllowReturnTraffic, actual.AllowReturnTraffic)
	compareBool(&diff, "allow_icmp", desired.AllowICMP, actual.AllowICMP)
	compareBool(&diff, "enable_af_xdp", desired.EnableAFXDP, actual.EnableAFXDP)
	compareBool(&diff, "enable_conntrack", desired.EnableConntrack, actual.EnableConntrack)
	compareBool(&diff, "enable_rate_limit", desired.EnableRateLimit, actual.EnableRateLimit)
	compareBool(&diff, "strict_protocol", desired.StrictProtocol, actual.StrictProtocol)
	compareBool(&diff, "strict_tcp", desired.StrictTCP, actual.StrictTCP)
	compareBool(&diff, "syn_limit", desired.SYNLimit, actual.SYNLimit)
	compareBool(&diff, "bogon_filter", desired.BogonFilter, actual.BogonFilter)
	compareBool(&diff, "drop_fragments", desired.DropFragments, actual.DropFragments)
	compareBool(&diff, "auto_block", desired.AutoBlock, actual.AutoBlock)

	compareUint64(&diff, "icmp_rate", desired.ICMPRate, actual.ICMPRate)
	compareUint64(&diff, "icmp_burst", desired.ICMPBurst, actual.ICMPBurst)
	compareDuration(&diff, "auto_block_expiry", desired.AutoBlockExpiry, actual.AutoBlockExpiry)
	compareInt(&diff, "whitelist_count", desired.WhitelistCount, actual.WhitelistCount)
	compareInt(&diff, "allowed_port_count", desired.AllowedPortCount, actual.AllowedPortCount)
	compareInt(&diff, "ip_port_rule_count", desired.IPPortRuleCount, actual.IPPortRuleCount)
	compareInt(&diff, "rate_limit_rule_count", desired.RateLimitRuleCount, actual.RateLimitRuleCount)
	compareInt(&diff, "capacity.conntrack", desired.ConntrackCapacity, actual.ConntrackCapacity)
	compareInt(&diff, "capacity.lock_list", desired.LockListCapacity, actual.LockListCapacity)
	compareInt(&diff, "capacity.dyn_lock_list", desired.DynLockListCapacity, actual.DynLockListCapacity)
	compareInt(&diff, "capacity.whitelist", desired.WhitelistCapacity, actual.WhitelistCapacity)
	compareInt(&diff, "capacity.rule_map", desired.RuleMapCapacity, actual.RuleMapCapacity)
	compareInt(&diff, "capacity.rate_limits", desired.RateLimitsCapacity, actual.RateLimitsCapacity)
	compareInt(&diff, "capacity.drop_reason_stats", desired.DropReasonStatsCapacity, actual.DropReasonStatsCapacity)
	compareInt(&diff, "capacity.pass_reason_stats", desired.PassReasonStatsCapacity, actual.PassReasonStatsCapacity)

	return diff
}

func compareBool(diff *StateDiff, field string, desired bool, actual BoolField) {
	if !actual.Known || desired == actual.Value {
		return
	}
	diff.Mismatches = append(diff.Mismatches, Mismatch{
		Field:   field,
		Desired: fmt.Sprintf("%t", desired),
		Actual:  fmt.Sprintf("%t", actual.Value),
	})
}

func compareUint64(diff *StateDiff, field string, desired uint64, actual Uint64Field) {
	if !actual.Known || desired == actual.Value {
		return
	}
	diff.Mismatches = append(diff.Mismatches, Mismatch{
		Field:   field,
		Desired: fmt.Sprintf("%d", desired),
		Actual:  fmt.Sprintf("%d", actual.Value),
	})
}

func compareInt(diff *StateDiff, field string, desired int, actual IntField) {
	if !actual.Known || desired == actual.Value {
		return
	}
	diff.Mismatches = append(diff.Mismatches, Mismatch{
		Field:   field,
		Desired: fmt.Sprintf("%d", desired),
		Actual:  fmt.Sprintf("%d", actual.Value),
	})
}

func compareDuration(diff *StateDiff, field string, desired time.Duration, actual Uint64Field) {
	if !actual.Known || uint64(desired) == actual.Value {
		return
	}
	diff.Mismatches = append(diff.Mismatches, Mismatch{
		Field:   field,
		Desired: desired.String(),
		Actual:  time.Duration(actual.Value).String(),
	})
}
