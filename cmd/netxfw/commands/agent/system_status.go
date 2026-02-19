package agent

import (
	"fmt"
)

// Drop reason codes / 丢弃原因码
const (
	DROP_REASON_UNKNOWN     = 0
	DROP_REASON_INVALID     = 1
	DROP_REASON_PROTOCOL    = 2
	DROP_REASON_BLACKLIST   = 3
	DROP_REASON_RATELIMIT   = 4
	DROP_REASON_STRICT_TCP  = 5
	DROP_REASON_DEFAULT     = 6
	DROP_REASON_LAND_ATTACK = 7
	DROP_REASON_BOGON       = 8
	DROP_REASON_FRAGMENT    = 9
	DROP_REASON_BAD_HEADER  = 10
	DROP_REASON_TCP_FLAGS   = 11
	DROP_REASON_SPOOF       = 12
)

// Pass reason codes / 通过原因码
const (
	PASS_REASON_UNKNOWN   = 100
	PASS_REASON_WHITELIST = 101
	PASS_REASON_RETURN    = 102
	PASS_REASON_CONNTRACK = 103
	PASS_REASON_DEFAULT   = 104
)

// dropReasonToString maps drop reason codes to human-readable strings
// dropReasonToString 将丢弃原因码映射为可读字符串
func dropReasonToString(reason uint32) string {
	switch reason {
	case DROP_REASON_BLACKLIST:
		return "BLACKLIST"
	case DROP_REASON_RATELIMIT:
		return "RATELIMIT"
	case DROP_REASON_DEFAULT:
		return "DEFAULT_DENY"
	case DROP_REASON_INVALID:
		return "INVALID"
	case DROP_REASON_PROTOCOL:
		return "PROTOCOL"
	case DROP_REASON_STRICT_TCP:
		return "STRICT_TCP"
	case DROP_REASON_LAND_ATTACK:
		return "LAND_ATTACK"
	case DROP_REASON_BOGON:
		return "BOGON"
	case DROP_REASON_FRAGMENT:
		return "FRAGMENT"
	case DROP_REASON_BAD_HEADER:
		return "BAD_HEADER"
	case DROP_REASON_TCP_FLAGS:
		return "TCP_FLAGS"
	case DROP_REASON_SPOOF:
		return "SPOOF"
	default:
		return "UNKNOWN"
	}
}

// passReasonToString maps pass reason codes to human-readable strings
// passReasonToString 将通过原因码映射为可读字符串
func passReasonToString(reason uint32) string {
	switch reason {
	case PASS_REASON_WHITELIST:
		return "WHITELIST"
	case PASS_REASON_RETURN:
		return "RETURN"
	case PASS_REASON_CONNTRACK:
		return "CONNTRACK"
	case PASS_REASON_DEFAULT:
		return "DEFAULT"
	default:
		return "UNKNOWN"
	}
}

// protocolToString maps protocol numbers to human-readable strings
// protocolToString 将协议号映射为可读字符串
func protocolToString(proto uint8) string {
	switch proto {
	case 0:
		return "OTHER"
	case 1:
		return "ICMP"
	case 2:
		return "IGMP"
	case 4:
		return "IP-in-IP"
	case 6:
		return "TCP"
	case 8:
		return "EGP"
	case 17:
		return "UDP"
	case 41:
		return "IPv6"
	case 43:
		return "IPv6-Route"
	case 44:
		return "IPv6-Frag"
	case 47:
		return "GRE"
	case 50:
		return "ESP"
	case 51:
		return "AH"
	case 58:
		return "ICMPv6"
	case 59:
		return "IPv6-NoNxt"
	case 60:
		return "IPv6-Opts"
	case 89:
		return "OSPF"
	case 132:
		return "SCTP"
	case 135:
		return "UDPLite"
	default:
		return fmt.Sprintf("%d", proto)
	}
}
