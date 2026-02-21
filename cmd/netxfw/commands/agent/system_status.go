package agent

import (
	"fmt"
)

// Drop reason codes / 丢弃原因码
const (
	DropReasonUnknown    = 0
	DropReasonInvalid    = 1
	DropReasonProtocol   = 2
	DropReasonBlacklist  = 3
	DropReasonRatelimit  = 4
	DropReasonStrictTCP  = 5
	DropReasonDefault    = 6
	DropReasonLandAttack = 7
	DropReasonBogon      = 8
	DropReasonFragment   = 9
	DropReasonBadHeader  = 10
	DropReasonTCPFlags   = 11
	DropReasonSpoof      = 12
)

// Pass reason codes / 通过原因码
const (
	PassReasonUnknown   = 100
	PassReasonWhitelist = 101
	PassReasonReturn    = 102
	PassReasonConntrack = 103
	PassReasonDefault   = 104
)

// dropReasonToString maps drop reason codes to human-readable strings
// dropReasonToString 将丢弃原因码映射为可读字符串
func dropReasonToString(reason uint32) string {
	switch reason {
	case DropReasonBlacklist:
		return "BLACKLIST"
	case DropReasonRatelimit:
		return "RATELIMIT"
	case DropReasonDefault:
		return "DEFAULT_DENY"
	case DropReasonInvalid:
		return "INVALID"
	case DropReasonProtocol:
		return "PROTOCOL"
	case DropReasonStrictTCP:
		return "STRICT_TCP"
	case DropReasonLandAttack:
		return "LAND_ATTACK"
	case DropReasonBogon:
		return "BOGON"
	case DropReasonFragment:
		return "FRAGMENT"
	case DropReasonBadHeader:
		return "BAD_HEADER"
	case DropReasonTCPFlags:
		return "TCP_FLAGS"
	case DropReasonSpoof:
		return "SPOOF"
	default:
		return "UNKNOWN"
	}
}

// passReasonToString maps pass reason codes to human-readable strings
// passReasonToString 将通过原因码映射为可读字符串
func passReasonToString(reason uint32) string {
	switch reason {
	case PassReasonWhitelist:
		return "WHITELIST"
	case PassReasonReturn:
		return "RETURN"
	case PassReasonConntrack:
		return "CONNTRACK"
	case PassReasonDefault:
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
