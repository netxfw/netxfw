package sdk

import (
	"time"
)

// =============================================================================
// Data Types - 数据类型
// =============================================================================

// BlockedIP represents an IP address in the blacklist.
// BlockedIP 表示黑名单中的 IP 地址。
type BlockedIP struct {
	// IP is the IP address or CIDR.
	// IP 是 IP 地址或 CIDR。
	IP string

	// ExpiresAt is the Unix timestamp when the entry expires (0 = never).
	// ExpiresAt 是条目过期的 Unix 时间戳（0 = 永不过期）。
	ExpiresAt uint64

	// Counter is the number of times this IP has been blocked.
	// Counter 是此 IP 被拦截的次数。
	Counter uint64
}

// IPPortRule represents an IP+Port rule.
// IPPortRule 表示 IP+端口规则。
type IPPortRule struct {
	// IP is the IP address or CIDR.
	// IP 是 IP 地址或 CIDR。
	IP string

	// Port is the port number.
	// Port 是端口号。
	Port uint16

	// Action is the action to take: 1=Allow, 2=Deny.
	// Action 是要执行的操作：1=允许，2=拒绝。
	Action uint8
}

// RateLimitConf represents rate limiting configuration for a CIDR.
// RateLimitConf 表示 CIDR 的限速配置。
type RateLimitConf struct {
	// Rate is the rate limit in packets per second.
	// Rate 是每秒数据包的速率限制。
	Rate uint64

	// Burst is the burst size in packets.
	// Burst 是数据包的突发大小。
	Burst uint64
}

// ConntrackEntry represents a single connection tracking entry.
// ConntrackEntry 表示单个连接跟踪条目。
type ConntrackEntry struct {
	// SrcIP is the source IP address.
	// SrcIP 是源 IP 地址。
	SrcIP string

	// DstIP is the destination IP address.
	// DstIP 是目标 IP 地址。
	DstIP string

	// SrcPort is the source port.
	// SrcPort 是源端口。
	SrcPort uint16

	// DstPort is the destination port.
	// DstPort 是目标端口。
	DstPort uint16

	// Protocol is the protocol number (TCP=6, UDP=17, etc.).
	// Protocol 是协议号（TCP=6, UDP=17 等）。
	Protocol uint8

	// LastSeen is the last time this connection was seen.
	// LastSeen 是最后一次看到此连接的时间。
	LastSeen time.Time
}

// DropDetailEntry represents detailed statistics for dropped/passed packets.
// DropDetailEntry 表示拦截/放行数据包的详细统计信息。
type DropDetailEntry struct {
	// Timestamp is when the event occurred.
	// Timestamp 是事件发生的时间。
	Timestamp time.Time

	// SrcIP is the source IP address.
	// SrcIP 是源 IP 地址。
	SrcIP string

	// DstIP is the destination IP address.
	// DstIP 是目标 IP 地址。
	DstIP string

	// SrcPort is the source port.
	// SrcPort 是源端口。
	SrcPort uint16

	// DstPort is the destination port.
	// DstPort 是目标端口。
	DstPort uint16

	// Protocol is the protocol number.
	// Protocol 是协议号。
	Protocol uint8

	// Reason is the drop reason code.
	// Reason 是拦截原因代码。
	Reason uint32

	// Count is the number of packets.
	// Count 是数据包数量。
	Count uint64

	// Payload is the packet payload (if captured).
	// Payload 是数据包负载（如果已捕获）。
	Payload []byte
}

// DropLogEntry matches DropDetailEntry but specifically for high-level logs.
// DropLogEntry 与 DropDetailEntry 匹配，但专门用于高级日志。
type DropLogEntry struct {
	// Timestamp is when the event occurred.
	// Timestamp 是事件发生的时间。
	Timestamp time.Time

	// SrcIP is the source IP address.
	// SrcIP 是源 IP 地址。
	SrcIP string

	// DstIP is the destination IP address.
	// DstIP 是目标 IP 地址。
	DstIP string

	// SrcPort is the source port.
	// SrcPort 是源端口。
	SrcPort uint16

	// DstPort is the destination port.
	// DstPort 是目标端口。
	DstPort uint16

	// Protocol is the protocol number.
	// Protocol 是协议号。
	Protocol uint8

	// Reason is the drop reason code.
	// Reason 是拦截原因代码。
	Reason uint32

	// Count is the number of packets.
	// Count 是数据包数量。
	Count uint64

	// Payload is the packet payload (if captured).
	// Payload 是数据包负载（如果已捕获）。
	Payload []byte
}
