// SPDX-License-Identifier: (BSD-2-Clause OR GPL-2.0-only)
#ifndef __NETXFW_HELPERS_H
#define __NETXFW_HELPERS_H

#include "maps.bpf.h"

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#define CONFIG_DEFAULT_DENY 0
#define CONFIG_ALLOW_RETURN_TRAFFIC 1
#define CONFIG_ALLOW_ICMP 2
#define CONFIG_ENABLE_CONNTRACK 3
#define CONFIG_CONNTRACK_TIMEOUT 4
#define CONFIG_ICMP_RATE 5
#define CONFIG_ICMP_BURST 6
#define CONFIG_ENABLE_AF_XDP 7
#define CONFIG_CONFIG_VERSION 8
#define CONFIG_STRICT_PROTO 9
#define CONFIG_ENABLE_RATELIMIT 10
#define CONFIG_DROP_FRAGMENTS 11
#define CONFIG_STRICT_TCP 12
#define CONFIG_SYN_LIMIT 13
#define CONFIG_BOGON_FILTER 14
#define CONFIG_AUTO_BLOCK 15
#define CONFIG_AUTO_BLOCK_EXPIRY 16

// Configuration refresh optimization constants
#define CONFIG_REFRESH_INTERVAL 1024  // Refresh every 1024 packets (Power of 2 for optimization)

// Global cached config version (defined in config.bpf.h)
extern __u64 cached_version;

// Global cached config variables (defined in main netxfw.bpf.c)
extern __u32 cached_default_deny;
extern __u32 cached_allow_return;
extern __u32 cached_allow_icmp;
extern __u32 cached_ct_enabled;
extern __u64 cached_ct_timeout;
extern __u32 cached_icmp_rate;
extern __u32 cached_icmp_burst;
extern __u32 cached_af_xdp_enabled;
extern __u32 cached_strict_proto;
extern __u32 cached_ratelimit_enabled;
extern __u32 cached_drop_frags;
extern __u32 cached_strict_tcp;
extern __u32 cached_syn_limit;
extern __u32 cached_bogon_filter;
extern __u32 cached_auto_block;
extern __u64 cached_auto_block_expiry;

// Helper functions for common operations
// 通用操作的辅助函数
static __always_inline int is_valid_eth_frame(void *data, void *data_end, struct ethhdr *eth) {
    return (data + sizeof(*eth) <= data_end);
}

static __always_inline int is_ipv4_packet(struct ethhdr *eth) {
    return (eth->h_proto == bpf_htons(ETH_P_IP));
}

static __always_inline int is_ipv6_packet(struct ethhdr *eth) {
    return (eth->h_proto == bpf_htons(ETH_P_IPV6));
}

static __always_inline int is_arp_packet(struct ethhdr *eth) {
    return (eth->h_proto == bpf_htons(ETH_P_ARP));
}

/**
 * Convert IPv4 address to IPv4-mapped IPv6 address (::ffff:a.b.c.d)
 * ip4: IPv4 address in network byte order
 * ip6: Pointer to struct in6_addr to store the result
 * 将 IPv4 地址转换为 IPv4 映射的 IPv6 地址 (::ffff:a.b.c.d)
 * ip4: 网络字节序的 IPv4 地址
 * ip6: 存储结果的 struct in6_addr 指针
 */
static __always_inline void ipv4_to_ipv6_mapped(__u32 ip4, struct in6_addr *ip6) {
    ip6->in6_u.u6_addr32[0] = 0;
    ip6->in6_u.u6_addr32[1] = 0;
    ip6->in6_u.u6_addr32[2] = bpf_htonl(0x0000ffff);
    ip6->in6_u.u6_addr32[3] = ip4;
}

#endif // __NETXFW_HELPERS_H
