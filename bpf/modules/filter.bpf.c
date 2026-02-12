// SPDX-License-Identifier: MIT
#ifndef __NETXFW_FILTER_BPF_C
#define __NETXFW_FILTER_BPF_C

#include "../include/protocol.h"
#include "../include/helpers.bpf.h"

/**
 * Check if an IPv4 address is a Bogon (reserved/private)
 */
static __always_inline int is_bogon_ipv4(__u32 ip) {
    __u32 host_ip = bpf_ntohl(ip);
    
    // 0.0.0.0/8
    if ((host_ip & 0xFF000000) == 0x00000000) return 1;
    // 127.0.0.0/8 (Loopback)
    if ((host_ip & 0xFF000000) == 0x7F000000) return 1;
    // 169.254.0.0/16 (Link Local)
    if ((host_ip & 0xFFFF0000) == 0xA9FE0000) return 1;
    // 224.0.0.0/4 (Multicast/Reserved)
    if ((host_ip & 0xF0000000) == 0xE0000000) return 1;
    // 240.0.0.0/4 (Reserved)
    if ((host_ip & 0xF0000000) == 0xF0000000) return 1;
    
    return 0;
}

/**
 * Check if an IPv6 address is a Bogon (reserved/private)
 */
static __always_inline int is_bogon_ipv6(struct in6_addr *ip) {
    // ::/128 (Unspecified)
    if (ip->s6_addr32[0] == 0 && ip->s6_addr32[1] == 0 &&
        ip->s6_addr32[2] == 0 && ip->s6_addr32[3] == 0) return 1;
    
    // ::1/128 (Loopback)
    if (ip->s6_addr32[0] == 0 && ip->s6_addr32[1] == 0 &&
        ip->s6_addr32[2] == 0 && ip->s6_addr32[3] == bpf_htonl(1)) return 1;

    // ff00::/8 (Multicast)
    if (ip->s6_addr[0] == 0xff) return 1;

    // fe80::/10 (Link-Local)
    if (ip->s6_addr[0] == 0xfe && (ip->s6_addr[1] & 0xc0) == 0x80) return 1;

    return 0;
}

/**
 * Validate TCP Flags (detect Null, Xmas, etc.)
 */
static __always_inline int is_invalid_tcp_flags(__u8 flags) {
    // 1. Null scan (no flags set)
    if (flags == 0) return 1;
    // 2. Xmas scan (FIN, PSH, URG set)
    if ((flags & 0x29) == 0x29) return 1;
    // 3. SYN and FIN set
    if ((flags & 0x03) == 0x03) return 1;
    // 4. SYN and RST set
    if ((flags & 0x06) == 0x06) return 1;
    // 5. FIN without ACK (rare but usually malicious, except first packet?)
    // Note: Some stacks might send FIN without ACK? RFC 793 says ACK is almost always set.
    // However, purely FIN scan is a thing.
    if ((flags & 0x01) && !(flags & 0x10)) return 1;
    // 6. URG without ACK
    if ((flags & 0x20) && !(flags & 0x10)) return 1;
    // 7. PSH without ACK
    if ((flags & 0x08) && !(flags & 0x10)) return 1;
    
    return 0;
}

/**
 * Check for Land Attack (Source IP == Dest IP)
 */
static __always_inline int is_land_attack_ipv4(__u32 saddr, __u32 daddr) {
    return saddr == daddr;
}

/**
 * Check for Land Attack IPv6
 */
static __always_inline int is_land_attack_ipv6(struct in6_addr *saddr, struct in6_addr *daddr) {
    return (saddr->s6_addr32[0] == daddr->s6_addr32[0] &&
            saddr->s6_addr32[1] == daddr->s6_addr32[1] &&
            saddr->s6_addr32[2] == daddr->s6_addr32[2] &&
            saddr->s6_addr32[3] == daddr->s6_addr32[3]);
}


#endif // __NETXFW_FILTER_BPF_C
