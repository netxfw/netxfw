// SPDX-License-Identifier: MIT
#ifndef __NETXFW_FILTER_BPF_C
#define __NETXFW_FILTER_BPF_C

#include "../include/protocol.h"
#include "../include/helpers.bpf.h"

/**
 * Check if an IPv4 address is a Bogon (reserved/private)
 * 检查 IPv4 地址是否为 Bogon（保留/私有）地址
 */
static __always_inline int is_bogon_ipv4(__u32 ip) {
    __u32 host_ip = bpf_ntohl(ip);
    
    // 0.0.0.0/8
    if ((host_ip & 0xFF000000) == 0x00000000) return 1;
    // 127.0.0.0/8 (Loopback)
    // 127.0.0.0/8 (环回)
    if ((host_ip & 0xFF000000) == 0x7F000000) return 1;
    // 169.254.0.0/16 (Link Local)
    // 169.254.0.0/16 (链路本地)
    if ((host_ip & 0xFFFF0000) == 0xA9FE0000) return 1;
    // 224.0.0.0/4 (Multicast/Reserved)
    // 224.0.0.0/4 (组播/保留)
    if ((host_ip & 0xF0000000) == 0xE0000000) return 1;
    // 240.0.0.0/4 (Reserved)
    // 240.0.0.0/4 (保留)
    if ((host_ip & 0xF0000000) == 0xF0000000) return 1;
    
    return 0;
}

/**
 * Check if an IPv6 address is a Bogon (reserved/private)
 * 检查 IPv6 地址是否为 Bogon（保留/私有）地址
 */
static __always_inline int is_bogon_ipv6(struct in6_addr *ip) {
    // ::/128 (Unspecified)
    // ::/128 (未指定)
    if (ip->s6_addr32[0] == 0 && ip->s6_addr32[1] == 0 &&
        ip->s6_addr32[2] == 0 && ip->s6_addr32[3] == 0) return 1;
    
    // ::1/128 (Loopback)
    // ::1/128 (环回)
    if (ip->s6_addr32[0] == 0 && ip->s6_addr32[1] == 0 &&
        ip->s6_addr32[2] == 0 && ip->s6_addr32[3] == bpf_htonl(1)) return 1;

    // ff00::/8 (Multicast)
    // ff00::/8 (组播)
    if (ip->s6_addr[0] == 0xff) return 1;

    // fe80::/10 (Link-Local)
    // fe80::/10 (链路本地)
    if (ip->s6_addr[0] == 0xfe && (ip->s6_addr[1] & 0xc0) == 0x80) return 1;

    return 0;
}

/**
 * Validate TCP Flags (detect Null, Xmas, etc.)
 * 验证 TCP 标志位（检测 Null, Xmas 等攻击）
 */
static __always_inline int is_invalid_tcp_flags(__u8 flags) {
    // 1. Null scan (no flags set)
    // 1. Null 扫描（无标志位）
    if (flags == 0) return 1;
    // 2. Xmas scan (FIN, PSH, URG set)
    // 2. Xmas 扫描（设置了 FIN, PSH, URG）
    if ((flags & 0x29) == 0x29) return 1;
    // 3. SYN and FIN set
    // 3. 同时设置 SYN 和 FIN
    if ((flags & 0x03) == 0x03) return 1;
    // 4. SYN and RST set
    // 4. 同时设置 SYN 和 RST
    if ((flags & 0x06) == 0x06) return 1;
    // 5. FIN without ACK (rare but usually malicious, except first packet?)
    // Note: Some stacks might send FIN without ACK? RFC 793 says ACK is almost always set.
    // However, purely FIN scan is a thing.
    // 5. FIN 但没有 ACK（罕见但通常是恶意的，除了第一个包？）
    // 注意：某些协议栈可能会发送不带 ACK 的 FIN？RFC 793 说 ACK 几乎总是被设置的。
    // 但是，纯 FIN 扫描是存在的。
    if ((flags & 0x01) && !(flags & 0x10)) return 1;
    // 6. URG without ACK
    // 6. URG 但没有 ACK
    if ((flags & 0x20) && !(flags & 0x10)) return 1;
    // 7. PSH without ACK
    // 7. PSH 但没有 ACK
    if ((flags & 0x08) && !(flags & 0x10)) return 1;
    
    return 0;
}

/**
 * Check for Land Attack (Source IP == Dest IP)
 * 检查 Land 攻击（源 IP == 目的 IP）
 */
static __always_inline int is_land_attack_ipv4(__u32 saddr, __u32 daddr) {
    return saddr == daddr;
}

/**
 * Check for Land Attack IPv6
 * 检查 IPv6 Land 攻击
 */
static __always_inline int is_land_attack_ipv6(struct in6_addr *saddr, struct in6_addr *daddr) {
    return (saddr->s6_addr32[0] == daddr->s6_addr32[0] &&
            saddr->s6_addr32[1] == daddr->s6_addr32[1] &&
            saddr->s6_addr32[2] == daddr->s6_addr32[2] &&
            saddr->s6_addr32[3] == daddr->s6_addr32[3]);
}


#endif // __NETXFW_FILTER_BPF_C
